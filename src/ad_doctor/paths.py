"""Control paths to tier 0 from a single snapshot, without a graph database.

Nodes are principals (by SID) and objects without a SID (OUs, GPOs, PKI objects, the
domain head). An edge A -> B means "A controls B or becomes B": group membership, an ACE
that allows a takeover, ownership, DCSync, editing a GPO, enrolling in an exploitable
certificate template, reading a gMSA password. A reverse breadth-first search from every
tier-0 node finds the shortest path from any other principal.
"""

from __future__ import annotations

import re
from collections import deque
from collections.abc import Iterable
from dataclasses import dataclass

from . import sd
from .checks import (
    CREATOR_OWNER,
    EKU_ANY,
    EKU_REQUEST_AGENT,
    PRINCIPAL_SELF,
    _authenticates,
    _finding,
    _issuable,
    _risky_rights,
    _tier0_group_sids,
    check,
)
from .model import Account, Finding, Severity, Snapshot

Edge = tuple[str, str]  # (target node, label)
UNESCAPED_COMMA = re.compile(r"(?<!\\),")


@dataclass
class Graph:
    edges: dict[str, list[Edge]]
    names: dict[str, str]
    tier0: set[str]

    def name(self, node: str) -> str:
        return self.names.get(node, node.split(":", 1)[-1])


@dataclass
class Path:
    start: str
    steps: list[Edge]  # (node reached, how)

    def render(self, g: Graph) -> str:
        out = g.name(self.start)
        for node, how in self.steps:
            out += f" -[{how}]-> {g.name(node)}"
        return out


def _sid_node(sid: str) -> str:
    return f"sid:{sid}"


def _dn_node(dn: str) -> str:
    return f"dn:{dn.lower()}"


CLASS_OF_KIND = {
    "user": sd.USER_CLASS,
    "computer": sd.COMPUTER_CLASS,
    "group": sd.GROUP_CLASS,
    "ou": sd.OU_CLASS,
}


def build(snap: Snapshot) -> Graph:
    edges: dict[str, list[Edge]] = {}
    names: dict[str, str] = {}

    def add(src: str, dst: str, how: str) -> None:
        if src != dst:
            edges.setdefault(src, []).append((dst, how))

    # DN -> node: objects with a SID are addressed by SID; the domain head is one node
    # whatever ACEs, links or the tier-0 set refer to it by
    domain_node = _dn_node(snap.domain_dn)
    dn_to_node: dict[str, str] = {}
    for a in snap.accounts:
        if a.sid:
            dn_to_node[a.dn.lower()] = _sid_node(a.sid)
            names[_sid_node(a.sid)] = a.sam
    for o in snap.objects:
        node = _sid_node(o.sid) if o.sid and o.kind != "domain" else _dn_node(o.dn)
        dn_to_node[o.dn.lower()] = node
        names.setdefault(node, o.name)
    for sid, name in snap.principals.items():
        names.setdefault(_sid_node(sid), name)

    def node_of(dn: str) -> str:
        key = dn.lower()
        if key in dn_to_node:
            return dn_to_node[key]
        first = dn.split(",", 1)[0]
        if ",cn=foreignsecurityprincipals," in key and first.upper().startswith("CN=S-1-"):
            return _sid_node(first[3:])
        return _dn_node(dn)

    def principal(sid: str) -> str:
        node = _sid_node(sid)
        names.setdefault(node, snap.name_of(sid))
        return node

    key_admins = {f"{snap.domain_sid}-526", f"{snap.domain_sid}-527"}
    skip = {PRINCIPAL_SELF, CREATOR_OWNER}

    def object_rights(ace: sd.Ace, kind: str) -> list[str]:
        if kind in ("user", "computer", "group"):
            rights = _risky_rights(ace, kind)
            if ace.sid in key_admins:
                rights = [r for r in rights if r != "write msDS-KeyCredentialLink"]
            return rights
        rights = ["full control"] if ace.takeover else []
        if kind in ("ou", "domain") and ace.writes(sd.GP_LINK) and not ace.takeover:
            rights.append("link GPOs")
        return rights

    # group membership
    for o in snap.objects:
        if o.kind == "group":
            target = node_of(o.dn)
            for m in o.members:
                add(node_of(m), target, "member of")

    # ACEs and owners
    for o in snap.objects:
        target = node_of(o.dn)
        if o.owner and o.owner not in skip:
            add(principal(o.owner), target, "owns")
        for ace in o.aces:
            if ace.sid not in skip:
                rights = object_rights(ace, o.kind)
                if rights:
                    add(principal(ace.sid), target, ", ".join(rights))
        if o.kind == "domain":
            # DCSync is normally two ACEs, one per replication right
            get = {a.sid for a in o.aces if a.extended_right(sd.DS_REPL_GET_CHANGES)}
            get_all = {a.sid for a in o.aces if a.extended_right(sd.DS_REPL_GET_CHANGES_ALL)}
            for sid in sorted((get & get_all) - skip):
                add(principal(sid), target, "DCSync")

    # Containers reach what is below them. Whoever controls an OU can make any ACE inherit
    # into it; ACEs that already inherit give their rights on matching children directly.
    # Objects with inheritance disabled (protected admins) are out of reach both ways.
    protected = {o.dn.lower() for o in snap.objects if o.dacl_protected}
    protected |= {a.dn.lower() for a in snap.accounts if a.admin_count}
    children: list[tuple[str, str, str]] = [  # (dn, node, kind)
        (a.dn, _sid_node(a.sid), "computer" if a.is_computer else "user")
        for a in snap.accounts
        if a.sid
    ]
    children += [(o.dn, node_of(o.dn), o.kind) for o in snap.objects if o.kind in ("group", "ou")]
    # index children under every OU/container above them (a DN suffix lookup per comma
    # instead of comparing every child with every container)
    parents = [p for p in snap.objects if p.kind in ("ou", "container")]
    parent_index = {p.dn.lower(): i for i, p in enumerate(parents)}
    below: list[list[tuple[str, str]]] = [[] for _ in parents]
    for dn, node, kind in children:
        key = dn.lower()
        if key in protected:
            continue
        for comma in UNESCAPED_COMMA.finditer(key):
            i = parent_index.get(key[comma.end() :])
            if i is not None:
                below[i].append((node, kind))
    for parent, kids in zip(parents, below, strict=True):
        parent_node = node_of(parent.dn)
        for node, kind in kids:
            add(parent_node, node, "contains")
            for ace in parent.inheritable:
                applies = ace.inherited_object_type in (None, CLASS_OF_KIND.get(kind))
                if ace.sid in skip or not applies:
                    continue
                rights = object_rights(ace, kind)
                if rights:
                    add(principal(ace.sid), node, f"{', '.join(rights)} (inherited)")

    # GPOs reach what they are linked to
    for g in snap.gpos:
        gpo_node = node_of(f"CN={g.guid},CN=Policies,CN=System,{snap.domain_dn}")
        names.setdefault(gpo_node, f"GPO {g.name}")
        for where in g.linked_to:
            add(gpo_node, domain_node if where == "domain" else "tier0:dc-ou", f"linked to {where}")

    # exploitable certificate templates turn enrollment into tier 0 (ESC1-3), and write
    # access to any published template makes it exploitable (ESC4)
    for t in snap.templates:
        if not t.published:
            continue
        esc = _issuable(t) and (
            (t.enrollee_supplies_subject and _authenticates(t))
            or not t.ekus
            or EKU_ANY in t.ekus
            or EKU_REQUEST_AGENT in t.ekus
        )
        node = f"tier0:template:{t.name}"
        for ace in t.aces:
            if ace.sid in skip:
                continue
            enrolls = ace.extended_right(sd.CERT_ENROLL) or ace.extended_right(sd.CERT_AUTOENROLL)
            if esc and enrolls:
                add(principal(ace.sid), node, "enroll (ESC1-3)")
            if ace.takeover:
                add(principal(ace.sid), node, "write template (ESC4)")
        names[node] = f"template {t.name}"
    # PKI object control (ESC5)
    for key, aces in snap.acls.items():
        if key.startswith("PKI:"):
            node = f"tier0:{key}"
            names[node] = key.removeprefix("PKI:")
            for ace in aces:
                if ace.takeover and ace.sid != f"{snap.domain_sid}-517":
                    add(principal(ace.sid), node, "full control")

    # gMSA password readers become the gMSA
    for gm in snap.gmsas:
        target = node_of(gm.dn)
        names.setdefault(target, gm.name)
        for sid in gm.readers:
            add(principal(sid), target, "read gMSA password")

    # tier-0 nodes
    tier0 = {_sid_node(s) for s in _tier0_group_sids(snap)}
    tier0 |= {node_of(dn) for dn in snap.tier0_dns()}
    tier0 |= {domain_node, "tier0:dc-ou"}
    tier0 |= {n for n in names if n.startswith("tier0:")}
    for o in snap.objects:
        dn = o.dn.lower()
        if dn.startswith("cn=adminsdholder,") or dn.startswith("ou=domain controllers,"):
            tier0.add(node_of(o.dn))
    names["tier0:dc-ou"] = "Domain Controllers OU"
    names[domain_node] = snap.domain
    for ca in snap.ca_hosts:  # CA servers sign logons for anyone: tier 0
        for a in snap.accounts:
            if a.sam.upper() == ca.upper() and a.sid:
                tier0.add(_sid_node(a.sid))
    return Graph(edges, names, tier0)


def paths_to_tier0(g: Graph) -> dict[str, Path]:
    """Shortest path from every non-tier-0 node that can reach tier 0."""
    reverse: dict[str, list[Edge]] = {}
    for src, outs in g.edges.items():
        for dst, how in outs:
            reverse.setdefault(dst, []).append((src, how))
    nxt: dict[str, Edge] = {}
    seen = set(g.tier0)
    queue = deque(sorted(g.tier0))
    while queue:
        node = queue.popleft()
        for src, how in reverse.get(node, []):
            if src in seen:
                continue
            seen.add(src)
            nxt[src] = (node, how)
            queue.append(src)
    return {start: _walk(start, nxt) for start in nxt}


def _walk(start: str, nxt: dict[str, Edge]) -> Path:
    steps, node = [], start
    while node in nxt:
        node, how = nxt[node]
        steps.append((node, how))
    return Path(start, steps)


def reachable(g: Graph, starts: Iterable[str]) -> dict[str, Path]:
    """Forward search: everything the start nodes control, with the shortest path."""
    prev: dict[str, tuple[str, str]] = {}
    seen = set(starts)
    queue = deque(sorted(seen))
    while queue:
        node = queue.popleft()
        for dst, how in g.edges.get(node, []):
            if dst not in seen:
                seen.add(dst)
                prev[dst] = (node, how)
                queue.append(dst)
    out = {}
    for end in prev:
        steps, node = [], end
        while node in prev:
            parent, how = prev[node]
            steps.append((node, how))
            node = parent
        out[end] = Path(node, list(reversed(steps)))
    return out


def identity_nodes(snap: Snapshot, sam_or_sid: str) -> list[str]:
    """The account's own node plus the groups it is in without a member link."""
    key = sam_or_sid.lower()
    account = next((a for a in snap.accounts if a.sam.lower() == key or a.sid.lower() == key), None)
    return [] if account is None else _identity(snap, account)


def _identity(snap: Snapshot, account: Account) -> list[str]:
    machine = account.is_computer or account.managed
    primary = account.primary_group or (515 if machine else 513)
    nodes = [_sid_node(account.sid), _sid_node("S-1-1-0"), _sid_node("S-1-5-11")]
    nodes.append(_sid_node(f"{snap.domain_sid}-{primary}"))
    if not machine:
        nodes.append(_sid_node("S-1-5-32-545"))
    if account.is_dc:
        nodes.append(_sid_node("S-1-5-9"))
    return nodes


def exposure(snap: Snapshot, g: Graph, found: dict[str, Path]) -> tuple[int, int]:
    """(enabled non-tier-0 users with a path to tier 0, enabled non-tier-0 users).

    `found` holds every node with a path, so a user is exposed when its own node is in it
    (directly or through group membership edges) or one of its implicit groups is.
    """
    users = [a for a in snap.accounts if a.enabled and not a.is_computer and not a.managed]
    users = [a for a in users if a.sid and _sid_node(a.sid) not in g.tier0]
    exposed = sum(
        1
        for a in users
        if any(n in found or n in g.tier0 for n in _identity(snap, a)[1:])
        or _sid_node(a.sid) in found
    )
    return exposed, len(users)


def direct_holders(g: Graph, found: dict[str, Path]) -> dict[str, Path]:
    """Principals that hold a right themselves (not only through a group), each with the
    shortest path that starts with one of their own rights."""
    out = {}
    for node in found:
        if not node.startswith("sid:"):
            continue
        best: Path | None = None
        for dst, how in g.edges.get(node, []):
            if how == "member of":
                continue
            if dst in g.tier0:
                candidate = Path(node, [(dst, how)])
            elif dst in found:
                candidate = Path(node, [(dst, how), *found[dst].steps])
            else:
                continue
            if best is None or len(candidate.steps) < len(best.steps):
                best = candidate
        if best is not None:
            out[node] = best
    return out


BROAD_FIRST = (
    "Everyone",
    "Anonymous Logon",
    "Authenticated Users",
    "Domain Users",
    "Domain Computers",
    "Users",
    "Pre-Windows 2000 Compatible Access",
)


@check("AD-PATH-001", "Control paths from non-tier-0 principals to tier 0")
def tier0_paths(snap: Snapshot) -> Finding | None:
    g = build(snap)
    found = paths_to_tier0(g)
    # principals that hold a right themselves; members who only inherit it through a group
    # are counted in the exposure figure instead of being listed one by one
    starts = direct_holders(g, found)
    if not starts:
        return None
    exposed, total = exposure(snap, g, found)
    ordered = sorted(
        starts.values(),
        key=lambda p: (g.name(p.start) not in BROAD_FIRST, len(p.steps), g.name(p.start).lower()),
    )
    broad = [p for p in ordered if g.name(p.start) in BROAD_FIRST]
    detail = (
        f"{len(starts)} principals outside tier 0 can reach it; {exposed} of {total} enabled "
        f"users ({(100 * exposed // total) if total else 0}%) have a path through their "
        "accounts or groups. Each object shows the shortest path."
    )
    if broad:
        detail += " Broad groups have a path, so every user is effectively tier 0."
    return _finding(
        "AD-PATH-001",
        Severity.HIGH,
        detail,
        "Break each path at its first step, starting with the ones shared by most paths "
        "(see `ad-doctor blast-radius` for one account).",
        [p.render(g) for p in ordered],
    )
