"""Control paths to tier 0 from a single snapshot, without a graph database.

Nodes are principals (by SID) and objects without a SID (OUs, GPOs, PKI objects, the
domain head). An edge A -> B means "A controls B or becomes B": group membership, an ACE
that allows a takeover, ownership, DCSync, editing a GPO, enrolling in an exploitable
certificate template, reading a gMSA password, local admin rights a GPO hands out (admin
on a computer is SYSTEM there, so it becomes the computer account), a sync server holding
its sync account's password. A reverse breadth-first search from every tier-0 node finds
the shortest path from any other principal.

Remote logon rights a GPO grants (RDP, WinRM, DCOM) are kept apart as logon edges: they
are exported, but logon is not control, so the path search does not follow them.

Whoever can write a GPO controls what it applies to. That reach runs through scope nodes
(gpo_scope.Reach), not through OU nodes: an OU's contains edges stand for ACL inheritance.
Scope nodes are plumbing, so they count as neither controlled objects nor tier 0.
"""

from __future__ import annotations

import sys
from collections import Counter, deque
from collections.abc import Callable, Iterable, Iterator
from contextlib import contextmanager
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any

from . import gpo_scope, sd
from .checks import (
    CA_RIGHTS,
    CREATOR_OWNER,
    EKU_ANY,
    EKU_REQUEST_AGENT,
    PRINCIPAL_SELF,
    _authenticates,
    _finding,
    _issuable,
    _risky_rights,
    _sync_accounts,
    _sync_servers,
    _tier0_group_sids,
    ca_control,
    check,
    officer_templates,
)
from .model import WELL_KNOWN_SIDS, Account, DirObject, Finding, Severity, Snapshot

if TYPE_CHECKING:
    from .provenance import Provenance

Edge = tuple[str, str]  # (target node, label)
GPO_APPLIES = "GPO applies to"  # GPO to the scope of a link
GPO_INHERITED = "GPO inherited by"  # scope to the scope of a child OU
GPO_REACHES = "GPO reaches"  # scope to an account
UNESCAPED_COMMA = gpo_scope.RDN_SEPARATOR


@dataclass
class Graph:
    edges: dict[str, list[Edge]]
    names: dict[str, str]
    tier0: set[str]
    # remote logon rights (not traversed by the path search)
    logon_edges: dict[str, list[Edge]] = field(default_factory=dict)
    # (source, target, label) -> extra edge properties: the GPO and its caveats
    edge_props: dict[tuple[str, str, str], dict[str, Any]] = field(default_factory=dict)
    # node -> object class where the snapshot says it (user, computer, group, ou, ...)
    kinds: dict[str, str] = field(default_factory=dict)
    # what-if: the removable fact behind each edge (build(snap, provenance=True))
    prov: Provenance | None = None

    def name(self, node: str) -> str:
        """The node's directory name; a well-known SID the snapshot holds no object for
        (Authenticated Users, Everyone, ...) by its standard name, else the bare ID."""
        if node in self.names:
            return self.names[node]
        bare = node.split(":", 1)[-1]
        return WELL_KNOWN_SIDS.get(bare, bare) if node.startswith("sid:") else bare

    def ident(self, node: str) -> str:
        """The name a path's start is keyed by in baselines and acceptance files: the
        directory name, else the bare SID (unchanged when well-known SIDs got names)."""
        return self.names.get(node, node.split(":", 1)[-1])

    def kind(self, node: str) -> str:
        """user, computer, gmsa, group, ou, container, gpo, domain, template, pki, ca or
        principal (a SID the snapshot holds no object for)."""
        if node in self.kinds:
            return self.kinds[node]
        for prefix, kind in NODE_PREFIX_KINDS:
            if node.startswith(prefix):
                return kind
        sid = node.removeprefix("sid:")
        rid = sid.rsplit("-", 1)[-1]
        if sid in WELL_KNOWN_GROUPS or sid.startswith("S-1-5-32-") or rid in DOMAIN_GROUP_RIDS:
            return "group"
        return "principal"

    def record(self, node: str) -> dict[str, Any]:
        """A node as JSON for reports and the viewer."""
        return {
            "id": node,
            "name": self.name(node),
            "kind": self.kind(node),
            "tier0": node in self.tier0,
        }


NODE_PREFIX_KINDS = (
    ("tier0:template:", "template"),
    ("tier0:PKI:", "pki"),
    ("tier0:ca:", "ca"),
    ("tier0:dc-ou", "ou"),
    ("gpo-scope:", "scope"),
)
# Everyone, Anonymous Logon, Authenticated Users, Enterprise Domain Controllers
WELL_KNOWN_GROUPS = {"S-1-1-0", "S-1-5-7", "S-1-5-11", "S-1-5-9"}
# Domain Admins .. Enterprise Key Admins, RAS and IAS Servers, (Denied) RODC Password
# Replication Group: groups whose snapshot object may be missing
DOMAIN_GROUP_RIDS = {*map(str, range(512, 528)), "553", "571", "572"}


@dataclass
class Path:
    start: str
    steps: list[Edge]  # (node reached, how)

    def render(self, g: Graph) -> str:
        out = g.name(self.start)
        src = self.start
        for node, how in self.steps:
            caveats = g.edge_props.get((src, node, how), {}).get("caveats")
            # a report has only this text: what an edge assumes must show in it
            mark = f" ({'; '.join(caveats)})".replace("]", "") if caveats else ""
            out += f" -[{how}{mark}]-> {g.name(node)}"
            src = node
        return out

    def record(self, g: Graph) -> dict[str, Any]:
        """The path as JSON: the start principal and each step, with names, kinds and
        whether the node is tier 0."""
        return {
            "object": self.render(g),
            "start": g.record(self.start),
            "steps": [{"how": how, **g.record(node)} for node, how in self.steps],
        }

    @classmethod
    def from_record(cls, data: dict[str, Any]) -> Path:
        return cls(data["start"]["id"], [(s["id"], s["how"]) for s in data["steps"]])


def _sid_node(sid: str) -> str:
    return sys.intern(f"sid:{sid}")  # every edge of a node shares one string


def _dn_node(dn: str) -> str:
    return f"dn:{dn.lower()}"


CLASS_OF_KIND = {
    "user": sd.USER_CLASS,
    "computer": sd.COMPUTER_CLASS,
    "group": sd.GROUP_CLASS,
    "ou": sd.OU_CLASS,
}


def build(snap: Snapshot, provenance: bool = False) -> Graph:
    """The control graph. With `provenance`, Graph.prov also records the removable fact
    behind every edge (what-if); the graph itself is the same either way."""
    edges: dict[str, list[Edge]] = {}
    names: dict[str, str] = {}
    kinds: dict[str, str] = {}
    rec: Provenance | None = None

    # `why` is `rec and rec.<reason>(...)`: None (and not worked out) without provenance
    def add(src: str, dst: str, how: str, why: Any = None) -> None:
        if src != dst:
            edges.setdefault(src, []).append((dst, how))
            if rec is not None:
                rec.push(src, why)

    # DN -> node: objects with a SID are addressed by SID; the domain head is one node
    # whatever ACEs, links or the tier-0 set refer to it by
    domain_node = _dn_node(snap.domain_dn)
    dn_to_node: dict[str, str] = {}
    for a in snap.accounts:
        if a.sid:
            dn_to_node[a.dn.lower()] = _sid_node(a.sid)
            names[_sid_node(a.sid)] = a.sam
            kind = "gmsa" if a.managed else "computer" if a.is_computer else "user"
            kinds[_sid_node(a.sid)] = kind
    for o in snap.objects:
        node = _sid_node(o.sid) if o.sid and o.kind != "domain" else _dn_node(o.dn)
        dn_to_node[o.dn.lower()] = node
        names.setdefault(node, o.name)
        kinds.setdefault(node, o.kind)
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

    if provenance:
        from .provenance import FIXED, Provenance

        rec = Provenance(snap, node_of, domain_node)

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
                source = node_of(m)
                add(source, target, "member of", rec and rec.member(o, m, target, source))

    # ACEs and owners
    for o in snap.objects:
        target = node_of(o.dn)
        if o.owner and o.owner not in skip:
            add(principal(o.owner), target, "owns", rec and rec.owner(o))
        for ace in o.aces:
            if ace.sid not in skip:
                rights = object_rights(ace, o.kind)
                if rights:
                    how = ", ".join(rights)
                    add(principal(ace.sid), target, how, rec and rec.ace(o, ace, how))
        if o.kind == "domain":
            # DCSync is normally two ACEs, one per replication right
            get = {a.sid for a in o.aces if a.extended_right(sd.DS_REPL_GET_CHANGES)}
            get_all = {a.sid for a in o.aces if a.extended_right(sd.DS_REPL_GET_CHANGES_ALL)}
            for sid in sorted((get & get_all) - skip):
                add(principal(sid), target, "DCSync", rec and rec.dcsync(o, sid))

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
            add(parent_node, node, "contains", rec and FIXED["contains"])
            for ace in parent.inheritable:
                applies = ace.inherited_object_type in (None, CLASS_OF_KIND.get(kind))
                if ace.sid in skip or not applies:
                    continue
                rights = object_rights(ace, kind)
                if rights:
                    how = f"{', '.join(rights)} (inherited)"
                    add(principal(ace.sid), node, how, rec and rec.ace(parent, ace, how))

    logon_edges: dict[str, list[Edge]] = {}
    edge_props: dict[tuple[str, str, str], dict[str, Any]] = {}

    # GPOs reach what they are linked to. A link to the domain or the DC OU counts as
    # control of tier 0 only if the GPO gets to a writable DC (older snapshots hold no
    # links; a snapshot without DCs cannot tell)
    reach = gpo_scope.reach(snap)
    gpo_nodes: dict[str, str] = {}
    has_dcs = any(a.is_registered_dc and not a.is_rodc for a in snap.accounts)
    gpo_objects = {o.dn.lower(): o for o in snap.objects if o.kind == "gpo"}
    for g in snap.gpos:
        guid = g.guid.upper()
        dn = f"CN={g.guid},CN=Policies,CN=System,{snap.domain_dn}"
        gpo_node = node_of(dn)
        gpo_nodes[guid] = gpo_node
        names.setdefault(gpo_node, f"GPO {g.name}")
        kinds[gpo_node] = "gpo"
        targets = [
            (domain_node if where == "domain" else "tier0:dc-ou", f"linked to {where}")
            for where in g.linked_to
        ]
        if not (g.links and has_dcs) or guid in reach.dc_gpos:
            for (target, how), where in zip(targets, g.linked_to, strict=True):
                add(gpo_node, target, how, rec and rec.dc_link(guid, where))
                if reach.dc_gpos.get(guid):
                    edge_props[(gpo_node, target, how)] = {
                        "gpo": g.name,
                        "caveats": list(reach.dc_gpos[guid]),
                    }
        # a filter stops a writer of values, not whoever can rewrite the DACL: that writer
        # gets a node of its own, which goes where the GPO would with no filter
        wide = reach.widened.get(guid, [])
        rewriters = _dacl_writers(gpo_objects.get(dn.lower()), skip) if wide else {}
        if rewriters:
            unfiltered = node_of(f"CN=Filter,{dn}")
            names[unfiltered] = f"GPO {g.name} with its filter changed"
            kinds[unfiltered] = "gpo"
            for sid, how in rewriters.items():
                gpo_object = gpo_objects[dn.lower()]
                add(principal(sid), unfiltered, how, rec and rec.rewriter(gpo_object, sid))
            for scope, caveats in wide:
                add(unfiltered, scope, GPO_APPLIES, rec and FIXED["filter-node"])
                if caveats:
                    edge_props[(unfiltered, scope, GPO_APPLIES)] = {
                        "gpo": g.name,
                        "caveats": list(caveats),
                    }
            if guid in reach.dc_widened:
                for target, how in targets:
                    add(unfiltered, target, how, rec and FIXED["filter-node"])
    names.update(reach.names)
    for g, scope, caveats in reach.applies:
        src = gpo_nodes[g.guid.upper()]
        why = rec and rec.applies(g.guid, scope, GPO_APPLIES, reach.entered_by)
        add(src, scope, GPO_APPLIES, why)
        if caveats:
            edge_props[(src, scope, GPO_APPLIES)] = {"gpo": g.name, "caveats": list(caveats)}
    for scope, below_it in reach.inherits:
        add(scope, below_it, GPO_INHERITED, rec and FIXED["gpo-scope"])
    for scope, account in reach.holds:
        add(scope, _sid_node(account.sid), GPO_REACHES, rec and FIXED["gpo-scope"])

    # local groups set by Group Policy: an admin-equivalent group makes the member SYSTEM on
    # the computer, so it becomes the computer account; a domain group rewritten through
    # the DCs is plain membership
    for grant in gpo_scope.grants(snap):
        member = principal(grant.item.member_sid)
        via = f" via GPO {grant.gpo.name}"
        if grant.computer is None:
            target, how = _sid_node(grant.item.group_sid), "member of" + via
            names.setdefault(target, snap.name_of(grant.item.group_sid))
            add(member, target, how, rec and rec.grant(grant))
        else:
            group = gpo_scope.LOCAL_GROUPS[grant.item.group_sid]
            target, how = _sid_node(grant.computer.sid), group.verb + via
            if group.admin:
                add(member, target, how, rec and rec.grant(grant))
            elif grant.effective:
                logon_edges.setdefault(member, []).append((target, how))
                if rec is not None:
                    rec.push_logon(member, rec.grant(grant))
            else:
                continue
        props: dict[str, Any] = {"gpo": grant.gpo.name}
        if grant.caveats:
            props["caveats"] = list(grant.caveats)
        edge_props[(member, target, how)] = props
    # the ADSync service keeps the sync account's password on its server
    for account in _sync_accounts(snap):
        for server in _sync_servers(snap, account):
            server_node, account_node = _sid_node(server.sid), _sid_node(account.sid)
            add(server_node, account_node, "hosts sync account", rec and FIXED["sync-host"])

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
                add(principal(ace.sid), node, "enroll (ESC1-3)", rec and rec.enroll(t, ace.sid))
            if ace.takeover:
                how = "write template (ESC4)"
                add(principal(ace.sid), node, how, rec and rec.template_ace(t, ace.sid))
        names[node] = f"template {t.name}"
    # PKI object control (ESC5)
    for key, aces in snap.acls.items():
        if key.startswith("PKI:"):
            node = f"tier0:{key}"
            names[node] = key.removeprefix("PKI:")
            for ace in aces:
                if ace.takeover and ace.sid != f"{snap.domain_sid}-517":
                    add(principal(ace.sid), node, "full control", rec and rec.pki(key, ace.sid))
    # managing a CA controls a tier-0 server (ESC7); ManageCertificates alone only when a
    # published template lets the requester name the subject
    hosts = {a.dns_host.lower(): _sid_node(a.sid) for a in snap.accounts if a.dns_host and a.sid}
    officer = bool(officer_templates(snap))
    ca_nodes: set[str] = set()
    for c, sid, right in ca_control(snap):
        if right == "ManageCertificates" and not officer:
            continue
        ca_node = hosts.get(c.host.lower(), f"tier0:ca:{c.name}")
        ca_nodes.add(ca_node)
        names.setdefault(ca_node, f"CA {c.name}")
        kinds.setdefault(ca_node, "ca")
        add(principal(sid), ca_node, f"{right} (ESC7)", rec and rec.ca_right(c.name, sid, right))
        if rec is not None and principal(sid) != ca_node:
            rec.note_ca_edge(principal(sid), ca_node)
    if rec is not None:
        rec.hidden_ca = _hidden_ca_holders(snap)

    # gMSA password readers become the gMSA
    for gm in snap.gmsas:
        target = node_of(gm.dn)
        names.setdefault(target, gm.name)
        kinds.setdefault(target, "gmsa")
        for sid in gm.readers:
            add(principal(sid), target, "read gMSA password", rec and rec.gmsa(gm.dn, sid))

    tier0 = tier0_nodes(snap, node_of, domain_node, ca_nodes, names, snap.tier0_dns())
    names["tier0:dc-ou"] = "Domain Controllers OU"
    names[domain_node] = snap.domain
    kinds[domain_node] = "domain"
    return Graph(edges, names, tier0, logon_edges, edge_props, kinds, rec)


def tier0_nodes(
    snap: Snapshot,
    node_of: Callable[[str], str],
    domain_node: str,
    ca_nodes: Iterable[str],
    names: Iterable[str],
    tier0_dns: Iterable[str],
) -> set[str]:
    """Tier-0 groups and accounts, the domain head, the DC OU, AdminSDHolder, CA servers,
    CA nodes that an ESC7 edge reaches, and the tier0: nodes among `names` (templates,
    PKI objects). What-if calls it again after a change to group membership."""
    tier0 = {_sid_node(s) for s in _tier0_group_sids(snap)}
    tier0 |= {node_of(dn) for dn in tier0_dns}
    tier0 |= {domain_node, "tier0:dc-ou"} | set(ca_nodes)
    tier0 |= {n for n in names if n.startswith("tier0:")}
    for o in snap.objects:
        dn = o.dn.lower()
        if dn.startswith("cn=adminsdholder,") or dn.startswith("ou=domain controllers,"):
            tier0.add(node_of(o.dn))
    for ca in snap.ca_hosts:  # CA servers sign logons for anyone: tier 0
        for a in snap.accounts:
            if a.sam.upper() == ca.upper() and a.sid:
                tier0.add(_sid_node(a.sid))
    return tier0


def _hidden_ca_holders(snap: Snapshot) -> set[str]:
    """SIDs holding a CA right that ca_control leaves out (tier 0, not a fixed tier-0
    group): a membership change can take them out of tier 0 and give them an edge."""
    shown = {sid for _, sid, _ in ca_control(snap)}
    held: set[str] = set()
    for c in snap.probes.ca_configs:
        if c.owner:
            held.add(c.owner)
        held |= {a.sid for a in c.aces if any(a.mask & bit for bit, _ in CA_RIGHTS)}
    return held - shown - _tier0_group_sids(snap)


def _dacl_writers(o: DirObject | None, skip: set[str]) -> dict[str, str]:
    """SID -> edge label, for those who can change who a GPO applies to."""
    if o is None:
        return {}
    found = {a.sid: "full control" for a in o.aces if a.rewrites_dacl and a.sid not in skip}
    if o.owner and o.owner not in skip:
        found[o.owner] = "owns"
    return found


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


def blast_radius(g: Graph, starts: list[str]) -> tuple[dict[str, Path], list[Path]]:
    """What the identity `starts` (identity_nodes) controls, and its paths into tier 0:
    the tier-0 objects it reaches, shortest first, led by the account itself when it (or
    one of its implicit groups) is tier 0 already. The viewer's JavaScript ports this."""
    found = reachable(g, starts)
    controlled = {n: p for n, p in found.items() if g.kind(n) != "scope"}
    tier0 = sorted((p for n, p in controlled.items() if n in g.tier0), key=lambda p: len(p.steps))
    if starts and starts[0] in g.tier0:  # the account itself is tier 0
        tier0.insert(0, Path(starts[0], []))
    elif any(s in g.tier0 for s in starts[1:]):
        start = next(s for s in starts[1:] if s in g.tier0)
        tier0.insert(0, Path(starts[0], [(start, "primary group")]))
    return controlled, tier0


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


@dataclass
class Analysis:
    """What AD-PATH-001, `ad-doctor paths` and the viewer report."""

    graph: Graph
    # principals that hold a right themselves, each with its shortest path, in report
    # order: broad groups first, then by length, then by name
    paths: list[Path]
    exposed: int  # enabled non-tier-0 users with a path
    users: int  # enabled non-tier-0 users

    @property
    def broad(self) -> list[Path]:
        return [p for p in self.paths if self.graph.name(p.start) in BROAD_FIRST]

    @property
    def percent(self) -> int:
        return (100 * self.exposed // self.users) if self.users else 0


# (snapshot, graph built from it): what-if lends its graph to the checks it runs on the
# snapshot as collected, so AD-PATH-001 does not build the same graph again
_LENT: tuple[Snapshot, Graph] | None = None


@contextmanager
def lend(snap: Snapshot, g: Graph) -> Iterator[None]:
    """While active, analyze(snap) uses `g`, which must be built from `snap` as it is."""
    global _LENT
    _LENT = (snap, g)
    try:
        yield
    finally:
        _LENT = None


def analyze(snap: Snapshot, g: Graph | None = None) -> Analysis:
    """`g`: a graph already built from this snapshot (with provenance, say)."""
    if g is None and _LENT is not None and _LENT[0] is snap:
        g = _LENT[1]
    g = build(snap) if g is None else g
    found = paths_to_tier0(g)
    # principals that hold a right themselves; members who only inherit it through a group
    # are counted in the exposure figure instead of being listed one by one
    starts = direct_holders(g, found)
    exposed, total = exposure(snap, g, found)
    ordered = sorted(
        starts.values(),
        key=lambda p: (g.name(p.start) not in BROAD_FIRST, len(p.steps), g.name(p.start).lower()),
    )
    return Analysis(g, ordered, exposed, total)


@dataclass(frozen=True)
class Chokepoint:
    """An edge (`source` set) or a node (`source` None) that `count` paths go through."""

    target: str
    count: int
    source: str | None = None
    how: str = ""

    @property
    def is_edge(self) -> bool:
        return self.source is not None


def chokepoints(paths: Iterable[Path], minimum: int = 2) -> list[Chokepoint]:
    """The edges and nodes that at least `minimum` paths share, most shared first: the
    places where one change breaks the most paths. A node counts for every path that
    starts at it or passes through it; the tier-0 object a path ends at is not counted,
    because that is not where a path can be broken."""
    edges: Counter[tuple[str, str, str]] = Counter()
    nodes: Counter[str] = Counter()
    for p in paths:
        hops: set[tuple[str, str, str]] = set()
        prev = p.start
        for node, how in p.steps:
            hops.add((prev, node, how))
            prev = node
        edges.update(hops)
        nodes.update({p.start, *(node for node, _ in p.steps[:-1])})
    out = [Chokepoint(t, n, s, h) for (s, t, h), n in edges.items() if n >= minimum]
    out += [Chokepoint(node, n) for node, n in nodes.items() if n >= minimum]
    out.sort(key=lambda c: (-c.count, not c.is_edge, c.source or "", c.target, c.how))
    return out


@check("AD-PATH-001", "Control paths from non-tier-0 principals to tier 0")
def tier0_paths(snap: Snapshot) -> Finding | None:
    a = analyze(snap)
    if not a.paths:
        return None
    g = a.graph
    detail = (
        f"{len(a.paths)} principals outside tier 0 can reach it; {a.exposed} of {a.users} "
        f"enabled users ({a.percent}%) have a path through their accounts or groups. "
        "Each object shows the shortest path."
    )
    if a.broad:
        detail += " Broad groups have a path, so every user is effectively tier 0."
    f = _finding(
        "AD-PATH-001",
        Severity.HIGH,
        detail,
        "Break each path at its first step, starting with the ones shared by most paths "
        "(`ad-doctor paths --chokepoints` ranks them; `ad-doctor blast-radius` shows one "
        "account).",
        [p.render(g) for p in a.paths],
    )
    # a path's identity is the principal it starts from: when the path gets longer or takes
    # another route it keeps its fingerprint and is not new in a diff
    f.keys = {p.render(g): g.ident(p.start) for p in a.paths}
    f.data = {
        "exposed": a.exposed,
        "users": a.users,
        "paths": [p.record(g) for p in a.paths],
    }
    return f
