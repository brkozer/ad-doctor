"""Control paths to tier 0 from a single snapshot, without a graph database.

Nodes are principals (by SID) and objects without a SID (OUs, GPOs, PKI objects, the
domain head). An edge A -> B means "A controls B or becomes B": group membership, an ACE
that allows a takeover, ownership, DCSync, editing a GPO, enrolling in an exploitable
certificate template or one whose issuance policy carries a group, reading a gMSA password,
local admin rights a GPO hands out (admin on a computer is SYSTEM there, so it becomes the
computer account), a sync server holding
its sync account's password, delegation that lets an account impersonate an admin to a
computer, a SID held in sIDHistory. A reverse breadth-first search from every tier-0
node finds the shortest path from any other principal.

Remote logon rights a GPO grants (RDP, WinRM, DCOM) are kept apart as logon edges: they
are exported, but logon is not control, so the path search does not follow them.

Whoever can write a GPO controls what it applies to. That reach runs through scope nodes
(gpo_scope.Reach), not through OU nodes: an OU's contains edges stand for ACL inheritance.
Scope nodes are plumbing, so they count as neither controlled objects nor tier 0.
"""

from __future__ import annotations

import sys
from collections import Counter, deque
from collections.abc import Callable, Collection, Container, Iterable, Iterator
from contextlib import contextmanager
from dataclasses import dataclass, field, replace
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
    _spn_aliases,
    _sync_accounts,
    _sync_servers,
    _tier0_group_sids,
    ca_control,
    check,
    every_ca_holds,
    linked_policies,
    officer_templates,
    san_ca,
)
from .model import UAC, WELL_KNOWN_SIDS, Account, DirObject, Finding, Severity, Snapshot

if TYPE_CHECKING:
    from .provenance import Provenance

Edge = tuple[str, str]  # (target node, label)
GPO_APPLIES = "GPO applies to"  # GPO to the scope of a link
GPO_INHERITED = "GPO inherited by"  # scope to the scope of a child OU
GPO_REACHES = "GPO reaches"  # scope to an account
UNESCAPED_COMMA = gpo_scope.RDN_SEPARATOR
CONSTRAINED = "constrained delegation (protocol transition)"
RESOURCE_BASED = "resource-based delegation"
SID_HISTORY = "SID history"
ENROLL_ESC13 = "enroll (ESC13)"
ENROLL_ESC6 = "enroll (ESC6+ESC16)"
# a snapshot does not hold a member server's local groups
LOCAL_ADMIN_CAVEAT = gpo_scope.LOCAL_ADMIN_CAVEAT
# msDS-Behavior-Version of Windows Server 2012 R2, from which DCs apply Protected Users
PROTECTED_USERS_LEVEL = 6
EVERY_LOGON = ("S-1-1-0", "S-1-5-11")  # Everyone, Authenticated Users
DECLARED_MARK = " [declared tier 0]"  # ends a path whose target a user declared


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
    # nodes a user declared as tier 0 (declared.py): extended targets, kept apart from the
    # built-in set above (what-if also adds them to `tier0`, for the cut)
    declared: set[str] = field(default_factory=set)

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


def edge_text(g: Graph, src: str, dst: str, how: str) -> str:
    """An edge's label as a path shows it: what the edge assumes must be in the text."""
    caveats = g.edge_props.get((src, dst, how), {}).get("caveats")
    mark = f" ({'; '.join(caveats)})".replace("]", "") if caveats else ""
    return how + mark


@dataclass
class Path:
    start: str
    steps: list[Edge]  # (node reached, how)

    def render(self, g: Graph) -> str:
        out = g.name(self.start)
        src = self.start
        for node, how in self.steps:
            out += f" -[{edge_text(g, src, node, how)}]-> {g.name(node)}"
            src = node
        return out + DECLARED_MARK if self.steps and src in g.declared else out

    def record(self, g: Graph) -> dict[str, Any]:
        """The path as JSON: the start principal and each step, with names, kinds and
        whether the node is tier 0."""
        steps = [{"how": how, **g.record(node)} for node, how in self.steps]
        if steps and self.steps[-1][0] in g.declared:
            steps[-1]["declared"] = True  # the end only: a declared start or stop changes nothing
        return {"object": self.render(g), "start": g.record(self.start), "steps": steps}

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
    # An issuance policy linked to a group (ESC13) adds that group to the ticket of whoever
    # logs on with the certificate. A CA with ESC6 and ESC16 issues a certificate for any
    # user from any authentication template (AD-CHAIN-004). Both need the Enroll right
    # itself: AutoEnroll alone cannot request a certificate. A CA that holds every request
    # for a manager issues nothing on request, so neither edge exists through it.
    ca = san_ca(snap)
    held = every_ca_holds(snap)
    for t in snap.templates:
        if not _issuable(t) or not _authenticates(t):
            continue
        enrollers = list(
            dict.fromkeys(
                a.sid for a in t.aces if a.sid not in skip and a.extended_right(sd.CERT_ENROLL)
            )
        )
        for oid in () if held else linked_policies(snap, t):
            linked = snap.oid_group_links[oid]
            target = node_of(linked)
            for sid in enrollers:
                add(principal(sid), target, ENROLL_ESC13, rec and rec.esc13(t, sid, oid, linked))
        if ca is not None:
            node = f"tier0:template:{t.name}"
            for sid in enrollers:
                add(principal(sid), node, ENROLL_ESC6, rec and rec.esc6(t, sid, ca.name))
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

    _delegation_edges(snap, add, principal, node_of, rec, edge_props)

    tier0 = tier0_nodes(snap, node_of, domain_node, ca_nodes, names, snap.tier0_dns())
    names["tier0:dc-ou"] = "Domain Controllers OU"
    names[domain_node] = snap.domain
    kinds[domain_node] = "domain"
    return Graph(edges, names, tier0, logon_edges, edge_props, kinds, rec)


def _delegation_edges(
    snap: Snapshot,
    add: Callable[[str, str, str, Any], None],
    principal: Callable[[str], str],
    node_of: Callable[[str], str],
    rec: Provenance | None,
    edge_props: dict[tuple[str, str, str], dict[str, Any]],
) -> None:
    """S4U delegation and SID history. Impersonating an admin to a computer makes the
    source admin there, so it becomes the computer account. What each edge needs:

    - constrained: protocol transition (without it S4U2self gives no forwardable ticket,
      so the source needs a victim's ticket) and an SPN of its own; the target SPN
      resolves to one computer, as the KDC would resolve it.
    - resource-based: the source can run S4U2self: a computer (it can write itself an
      SPN) or an account with an SPN. S4U2self is run by the account holding the SPN, and
      sharing a group with it gives no control of it, so a listed group gives the edge to
      those of its members, not to the group (_s4u_sources says who, per well-known SID).
    - both: an enabled target with an SPN, and an admin of it that can be delegated.
    - SID history: nothing else inside the domain; the holder's tickets carry the SID.
    """
    for a in snap.accounts:
        if a.sid:
            for sid in a.sid_history:
                if sid.startswith("S-1-5-21-"):  # the built-in SIDs are not migrated ones
                    add(
                        _sid_node(a.sid),
                        principal(sid),
                        SID_HISTORY,
                        rec and rec.sid_history(a.dn, sid),
                    )
    constrained = [
        a
        for a in snap.accounts
        if a.sid and a.allowed_to_delegate_to and a.has(UAC.TRUSTED_TO_AUTH_FOR_DELEGATION)
    ]
    resource = [a for a in snap.accounts if a.sid and a.rbcd and a.rbcd_principals]
    if not constrained and not resource:
        return
    groups = {o.dn.lower(): o for o in snap.objects if o.kind == "group"}
    if rec is not None:  # a membership change can open or close these edges
        rec.condition_groups = _condition_groups(snap, groups, resource)
    server, rodc, dc = _impersonable(snap)

    def host(a: Account | None) -> bool:
        return (
            a is not None
            and a.is_computer
            and not a.managed
            and a.enabled
            and bool(a.spns)
            and (rodc if a.is_rodc else dc if a.is_dc else server)
        )

    def link(src: str, target: Account, how: str, why: Any) -> None:
        dst = _sid_node(target.sid)
        add(src, dst, how, why)
        if not target.is_dc and src != dst:
            edge_props[(src, dst, how)] = {"caveats": [LOCAL_ADMIN_CAVEAT]}

    owner: dict[str, Account | None] = {}
    if constrained:
        for a in snap.accounts:
            for spn in a.spns:
                key = spn.lower()
                owner[key] = a if key not in owner or owner[key] is a else None
    aliases = _spn_aliases(snap)

    def holder(spn: str) -> Account | None:
        """The one account the KDC finds for an SPN: as written, else through sPNMappings."""
        key = spn.lower().rstrip(".")
        if key in owner:
            return owner[key]
        service, _, rest = key.partition("/")
        return owner.get(f"{aliases[service]}/{rest}") if service in aliases else None

    for a in constrained:
        if a.is_computer or a.spns:
            for spn in a.allowed_to_delegate_to:
                target = holder(spn)
                if target is not None and host(target):
                    link(_sid_node(a.sid), target, CONSTRAINED, rec and rec.constrained(a.dn, spn))
    sources: dict[str, list[str]] = {}
    for target in resource:
        if host(target):
            for sid in target.rbcd_principals or ():
                if sid not in sources:
                    sources[sid] = _s4u_sources(snap, groups, node_of, sid)
                for src in sources[sid]:
                    link(principal(src), target, RESOURCE_BASED, rec and rec.rbcd(target.dn, sid))


def _impersonable(snap: Snapshot) -> tuple[bool, bool, bool]:
    """(a member server, a read-only DC, a writable DC) has an admin the KDC lets a service
    impersonate: enabled, not marked sensitive, not in Protected Users (which the DCs apply
    from the 2012 R2 domain functional level). A writable DC's own account counts on a
    writable DC: as that account a service can replicate. It is no admin of an RODC, and an
    RODC does not replicate outbound."""
    level = snap.policy.functional_level
    protected = (
        {dn.lower() for dn in snap.protected_users} if level >= PROTECTED_USERS_LEVEL else set()
    )
    accounts = snap.by_dn()

    def usable(dn: str) -> bool:
        a = accounts.get(dn.lower())
        return (
            a is not None
            and a.enabled
            and not a.has(UAC.NOT_DELEGATED)
            and dn.lower() not in protected
        )

    server = any(usable(dn) for dn in snap.privileged.get("Domain Admins", []))
    rodc = server or any(
        usable(dn)
        for name in ("Administrators", "Enterprise Admins")
        for dn in snap.privileged.get(name, [])
    )
    dc = rodc or any(a.is_registered_dc and not a.is_rodc and usable(a.dn) for a in snap.accounts)
    return server, rodc, dc


def _s4u_sources(
    snap: Snapshot, groups: dict[str, DirObject], node_of: Callable[[str], str], listed: str
) -> list[str]:
    """The SIDs a resource-based edge starts from when `listed` is in the attribute: those
    that can run S4U2self as that principal.

    - an account: itself, when it is a computer or holds an SPN;
    - a group: those of its members, nested ones included;
    - Domain Computers: the group, every member is a computer;
    - Everyone, Authenticated Users: the group when the machine account quota lets any user
      create a computer, else only the enabled computers and SPN holders;
    - Domain Users: its enabled SPN holders, by membership or primary group. A computer made
      through the quota is in Domain Computers, so the quota does not help;
    - Anonymous Logon, Domain Guests: nobody, they have no such account.
    """
    by_sid = {a.sid: a for a in snap.accounts if a.sid}
    group_of = {o.sid: o for o in groups.values() if o.sid}
    runners = [a for a in snap.accounts if a.sid and a.enabled and (a.is_computer or a.spns)]
    domain_users, domain_computers = f"{snap.domain_sid}-513", f"{snap.domain_sid}-515"
    quota = snap.policy.machine_account_quota > 0
    out: dict[str, None] = {}
    seen, stack = {listed}, [listed]
    while stack:
        sid = stack.pop()
        if sid in ("S-1-5-7", f"{snap.domain_sid}-514"):
            continue
        account = by_sid.get(sid)
        if account is not None:
            if account.is_computer or account.spns:
                out[sid] = None
            continue
        if sid == domain_computers or (sid in EVERY_LOGON and quota):
            out[sid] = None
            continue
        if sid in EVERY_LOGON:
            out.update(dict.fromkeys(a.sid for a in runners))
            continue
        if sid == domain_users:
            for a in runners:
                if (a.primary_group or (515 if a.is_computer or a.managed else 513)) == 513:
                    out[a.sid] = None
        for member in group_of[sid].members if sid in group_of else ():
            node = node_of(member)
            if node.startswith("sid:") and node[4:] not in seen:
                seen.add(node[4:])
                stack.append(node[4:])
    return list(out)


def _condition_groups(
    snap: Snapshot, groups: dict[str, DirObject], resource: list[Account]
) -> set[str]:
    """Lower-cased DNs of the groups, nested ones included, whose members decide whether
    a delegation edge exists: the admins, Protected Users and listed groups."""
    roots = {"S-1-5-32-544"}
    for domain in {snap.domain_sid, snap.root_sid} - {""}:
        roots |= {f"{domain}-{rid}" for rid in (512, 519, 525)}
    roots |= {sid for a in resource for sid in a.rbcd_principals or ()}
    stack = [dn for dn, o in groups.items() if o.sid in roots]
    out = set(stack)
    while stack:
        for member in groups[stack.pop()].members:
            key = member.lower()
            if key in groups and key not in out:
                out.add(key)
                stack.append(key)
    return out


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
    nxt = _next_hops(_reverse(g), g.tier0, g.tier0)
    return {start: _walk(start, nxt) for start in nxt}


def _reverse(g: Graph) -> dict[str, list[Edge]]:
    reverse: dict[str, list[Edge]] = {}
    for src, outs in g.edges.items():
        for dst, how in outs:
            reverse.setdefault(dst, []).append((src, how))
    return reverse


def _next_hops(
    reverse: dict[str, list[Edge]], seeds: Iterable[str], stop: Iterable[str]
) -> dict[str, Edge]:
    """Breadth-first from `seeds` over the reversed edges, not entering `stop`: for every
    node reached, its next step towards the nearest seed."""
    nxt: dict[str, Edge] = {}
    seen = set(stop)
    queue = deque(sorted(seeds))
    while queue:
        node = queue.popleft()
        for src, how in reverse.get(node, []):
            if src in seen:
                continue
            seen.add(src)
            nxt[src] = (node, how)
            queue.append(src)
    return nxt


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


def exposure(snap: Snapshot, g: Graph, found: Container[str]) -> tuple[int, int]:
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


def direct_holders(
    g: Graph, found: dict[str, Path], targets: Collection[str] | None = None
) -> dict[str, Path]:
    """Principals that hold a right themselves (not only through a group), each with the
    shortest path that starts with one of their own rights, to `targets` (default: tier 0)."""
    targets = g.tier0 if targets is None else targets
    out = {}
    for node in found:
        if not node.startswith("sid:"):
            continue
        best: Path | None = None
        for dst, how in g.edges.get(node, []):
            if how == "member of":
                continue
            if dst in targets:
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
class DeclaredReach:
    """Who reaches the declared targets (Graph.declared), apart from built-in tier 0."""

    # principals outside both sets that hold a right themselves, shortest path to the nearest
    # declared target, in report order
    paths: list[Path]
    principals: dict[str, int]  # declared node -> principals with a path to it
    exposed: int  # enabled users with a path to built-in or declared tier 0
    users: int  # enabled users outside both sets


@dataclass
class Analysis:
    """What AD-PATH-001, `ad-doctor paths` and the viewer report."""

    graph: Graph
    # principals that hold a right themselves, each with its shortest path, in report
    # order: broad groups first, then by length, then by name
    paths: list[Path]
    exposed: int  # enabled non-tier-0 users with a path
    users: int  # enabled non-tier-0 users
    declared: DeclaredReach | None = None  # with a declaration; the fields above ignore it

    @property
    def broad(self) -> list[Path]:
        return [p for p in self.paths if self.graph.name(p.start) in BROAD_FIRST]

    @property
    def percent(self) -> int:
        return (100 * self.exposed // self.users) if self.users else 0


# (snapshot, graph built from it, its analysis if done): what-if lends its graph to the
# checks it runs on the snapshot as collected, so AD-PATH-001 does not build the same
# graph again; a declaration lends its graph the same way, which is how AD-PATH-001 sees it
_LENT: tuple[Snapshot, Graph, Analysis | None] | None = None


@contextmanager
def lend(snap: Snapshot, g: Graph, analysis: Analysis | None = None) -> Iterator[None]:
    """While active, analyze(snap) uses `g`, which must be built from `snap` as it is."""
    global _LENT
    _LENT = (snap, g, analysis)
    try:
        yield
    finally:
        _LENT = None


def analyze(snap: Snapshot, g: Graph | None = None) -> Analysis:
    """`g`: a graph already built from this snapshot (with provenance, say)."""
    if g is None and _LENT is not None and _LENT[0] is snap:
        if _LENT[2] is not None:
            return _LENT[2]
        g = _LENT[1]
    g = build(snap) if g is None else g
    found = paths_to_tier0(g)
    # principals that hold a right themselves; members who only inherit it through a group
    # are counted in the exposure figure instead of being listed one by one
    starts = direct_holders(g, found)
    exposed, total = exposure(snap, g, found)
    return Analysis(
        g,
        _report_order(g, starts),
        exposed,
        total,
        _declared_reach(snap, g) if g.declared else None,
    )


def _report_order(g: Graph, starts: dict[str, Path]) -> list[Path]:
    return sorted(
        starts.values(),
        key=lambda p: (g.name(p.start) not in BROAD_FIRST, len(p.steps), g.name(p.start).lower()),
    )


def _declared_reach(snap: Snapshot, g: Graph) -> DeclaredReach:
    """The paths to the declared targets, none through built-in tier 0: whoever passes
    through that is already in the built-in list. The exposure counts both sets, as what-if
    does when it treats the same nodes as tier 0."""
    targets = g.declared - g.tier0
    stop = g.tier0 | targets
    reverse = _reverse(g)
    nxt = _next_hops(reverse, targets, stop)
    starts = direct_holders(g, {s: _walk(s, nxt) for s in nxt}, targets)
    principals = {
        t: sum(n.startswith("sid:") for n in _next_hops(reverse, [t], g.tier0 | {t}))
        for t in sorted(targets)
    }
    both = replace(g, tier0=stop, declared=set())
    exposed, users = exposure(snap, both, _next_hops(reverse, stop, stop))
    return DeclaredReach(_report_order(g, starts), principals, exposed, users)


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
    d = a.declared
    if not a.paths and not (d and d.paths):
        return None
    g = a.graph
    detail = (
        f"{len(a.paths)} principals outside tier 0 can reach it; {a.exposed} of {a.users} "
        f"enabled users ({a.percent}%) have a path through their accounts or groups. "
        "Each object shows the shortest path."
    )
    if a.broad:
        detail += " Broad groups have a path, so every user is effectively tier 0."
    if d is not None:
        detail += (
            f" Declared tier 0 (not built-in): {len(d.paths)} principals can reach an asset "
            f"you declared, marked{DECLARED_MARK} on the path; {d.exposed} of {d.users} enabled "
            "users outside both sets have a path to either."
        )
    f = _finding(
        "AD-PATH-001",
        Severity.HIGH,
        detail,
        "Break each path at its first step, starting with the ones shared by most paths "
        "(`ad-doctor paths --chokepoints` ranks them; `ad-doctor blast-radius` shows one "
        "account).",
        [p.render(g) for p in (a.paths + d.paths if d else a.paths)],
    )
    # a path's identity is the principal it starts from: when the path gets longer or takes
    # another route it keeps its fingerprint and is not new in a diff
    f.keys = {p.render(g): g.ident(p.start) for p in a.paths}
    f.data = {
        "exposed": a.exposed,
        "users": a.users,
        "paths": [p.record(g) for p in a.paths],
    }
    if d is not None:
        # a start can hold a path to each set: the two are different findings
        f.keys |= {p.render(g): f"declared:{g.ident(p.start)}" for p in d.paths}
        f.data["declared_paths"] = [p.record(g) for p in d.paths]
    return f
