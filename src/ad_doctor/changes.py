"""What-if changes: the removable facts behind control-graph edges, their IDs, classes and
costs, and the mutators that take them out of a snapshot.

A change removes one snapshot fact; the edges it made go with it. `provenance.py` decides
which change made each edge, and the mutators here ask the same functions which facts a
change covers, so `paths.build(apply(snap, R))` and the masked graph agree. The mutators
work in place: the CLI runs once per snapshot, and a deep copy of a large domain costs
more than the whole analysis.

Classes: removable (proposed by `plan`), warn (proposed only when nothing of equal cost
avoids it, with a warning) and fixed (never proposed: structure, see
`provenance.FIXED_REASONS`, and edges out of tier 0). A kept change (`[[keep]]`, the Entra
sync account's DCSync by default, accepted risks, invariants) is never proposed either.
"""

from __future__ import annotations

import hashlib
from collections.abc import Iterable, Mapping
from dataclasses import dataclass, field

from . import sd
from .checks import CA_RIGHTS, _sync_accounts, _sync_servers
from .model import EXCHANGE_GROUPS, UAC, GpLink, GpoLocalGroup, Snapshot
from .provenance import TEMPLATE_FLAGS, Prim, Provenance

# Identity fields of each kind, in the order of the primitive tuple after the kind.
FIELDS = {
    "ace": ("object", "trustee"),
    "inherited-ace": ("object", "trustee"),
    "adminsdholder-ace": ("trustee",),
    "owner": ("object",),
    "member": ("group", "member"),
    "gplink": ("gpo", "container"),
    "gpo-entry": ("gpo", "group", "member"),
    "template-ace": ("template", "trustee"),
    "template-flag": ("template", "flag"),
    "pki-ace": ("object", "trustee"),
    "ca-right": ("ca", "trustee", "right"),
    "gmsa-reader": ("gmsa", "reader"),
    "delegation": ("account", "what"),
    "rbcd-principal": ("computer", "principal"),
    "sid-history": ("account", "sid"),
    "oid-link": ("oid", "group"),
    "ca-flag": ("ca", "flag"),
    "script-ace": ("path", "trustee"),
    "script-host": ("gpo", "path"),
}
# fields that hold a DN (lower-cased in IDs) and a SID (upper-cased)
DN_FIELDS = {"object", "group", "container", "gmsa", "account", "computer"}
SID_FIELDS = {"trustee", "reader", "principal", "sid"}
COST = {
    "ace": 1,
    "inherited-ace": 1,
    "adminsdholder-ace": 1,
    "owner": 1,
    "member": 1,
    "template-ace": 1,
    "pki-ace": 1,
    "gmsa-reader": 1,
    "delegation": 1,
    "rbcd-principal": 1,
    "sid-history": 1,
    "gpo-entry": 2,
    "gplink": 3,
    "ca-right": 3,
    "oid-link": 3,
    "ca-flag": 3,
    "script-ace": 1,
    "script-host": 3,
}
TIER0_MEMBER_COST = 5  # taking a member out of a tier-0 group
WARN_COST = 10
# order of kinds when everything else ties (spec 2.2)
KIND_ORDER = (
    "ace",
    "inherited-ace",
    "adminsdholder-ace",
    "template-ace",
    "template-flag",
    "pki-ace",
    "ca-right",
    "oid-link",
    "ca-flag",
    "owner",
    "gmsa-reader",
    "gpo-entry",
    "gplink",
    "member",
    "delegation",
    "rbcd-principal",
    "sid-history",
    "script-ace",
    "script-host",
)
DELEGATIONS = ("unconstrained", "protocol-transition", "rbcd")  # and "constrained:<SPN>"
CA_FLAG_TEXT = {
    "san-from-request": "take no SAN from request attributes (EDITF_ATTRIBUTESUBJECTALTNAME2)",
    "no-sid-extension": "put the SID security extension back into certificates",
}
PRE2K = "S-1-5-32-554"


def change_id(prim: Prim) -> str:
    """`c:` + 12 hex of SHA-256 over kind and identity fields, DNs lower-cased and SIDs
    upper-cased (the convention of report.fingerprint). Stable while the fact exists."""
    kind, *values = prim
    parts = [kind]
    for name, value in zip(FIELDS[kind], values, strict=True):
        if name in DN_FIELDS:
            value = value.lower()
        elif name in SID_FIELDS or (kind == "gpo-entry" and name != "gpo"):
            value = value.upper()
        parts.append(value)
    return "c:" + hashlib.sha256("|".join(parts).encode()).hexdigest()[:12]


def fields(prim: Prim) -> dict[str, str]:
    kind, *values = prim
    return {"kind": kind, **dict(zip(FIELDS[kind], values, strict=True))}


def prim_of(values: Mapping[str, object]) -> Prim:
    """The primitive tuple from a kind and its identity fields (a plan file entry)."""
    kind = str(values.get("kind", ""))
    if kind not in FIELDS:
        raise ValueError(f"unknown change kind {kind!r}")
    missing = [n for n in FIELDS[kind] if not isinstance(values.get(n), str)]
    if missing:
        raise ValueError(f"a {kind} change needs {', '.join(missing)}")
    return (kind, *(str(values[n]) for n in FIELDS[kind]))


class Where:
    """DN (lower case) -> the DN as written, a display name and the ACE lists of an object,
    a GPO, the domain head or AdminSDHolder: what fix lines and resolution need."""

    def __init__(self, snap: Snapshot, prov: Provenance) -> None:
        self.dn: dict[str, str] = {}
        self.name: dict[str, str] = {}
        self.kind: dict[str, str] = {}
        self.lists: dict[str, list[list[sd.Ace]]] = {}
        self.objects: dict[str, object] = {}
        self.sid_name: dict[str, str] = dict(snap.principals)
        for a in snap.accounts:
            if a.sid:
                self.sid_name.setdefault(a.sid, a.sam)
        for o in snap.objects:
            if o.sid:
                self.sid_name.setdefault(o.sid, o.name)
        for o in snap.objects:
            key = o.dn.lower()
            self.dn.setdefault(key, o.dn)
            self.name.setdefault(key, o.name)
            self.kind.setdefault(key, o.kind)
            self.lists.setdefault(key, []).extend([o.aces, o.inheritable])
            self.objects.setdefault(key, o)
        for a in snap.accounts:
            key = a.dn.lower()
            self.dn.setdefault(key, a.dn)
            self.name.setdefault(key, a.sam)
            self.kind.setdefault(key, "computer" if a.is_computer else "user")
        for gm in snap.gmsas:
            key = gm.dn.lower()
            self.dn.setdefault(key, gm.dn)
            self.name.setdefault(key, gm.name)
            self.kind.setdefault(key, "gmsa")
        for g in snap.gpos:
            key = prov.gpo_dns[g.guid.upper()]
            self.dn[key] = f"CN={g.guid},CN=Policies,CN=System,{snap.domain_dn}"
            self.name[key] = g.name
            self.kind[key] = "gpo"
            self.lists.setdefault(key, []).append(g.aces)
        domain = snap.domain_dn.lower()
        self.dn.setdefault(domain, snap.domain_dn)
        self.name[domain] = snap.domain
        self.kind.setdefault(domain, "domain")
        if "domain" in snap.acls:
            self.lists.setdefault(domain, []).append(snap.acls["domain"])
        holder = prov.holder_dn
        self.dn.setdefault(holder, f"CN=AdminSDHolder,CN=System,{snap.domain_dn}")
        self.name.setdefault(holder, "AdminSDHolder")
        self.kind.setdefault(holder, "container")
        if "AdminSDHolder" in snap.acls and holder not in self.lists:
            self.lists[holder] = [snap.acls["AdminSDHolder"]]

    def aces(self, dn: str) -> list[sd.Ace]:
        """Every ACE entry of the object (both lists; an AD ACE can sit in two)."""
        return [a for aces in self.lists.get(dn, []) for a in aces]

    def who(self, snap: Snapshot, sid: str) -> str:
        """A principal's name: the snapshot's, else a well-known one, else the SID."""
        return self.sid_name.get(sid) or snap.name_of(sid)

    def display(self, dn: str) -> str:
        return self.name.get(dn) or dn.split(",", 1)[0].split("=", 1)[-1]


def describe(snap: Snapshot, prim: Prim, where: Where | None = None) -> str:
    """A short description of a change for people."""
    f = fields(prim)
    kind = f["kind"]

    def obj(field_name: str) -> str:
        dn = f[field_name]
        if where is not None:
            return where.display(dn)
        return dn.split(",", 1)[0].split("=", 1)[-1]

    def who(field_name: str) -> str:
        if where is not None:
            return where.who(snap, f[field_name])
        return snap.name_of(f[field_name])

    if kind in ("ace", "inherited-ace"):
        what = "inheritable ACEs" if kind == "inherited-ace" else "ACEs"
        return f"remove the {what} of {who('trustee')} on {obj('object')}"
    if kind == "adminsdholder-ace":
        return f"remove the ACEs of {who('trustee')} on AdminSDHolder"
    if kind == "owner":
        return f"give {obj('object')} a tier-0 owner"
    if kind == "member":
        return f"remove {obj('member')} from {obj('group')}"
    gpo = {g.guid.upper(): g.name for g in snap.gpos}.get(f.get("gpo", ""), f.get("gpo", ""))
    if kind == "gplink":
        return f"unlink GPO {gpo} from {obj('container')}"
    if kind == "gpo-entry":
        return f"remove {who('member')} from {who('group')} in GPO {gpo}"
    if kind == "template-ace":
        return f"remove the ACEs of {who('trustee')} on template {f['template']}"
    if kind == "template-flag":
        return f"template {f['template']}: turn off {f['flag']}"
    if kind == "pki-ace":
        return f"remove the ACEs of {who('trustee')} on {f['object'].removeprefix('PKI:')}"
    if kind == "ca-right":
        return f"remove {f['right']} of {who('trustee')} on CA {f['ca']}"
    if kind == "gmsa-reader":
        return f"remove {who('reader')} from the password readers of {obj('gmsa')}"
    if kind == "rbcd-principal":
        return f"stop {who('principal')} delegating to {obj('computer')}"
    if kind == "sid-history":
        return f"remove {who('sid')} from the SID history of {obj('account')}"
    if kind == "oid-link":
        return f"unlink issuance policy {f['oid']} from {obj('group')}"
    if kind == "ca-flag":
        return f"CA {f['ca']}: {CA_FLAG_TEXT.get(f['flag'], f['flag'])}"
    if kind == "script-ace":
        return f"remove the write rights of {who('trustee')} on SYSVOL path {f['path']}"
    if kind == "script-host":
        return f"stop GPO {gpo} running {f['path']} from its host"
    return f"remove {f['what']} delegation of {obj('account')}"


@dataclass
class Facts:
    """What fix and rollback lines need to know about one change, from the snapshot as
    it was before any change."""

    prim: Prim
    label: str
    dn: str = ""  # the object, group, container, gMSA or account, as written
    aces: list[sd.Ace] = field(default_factory=list)  # the ACEs it removes there
    copies: int = 0  # other objects holding a copy (SDProp, inherited)
    member_dn: str = ""
    owner: str = ""  # the current owner SID
    readers: list[str] = field(default_factory=list)  # the list once the change set is done
    listed: list[str] = field(default_factory=list)  # the list as it was: what rollback writes
    gpo_name: str = ""
    entry: GpoLocalGroup | None = None
    link: GpLink | None = None
    inheritance_known: bool = True
    orphan: bool = False  # an AdminSDHolder copy SDProp no longer rewrites


def facts(snap: Snapshot, prov: Provenance, where: Where, prims: Iterable[int]) -> dict[int, Facts]:
    """Facts of the changes, with one pass over the snapshot's ACEs for the copies."""
    wanted = list(dict.fromkeys(prims))
    out = {p: Facts(prov.prims[p], describe(snap, prov.prims[p], where)) for p in wanted}
    sids = {prov.prims[p][-1] for p in wanted if prov.prims[p][0] in ACE_KINDS}
    by_key = {prov.prims[p]: p for p in wanted}
    holders: dict[int, set[str]] = {}
    # the fix lines write a whole list, so each one leaves out every principal of the set
    leaving: dict[tuple[str, str], set[str]] = {}
    for key in by_key:
        if key[0] in ("gmsa-reader", "rbcd-principal"):
            leaving.setdefault((key[0], key[1]), set()).add(key[2])
    cleared = {key[1] for key in by_key if key[0] == "delegation" and key[2] == "rbcd"}
    if sids:
        for dn, lists in where.lists.items():
            kind = where.kind.get(dn)
            for aces in lists:
                for a in aces:
                    if a.sid not in sids:
                        continue
                    for key in prov.ace_prim_keys(dn, a, kind):
                        p = by_key.get(key)
                        if p is not None:
                            holders.setdefault(p, set()).add(dn)
    gpos = {g.guid.upper(): g for g in snap.gpos}
    for p, f in out.items():
        kind, *_ = f.prim
        f.inheritance_known = snap.ace_inheritance_checked
        if kind in ACE_KINDS:
            anchor = prov.holder_dn if kind == "adminsdholder-ace" else f.prim[1]
            f.dn = where.dn.get(anchor, anchor)
            f.aces = _unique(
                a
                for a in where.aces(anchor)
                if a.sid == f.prim[-1]
                and not a.inherited
                and f.prim in prov.ace_prim_keys(anchor, a, where.kind.get(anchor))
            )
            f.copies = len(holders.get(p, set()) - {anchor})
            f.orphan = kind == "ace" and prov.orphan_copy(anchor, f.prim[-1], f.aces)
        elif kind == "owner":
            f.dn = where.dn.get(f.prim[1], f.prim[1])
            o = where.objects.get(f.prim[1])
            f.owner = str(getattr(o, "owner", "") or "")
        elif kind == "member":
            f.dn = where.dn.get(f.prim[1], f.prim[1])
            f.member_dn = where.dn.get(f.prim[2], f.prim[2])
        elif kind in ("gplink", "gpo-entry"):
            g = gpos.get(f.prim[1])
            f.gpo_name = g.name if g else f.prim[1]
            if kind == "gplink":
                f.dn = where.dn.get(f.prim[2], f.prim[2])
                f.link = next(
                    (x for x in (g.links if g else []) if x.container.lower() == f.prim[2]), None
                )
            else:
                f.entry = next(
                    (
                        x
                        for x in snap.gpo_local_groups
                        if x.gpo.upper() == f.prim[1]
                        and x.group_sid.upper() == f.prim[2]
                        and x.member_sid.upper() == f.prim[3]
                    ),
                    None,
                )
        elif kind == "template-ace":
            t = next((t for t in snap.templates if t.name == f.prim[1]), None)
            f.aces = _unique(a for a in (t.aces if t else []) if a.sid == f.prim[2])
        elif kind == "pki-ace":
            f.aces = _unique(a for a in snap.acls.get(f.prim[1], []) if a.sid == f.prim[2])
        elif kind == "gmsa-reader":
            gm = next((x for x in snap.gmsas if x.dn.lower() == f.prim[1]), None)
            f.dn = gm.dn if gm else f.prim[1]
            f.listed = list(gm.readers) if gm else []
            f.readers = [s for s in f.listed if s not in leaving[(kind, f.prim[1])]]
        elif kind == "oid-link":
            f.dn = snap.oid_group_links.get(f.prim[1], f.prim[2])
        elif kind in ("delegation", "rbcd-principal", "sid-history"):
            f.dn = where.dn.get(f.prim[1], f.prim[1])
            if kind == "rbcd-principal" or f.prim[2] == "rbcd":
                held = next((x for x in snap.accounts if x.dn.lower() == f.prim[1]), None)
                listed = (held.rbcd_principals if held else None) or []
                f.listed = list(listed)
                f.readers = list(listed)  # delegation:rbcd removes the attribute, not a principal
                if kind == "rbcd-principal":
                    going = leaving[(kind, f.prim[1])]
                    f.readers = (
                        [] if f.prim[1] in cleared else [s for s in listed if s not in going]
                    )
    return out


def _unique(aces: Iterable[sd.Ace]) -> list[sd.Ace]:
    """One entry per (mask, object type): the same AD ACE can sit in two lists."""
    out: dict[tuple[int, str | None], sd.Ace] = {}
    for a in aces:
        out.setdefault((a.mask, a.object_type), a)
    return list(out.values())


def trustee_of(prim: Prim) -> str:
    """The SID holding the right a change removes ("" for kinds without one)."""
    kind = prim[0]
    if kind in ("ace", "inherited-ace", "pki-ace", "template-ace", "adminsdholder-ace"):
        return prim[-1]
    if kind == "script-ace":
        return prim[2]
    if kind in ("gmsa-reader", "rbcd-principal"):
        return prim[2]
    if kind == "ca-right":
        return prim[2]
    if kind == "gpo-entry":
        return prim[3]
    return ""


@dataclass(frozen=True)
class Assessment:
    cls: str  # "removable" or "warn"
    cost: int
    warning: str = ""


class Context:
    """Lookups `assess` needs, built once per snapshot."""

    def __init__(self, snap: Snapshot) -> None:
        self.group_node = {
            o.dn.lower(): (f"sid:{o.sid}" if o.sid else f"dn:{o.dn.lower()}")
            for o in snap.objects
            if o.kind == "group"
        }
        self.rid_500 = {a.dn.lower() for a in snap.accounts if a.rid == 500}
        self.exchange = {
            sid for sid, name in snap.principals.items() if name.lower() in EXCHANGE_GROUPS
        } | {o.sid for o in snap.objects if o.sid and o.name.lower() in EXCHANGE_GROUPS}
        self.domain = snap.domain_dn.lower()
        # accounts that look like the Entra Connect sync account, with no sync server
        self.sync_unverified = {
            a.sid for a in _sync_accounts(snap) if a.sid and not _sync_servers(snap, a)
        }


def assess(snap: Snapshot, prim: Prim, tier0: set[str], ctx: Context | None = None) -> Assessment:
    """Class, cost and warning of one change. Fixed edges and kept changes never get here:
    the caller leaves them out."""
    ctx = ctx or Context(snap)
    kind = prim[0]
    if kind == "template-flag":
        return Assessment(
            "warn", WARN_COST, "changes what the template issues: check who enrolls in it"
        )
    trustee = "" if kind == "gpo-entry" else trustee_of(prim)
    if trustee:
        if trustee in ctx.exchange:
            return Assessment("warn", WARN_COST, "breaks Exchange provisioning (see AD-ACL-007)")
        if trustee in (f"{snap.domain_sid}-526", f"{snap.domain_sid}-527"):
            return Assessment("warn", WARN_COST, "Key Admins manage key credentials by design")
        if trustee in (PRE2K, f"{snap.domain_sid}-517"):
            return Assessment("warn", WARN_COST, "a default grant that Windows expects")
    if (
        trustee in ctx.sync_unverified
        and kind in ("ace", "inherited-ace")
        and prim[1] == ctx.domain
    ):
        return Assessment(
            "warn",
            WARN_COST,
            "named like the Entra Connect sync account, but no sync server was found: "
            "check whether sync needs it or someone planted it",
        )
    if kind == "sid-history" and not prim[2].startswith(
        tuple(f"{d}-" for d in (snap.domain_sid, snap.root_sid) if d)
    ):
        return Assessment(
            "warn", WARN_COST, "resources still granted to the old SID lose access: re-ACL first"
        )
    if kind == "member":
        group_node = ctx.group_node.get(prim[1], f"dn:{prim[1]}")
        if group_node in tier0:
            if prim[2] in ctx.rid_500:
                return Assessment(
                    "warn", WARN_COST, "takes the built-in Administrator out of a tier-0 group"
                )
            return Assessment("removable", TIER0_MEMBER_COST)
    return Assessment("removable", COST[kind])


def default_keeps(snap: Snapshot, prov: Provenance) -> dict[int, str]:
    """Changes never proposed unless asked: the Entra sync account's DCSync (decision D4;
    `allow warn` lifts it). Its server is then reported as not closable by removal. The
    account is found by name and description, so it is kept only when its sync server is
    in the domain too; else its DCSync is a warn-class change like any other."""
    out = {}
    domain = snap.domain_dn.lower()
    for account in _sync_accounts(snap):
        servers = _sync_servers(snap, account)
        if not servers:
            continue
        server = servers[0].sam
        for kind in ("ace", "inherited-ace"):
            p = prov.lookup((kind, domain, account.sid))
            if p is not None:
                out[p] = (
                    f"kept by default: looks like the Entra Connect sync account of {server}, "
                    "which needs DCSync"
                )
    return out


def invariant_keeps(snap: Snapshot, prov: Provenance, spec: dict[str, object]) -> dict[int, str]:
    """`[dcsync] allowed` and the declared members of `[groups]` from an invariants file:
    the declared state is kept."""
    out: dict[int, str] = {}
    domain = snap.domain_dn.lower()
    by_name = {a.sam.lower(): a for a in snap.accounts}
    dcsync = spec.get("dcsync")
    if isinstance(dcsync, dict):
        for name in dcsync.get("allowed", []):
            sids = [a.sid for a in snap.accounts if a.sam.lower() == str(name).lower()]
            sids += [s for s, n in snap.principals.items() if n.lower() == str(name).lower()]
            for sid in sids:
                for kind in ("ace", "inherited-ace"):
                    p = prov.lookup((kind, domain, sid))
                    if p is not None:
                        out[p] = "allowed to replicate in the invariants file"
    groups = spec.get("groups")
    if isinstance(groups, dict):
        objects = {o.name.lower(): o for o in snap.objects if o.kind == "group"}
        for group, members in groups.items():
            g = objects.get(str(group).lower())
            if g is None:
                continue
            for name in members:
                a = by_name.get(str(name).lower())
                if a is not None:
                    p = prov.lookup(("member", g.dn.lower(), a.dn.lower()))
                    if p is not None:
                        out[p] = f"declared member of {g.name} in the invariants file"
    return out


# -- mutators ---------------------------------------------------------------------------

ACE_KINDS = {"ace", "inherited-ace", "adminsdholder-ace"}


def apply(snap: Snapshot, prov: Provenance, removed: Iterable[int]) -> dict[int, int]:
    """Take the changes out of the snapshot, in place. Returns, per change, how many
    facts went (0: absent in this snapshot). `prov` must come from a graph built on this
    snapshot before any change."""
    wanted = set(removed)
    gone = dict.fromkeys(wanted, 0)
    by_kind: dict[str, set[Prim]] = {}
    for p in wanted:
        by_kind.setdefault(prov.prims[p][0], set()).add(prov.prims[p])

    def hit(key: Prim) -> bool:
        p = prov.index.get(key)
        if p is not None and p in wanted:
            gone[p] += 1
            return True
        return False

    if ACE_KINDS & by_kind.keys():
        _remove_aces(snap, prov, wanted, gone)
    members = by_kind.get("member", set())
    if members:
        pairs = {(p[1], p[2]) for p in members}
        snap.privileged = privileged_without(snap, pairs)
        snap.protected_users = protected_without(snap, pairs)
        for o in snap.objects:
            if o.kind == "group" and any(p[1] == o.dn.lower() for p in members):
                o.members = [m for m in o.members if not hit(("member", o.dn.lower(), m.lower()))]
    for o in snap.objects:
        if o.owner and ("owner", o.dn.lower()) in by_kind.get("owner", ()):
            hit(("owner", o.dn.lower()))
            o.owner = None  # back to a tier-0 owner; which one is the operator's choice
    links = by_kind.get("gplink", set())
    for g in snap.gpos:
        guid = g.guid.upper()
        dropped = {
            x.container.lower() for x in g.links if hit(("gplink", guid, x.container.lower()))
        }
        if dropped:
            g.links = [x for x in g.links if x.container.lower() not in dropped]
            where = {"domain": snap.domain_dn.lower()}
            where["Domain Controllers OU"] = f"ou=domain controllers,{snap.domain_dn.lower()}"
            g.linked_to = [w for w in g.linked_to if where.get(w) not in dropped]
        elif links and not g.links:  # older snapshots: linked_to only
            kept = []
            for w in g.linked_to:
                container = prov.dc_link_container(w)
                if not hit(("gplink", guid, container)):
                    kept.append(w)
            g.linked_to = kept
    if by_kind.get("gpo-entry"):
        snap.gpo_local_groups = [
            x
            for x in snap.gpo_local_groups
            if not (
                x.member_sid
                and hit(("gpo-entry", x.gpo.upper(), x.group_sid.upper(), x.member_sid.upper()))
            )
        ]
    for t in snap.templates:
        if by_kind.get("template-ace"):
            t.aces = [a for a in t.aces if not hit(("template-ace", t.name, a.sid))]
        for flag in TEMPLATE_FLAGS:
            wanted_flag = ("template-flag", t.name, flag) in by_kind.get("template-flag", ())
            if wanted_flag and _set_flag(t, flag):
                hit(("template-flag", t.name, flag))
    if by_kind.get("pki-ace"):
        for key, aces in snap.acls.items():
            if key.startswith("PKI:"):
                snap.acls[key] = [a for a in aces if not hit(("pki-ace", key, a.sid))]
    for c in snap.probes.ca_configs:
        rights = [p for p in by_kind.get("ca-right", ()) if p[1] == c.name]
        for _, _, sid, right in rights:
            p = prov.index[("ca-right", c.name, sid, right)]
            if right == "ManageCA" and c.owner == sid:
                c.owner = None
                gone[p] += 1
            bit = next(b for b, r in CA_RIGHTS if r == right)
            left: list[sd.Ace] = []
            for ace in c.aces:
                if ace.sid == sid and ace.mask & bit:
                    gone[p] += 1
                    if ace.mask & ~bit:
                        left.append(sd.Ace(ace.sid, ace.mask & ~bit, ace.object_type))
                else:
                    left.append(ace)
            c.aces = left

    def hit_flag(ca: str, which: str) -> bool:
        flag = "san-from-request" if which == "san" else "no-sid-extension"
        return ("ca-flag", ca, flag) in by_kind.get("ca-flag", ()) and hit(("ca-flag", ca, flag))

    if by_kind.get("oid-link"):
        snap.oid_group_links = {
            oid: group
            for oid, group in snap.oid_group_links.items()
            if not hit(("oid-link", oid, group.lower()))
        }
    if by_kind.get("ca-flag"):
        for c in snap.probes.ca_configs:
            bit = sd.EDITF_ATTRIBUTESUBJECTALTNAME2
            if c.edit_flags is not None and c.edit_flags & bit and hit_flag(c.name, "san"):
                c.edit_flags &= ~bit
            ext = sd.SZOID_NTDS_CA_SECURITY_EXT
            listed = c.disabled_extensions or []
            if any(e.strip() == ext for e in listed) and hit_flag(c.name, "no-sid"):
                c.disabled_extensions = [e for e in listed if e.strip() != ext]
    if by_kind.get("gmsa-reader"):
        for gm in snap.gmsas:
            gm.readers = [s for s in gm.readers if not hit(("gmsa-reader", gm.dn.lower(), s))]
    for account in snap.accounts:
        for prim in by_kind.get("delegation", ()):
            if prim[1] == account.dn.lower() and _undelegate(account, prim[2]):
                gone[prov.index[prim]] += 1
    if by_kind.get("rbcd-principal") or by_kind.get("sid-history"):
        key = ""

        def stays(kind: str, value: str) -> bool:
            return not hit((kind, key, value))

        for account in snap.accounts:
            key = account.dn.lower()
            if account.sid_history:
                account.sid_history = [s for s in account.sid_history if stays("sid-history", s)]
            if account.rbcd_principals:
                kept = [s for s in account.rbcd_principals if stays("rbcd-principal", s)]
                account.rbcd_principals = kept
                account.rbcd = bool(kept)  # an empty list clears the attribute
    if by_kind.get("script-ace"):
        for acl in snap.sysvol_acls:
            at = acl.path.lower()
            acl.aces = [a for a in acl.aces if not hit(("script-ace", at, a.sid))]
            if acl.owner and hit(("script-ace", at, acl.owner)):
                acl.owner = None  # back to a tier-0 owner; which one is the operator's choice
    if by_kind.get("script-host"):
        for x in snap.gpo_scripts:
            if x.location == "host" and hit(("script-host", x.gpo.upper(), x.path.lower())):
                x.location = "moved"  # the GPO still runs a script, from somewhere else
    return gone


def _remove_aces(snap: Snapshot, prov: Provenance, wanted: set[int], gone: dict[int, int]) -> None:
    """ACE removal by the same attribution as the graph: SDProp copies go with the
    AdminSDHolder change, inherited copies with the container they come from."""
    sids = {prov.prims[p][-1] for p in wanted if prov.prims[p][0] in ACE_KINDS}

    def keep(dn: str, aces: list[sd.Ace], kind: str) -> list[sd.Ace]:
        out = []
        for a in aces:
            if a.sid in sids:
                # an inherited copy with several possible sources goes when all of them do
                ps = [prov.index.get(k) for k in prov.ace_prim_keys(dn, a, kind)]
                if all(p is not None and p in wanted for p in ps):
                    for p in ps:
                        assert p is not None
                        gone[p] += 1  # ACE entries; one AD ACE can sit in two lists
                    continue
            out.append(a)
        return out

    for o in snap.objects:
        dn = o.dn.lower()
        o.aces = keep(dn, o.aces, o.kind)
        o.inheritable = keep(dn, o.inheritable, o.kind)
    for g in snap.gpos:  # the GPO checks and security filtering read Gpo.aces
        g.aces = keep(prov.gpo_dns[g.guid.upper()], g.aces, "gpo")
    if "domain" in snap.acls:
        snap.acls["domain"] = keep(snap.domain_dn.lower(), snap.acls["domain"], "domain")
    if "AdminSDHolder" in snap.acls:
        snap.acls["AdminSDHolder"] = keep(prov.holder_dn, snap.acls["AdminSDHolder"], "container")


def _set_flag(t: object, flag: str) -> bool:
    from .checks import EKU_ANY, EKU_REQUEST_AGENT
    from .model import CertTemplate
    from .provenance import flag_active, template_facts

    assert isinstance(t, CertTemplate)
    if not flag_active(template_facts(t), flag):
        return False
    if flag == "require-approval":
        t.manager_approval = True
    elif flag == "enrollee-supplies-subject":
        t.enrollee_supplies_subject = False
    else:
        eku = EKU_ANY if flag == "any-purpose-eku" else EKU_REQUEST_AGENT
        t.ekus = [e for e in t.ekus if e != eku]
    return True


def _undelegate(a: object, what: str) -> bool:
    from .model import Account

    assert isinstance(a, Account)
    if what == "unconstrained" and a.has(UAC.TRUSTED_FOR_DELEGATION):
        a.uac &= ~UAC.TRUSTED_FOR_DELEGATION
        return True
    if what == "protocol-transition" and a.has(UAC.TRUSTED_TO_AUTH_FOR_DELEGATION):
        a.uac &= ~UAC.TRUSTED_TO_AUTH_FOR_DELEGATION
        return True
    if what == "rbcd" and a.rbcd:
        a.rbcd = False
        if a.rbcd_principals is not None:
            a.rbcd_principals = []
        return True
    if what.startswith("constrained:"):
        spn = what.removeprefix("constrained:").lower()
        kept = [s for s in a.allowed_to_delegate_to if s.lower() != spn]
        if len(kept) != len(a.allowed_to_delegate_to):
            a.allowed_to_delegate_to = kept
            return True
    return False


# Groups whose transitive members the collector lists in Snapshot.privileged
PRIVILEGED_RIDS = {"Domain Admins": 512, "Schema Admins": 518, "Enterprise Admins": 519}
PRIVILEGED_BUILTIN = {
    "Administrators": "S-1-5-32-544",
    "Account Operators": "S-1-5-32-548",
    "Server Operators": "S-1-5-32-549",
    "Print Operators": "S-1-5-32-550",
    "Backup Operators": "S-1-5-32-551",
}


def protected_without(snap: Snapshot, pairs: set[tuple[str, str]]) -> list[str]:
    """Snapshot.protected_users as it would be without these memberships."""
    groups = {o.dn.lower(): o for o in snap.objects if o.kind == "group"}
    root = next((k for k, o in groups.items() if o.sid == f"{snap.domain_sid}-525"), None)
    if root is None:
        return snap.protected_users

    def closure(skip: bool) -> set[str]:
        out: set[str] = set()
        seen, stack = {root}, [root]
        while stack:
            group = stack.pop()
            for m in groups[group].members:
                key = m.lower()
                if skip and (group, key) in pairs:
                    continue
                if key not in groups:
                    out.add(key)
                elif key not in seen:
                    seen.add(key)
                    stack.append(key)
        return out

    dropped = closure(False) - closure(True)
    return [d for d in snap.protected_users if d.lower() not in dropped]


def privileged_without(snap: Snapshot, pairs: set[tuple[str, str]]) -> dict[str, list[str]]:
    """Snapshot.privileged as it would be without these (group DN, member DN) memberships
    (lower case). A member leaves a list only when the snapshot showed how it got there
    and no other chain remains; primaryGroupID members stay (the collector adds them)."""
    if not pairs:
        return snap.privileged
    groups = {o.dn.lower(): o for o in snap.objects if o.kind == "group"}
    by_sid = {o.sid: o.dn.lower() for o in groups.values() if o.sid}

    def closure(root: str, skip: bool) -> set[str]:
        out: set[str] = set()
        seen, stack = {root}, [root]
        while stack:
            group = stack.pop()
            for m in groups[group].members:
                key = m.lower()
                if skip and (group, key) in pairs:
                    continue
                if key in groups:
                    if key not in seen:
                        seen.add(key)
                        stack.append(key)
                else:
                    out.add(key)
        return out

    out = {}
    for name, dns in snap.privileged.items():
        sid = PRIVILEGED_BUILTIN.get(name)
        if name in PRIVILEGED_RIDS:
            sid = f"{snap.domain_sid}-{PRIVILEGED_RIDS[name]}"
        root = by_sid.get(sid or "")
        if root is None:
            out[name] = dns
            continue
        dropped = closure(root, False) - closure(root, True)
        if not dropped:
            out[name] = dns
            continue
        rids = {PRIVILEGED_RIDS[name]} if name in PRIVILEGED_RIDS else set()
        if name == "Administrators":
            rids = set(PRIVILEGED_RIDS.values())
        hidden = {
            a.dn.lower() for a in snap.accounts if not a.is_computer and a.primary_group in rids
        }
        out[name] = [d for d in dns if d.lower() not in dropped or d.lower() in hidden]
    return out
