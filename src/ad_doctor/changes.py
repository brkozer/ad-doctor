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
from collections.abc import Iterable
from dataclasses import dataclass

from . import sd
from .checks import CA_RIGHTS, _sync_accounts
from .model import EXCHANGE_GROUPS, UAC, Snapshot
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
}
# fields that hold a DN (lower-cased in IDs) and a SID (upper-cased)
DN_FIELDS = {"object", "group", "container", "gmsa", "account"}
SID_FIELDS = {"trustee", "reader"}
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
    "gpo-entry": 2,
    "gplink": 3,
    "ca-right": 3,
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
    "owner",
    "gmsa-reader",
    "gpo-entry",
    "gplink",
    "member",
    "delegation",
)
DELEGATIONS = ("unconstrained", "protocol-transition", "rbcd")  # and "constrained:<SPN>"
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


def assess(snap: Snapshot, prim: Prim, tier0: set[str], ctx: Context | None = None) -> Assessment:
    """Class, cost and warning of one change. Fixed edges and kept changes never get here:
    the caller leaves them out."""
    ctx = ctx or Context(snap)
    kind = prim[0]
    if kind == "template-flag":
        return Assessment(
            "warn", WARN_COST, "changes what the template issues: check who enrolls in it"
        )
    trustee = ""
    if kind in ("ace", "inherited-ace", "pki-ace", "template-ace", "adminsdholder-ace"):
        trustee = prim[-1]
    elif kind in ("gmsa-reader", "ca-right"):
        trustee = prim[2]
    if trustee:
        if trustee in ctx.exchange:
            return Assessment("warn", WARN_COST, "breaks Exchange provisioning (see AD-ACL-007)")
        if trustee in (f"{snap.domain_sid}-526", f"{snap.domain_sid}-527"):
            return Assessment("warn", WARN_COST, "Key Admins manage key credentials by design")
        if trustee in (PRE2K, f"{snap.domain_sid}-517"):
            return Assessment("warn", WARN_COST, "a default grant that Windows expects")
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
    `allow warn` lifts it). Its server is then reported as not closable by removal."""
    out = {}
    domain = snap.domain_dn.lower()
    for account in _sync_accounts(snap):
        for kind in ("ace", "inherited-ace"):
            p = prov.lookup((kind, domain, account.sid))
            if p is not None:
                out[p] = "Entra Connect needs DCSync"
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
        snap.privileged = privileged_without(snap, {(p[1], p[2]) for p in members})
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
    if by_kind.get("gmsa-reader"):
        for gm in snap.gmsas:
            gm.readers = [s for s in gm.readers if not hit(("gmsa-reader", gm.dn.lower(), s))]
    for account in snap.accounts:
        for prim in by_kind.get("delegation", ()):
            if prim[1] == account.dn.lower() and _undelegate(account, prim[2]):
                gone[prov.index[prim]] += 1
    return gone


def _remove_aces(snap: Snapshot, prov: Provenance, wanted: set[int], gone: dict[int, int]) -> None:
    """ACE removal by the same attribution as the graph: SDProp copies go with the
    AdminSDHolder change, inherited copies with the container they come from."""
    sids = {prov.prims[p][-1] for p in wanted if prov.prims[p][0] in ACE_KINDS}

    def keep(dn: str, aces: list[sd.Ace]) -> list[sd.Ace]:
        out = []
        for a in aces:
            if a.sid in sids:
                p = prov.index.get(prov.ace_prim_key(dn, a))
                if p is not None and p in wanted:
                    gone[p] += 1  # ACE entries; one AD ACE can sit in two lists
                    continue
            out.append(a)
        return out

    for o in snap.objects:
        dn = o.dn.lower()
        o.aces = keep(dn, o.aces)
        o.inheritable = keep(dn, o.inheritable)
    for g in snap.gpos:  # the GPO checks and security filtering read Gpo.aces
        g.aces = keep(prov.gpo_dns[g.guid.upper()], g.aces)
    if "domain" in snap.acls:
        snap.acls["domain"] = keep(snap.domain_dn.lower(), snap.acls["domain"])
    if "AdminSDHolder" in snap.acls:
        snap.acls["AdminSDHolder"] = keep(prov.holder_dn, snap.acls["AdminSDHolder"])


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
