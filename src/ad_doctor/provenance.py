"""Edge provenance for what-if: the removable snapshot fact behind each control-graph edge.

`paths.build(snap, provenance=True)` asks a `Provenance` for the reason of every edge as it
adds it and keeps the answer in arrays parallel to `Graph.edges`. A reason is a primitive
(one fact an administrator can remove: the ACEs of one trustee on one object, one
membership, one GPO link, ...) or a fixed reason (structure that no removal changes).

The rules where the snapshot and AD differ are applied here, at the edge, and the
mutators in `changes.py` ask the same functions which facts a primitive covers, so the
graph and the changed snapshot agree by construction:

- SDProp: an ACE of trustee T on an object SDProp rewrites that equals an ACE of T on
  AdminSDHolder (mask and object type) belongs to `adminsdholder-ace(T)`: SDProp puts the
  copy back within the hour until the AdminSDHolder ACE goes. SDProp rewrites the
  protected groups, their members (nested and by primary group), Administrator and
  krbtgt. adminCount or a protected DACL alone is not enough: an account taken out of the
  groups keeps both, and SDProp leaves it alone, so the copy there is a change of its own.
- Inheritance: with the INHERITED_ACE flag kept (`Snapshot.ace_inheritance_checked`), an
  inherited copy belongs to the container above whose explicit inheritable ACE it copies:
  same trustee, object type and rights, for the child's class. When more than one
  container could be the source, the copy stays until all of them change (the edge holds
  one option per candidate). Older snapshots cannot tell, so a copy is a change of its
  own there: a plan can be too large, never too small.
- One AD ACE, two lists: a container's ACEs of one trustee in `aces` and `inheritable` are
  one primitive (`inherited-ace` when the trustee has an inheritable ACE there).

Duplicate edges keep one primitive each; an edge stays while any of them does.
"""

from __future__ import annotations

import itertools
from array import array
from collections.abc import Callable, Iterable
from dataclasses import dataclass, replace
from typing import TYPE_CHECKING

from . import gpo_scope, sd
from .model import CertTemplate, DirObject, Snapshot

CLASS_OF_KIND = {
    "user": sd.USER_CLASS,
    "computer": sd.COMPUTER_CLASS,
    "group": sd.GROUP_CLASS,
    "ou": sd.OU_CLASS,
}

if TYPE_CHECKING:
    from .gpo_scope import Grant

Prim = tuple[str, ...]

# why a fixed edge is fixed; stored as -1 - index in the parallel arrays
FIXED_REASONS = (
    "contains",  # an OU or container holds the object: ACL inheritance, not a right
    "gpo-scope",  # GPO scope plumbing (inherited by, reaches)
    "sync-host",  # a sync server holds its sync account's password
    "filter-node",  # out of a GPO with its filter changed: the right into it is the cut
    "default-gpo-link",  # links of the two default domain policies
    "builtin-nesting",  # nesting AD enforces (Domain/Enterprise Admins in Administrators)
)
FIXED = {reason: -1 - i for i, reason in enumerate(FIXED_REASONS)}

# the default domain and domain controllers policies: their links are not a change
DEFAULT_GPOS = {"{31B2F340-016D-11D2-945F-00C04FB984F9}", "{6AC1786C-016F-11D2-945F-00C04FB984F9}"}
# objects SDProp rewrites from AdminSDHolder: these groups (domain RIDs, BUILTIN), their
# members, Administrator and krbtgt
SDPROP_RIDS = {"512", "516", "518", "519", "521", "526", "527"}
SDPROP_PRIMARY = {512, 516, 518, 519, 521}  # members by primaryGroupID
SDPROP_BUILTIN = {
    "S-1-5-32-544",
    "S-1-5-32-548",
    "S-1-5-32-549",
    "S-1-5-32-550",
    "S-1-5-32-551",
    "S-1-5-32-552",
}
TEMPLATE_FLAGS = (
    "require-approval",
    "enrollee-supplies-subject",
    "any-purpose-eku",
    "request-agent-eku",
)
# template flags that can take the authentication condition of ESC6 and ESC13 away
AUTH_FLAGS = ("require-approval", "any-purpose-eku")
CA_FLAGS = ("san-from-request", "no-sid-extension")


def fixed_reason(why: int) -> str:
    return FIXED_REASONS[-1 - why]


@dataclass(frozen=True)
class Options:
    """An edge instance that stays while any of its primitives does, labelled by the first
    one still there (a GPO owner who also holds a DACL right: "owns", else "full control")."""

    items: tuple[tuple[int, str], ...]


@dataclass(frozen=True)
class Gated:
    """An edge instance that needs its primitive and an open gate (template flags)."""

    prim: int
    gate: int


@dataclass(frozen=True)
class Gate:
    """Facts that decide whether edges exist at all: "esc" for enrollment in one template
    (ESC1-3), "officer" for ManageCertificates (ESC7), which needs some template whose
    requester supplies the subject of an authentication certificate. A gate in
    FACT_GATES is one fact of an account: "same-source" when its edges all leave one
    node (protocol transition), "same-target" when they all reach one (the RBCD
    attribute); the side tells the flow network where its arc goes. "esc13" is enrollment
    in one template for one linked group, "esc6" in one template on the one CA whose flags
    make it a certificate for any user: they read the template facts too."""

    kind: str
    template: str  # "" for officer, the account's DN for a fact gate
    flags: tuple[int, ...]  # template-flag primitives that can close it


Why = int | Options | Gated
FACT_GATES = ("same-source", "same-target")
# gates the flow network arcs on the side their edges all share (the rest end in tier 0)
SIDED_GATES = (*FACT_GATES, "esc13")
# kinds of change that can close a gate
GATE_KINDS = {"template-flag", "delegation", "oid-link", "ca-flag"}


@dataclass
class TemplateFacts:
    """The template fields the gates read, as they were when the graph was built."""

    published: bool
    enrollee_supplies_subject: bool
    manager_approval: bool
    authorized_signatures: int
    ekus: tuple[str, ...]


def template_facts(t: CertTemplate) -> TemplateFacts:
    return TemplateFacts(
        t.published,
        t.enrollee_supplies_subject,
        t.manager_approval,
        t.authorized_signatures,
        tuple(t.ekus),
    )


def flag_active(f: TemplateFacts, flag: str) -> bool:
    """Whether removing the flag changes the template. An EKU goes only when another one
    stays: an empty list means any purpose."""
    if flag == "require-approval":
        return not f.manager_approval
    if flag == "enrollee-supplies-subject":
        return f.enrollee_supplies_subject
    from .checks import EKU_ANY, EKU_REQUEST_AGENT

    eku = EKU_ANY if flag == "any-purpose-eku" else EKU_REQUEST_AGENT
    return eku in f.ekus and len(f.ekus) > 1


def without_flags(f: TemplateFacts, flags: Iterable[str]) -> TemplateFacts:
    from .checks import EKU_ANY, EKU_REQUEST_AGENT

    out = f
    for flag in flags:
        if not flag_active(out, flag):
            continue
        if flag == "require-approval":
            out = replace(out, manager_approval=True)
        elif flag == "enrollee-supplies-subject":
            out = replace(out, enrollee_supplies_subject=False)
        else:
            eku = EKU_ANY if flag == "any-purpose-eku" else EKU_REQUEST_AGENT
            out = replace(out, ekus=tuple(e for e in out.ekus if e != eku))
    return out


def _authenticates(f: TemplateFacts) -> bool:
    from .checks import EKU_ANY, EKU_CLIENT_AUTH

    return not f.ekus or EKU_ANY in f.ekus or bool(EKU_CLIENT_AUTH & set(f.ekus))


def esc_open(f: TemplateFacts) -> bool:
    """paths.build's test for an exploitable template (ESC1-3), on the facts."""
    from .checks import EKU_ANY, EKU_REQUEST_AGENT

    issuable = f.published and not f.manager_approval and f.authorized_signatures == 0
    return issuable and (
        (f.enrollee_supplies_subject and _authenticates(f))
        or not f.ekus
        or EKU_ANY in f.ekus
        or EKU_REQUEST_AGENT in f.ekus
    )


def auth_open(f: TemplateFacts) -> bool:
    """Issued without a human in the loop and valid for logon: the template half of the
    ESC6 and ESC13 edges."""
    issuable = f.published and not f.manager_approval and f.authorized_signatures == 0
    return issuable and _authenticates(f)


def officer_open(f: TemplateFacts) -> bool:
    """checks.officer_templates' test, on the facts."""
    return f.published and f.enrollee_supplies_subject and _authenticates(f)


class Provenance:
    """Primitive table and edge reasons of one graph, plus what the mutators need to
    know about the snapshot as it was when the graph was built."""

    def __init__(self, snap: Snapshot, node_of: Callable[[str], str], domain_node: str) -> None:
        self.prims: list[Prim] = []
        self.index: dict[Prim, int] = {}
        # src -> reason per edge, and the global add order, both parallel to Graph.edges
        self.why: dict[str, array[int]] = {}
        self.seq: dict[str, array[int]] = {}
        self.logon_why: dict[str, array[int]] = {}
        self.extra: dict[tuple[str, int], Options | Gated] = {}
        self.logon_extra: dict[tuple[str, int], Options | Gated] = {}
        self.gates: list[Gate] = []
        self._gate_of: dict[tuple[str, str], int] = {}
        self._count = 0
        # ESC7 edges into CA nodes: (src, position, CA node); a CA node is tier 0 only
        # while an edge reaches it
        self.ca_edges: list[tuple[str, int, str]] = []
        self.node_of = node_of
        self.domain_node = domain_node
        self.domain_dn = snap.domain_dn.lower()
        self.domain_sid = snap.domain_sid
        self.root_sid = snap.root_sid
        # DCSync reasons that do not come down to one primitive (expected: none)
        self.unsupported = 0
        # Domain Admins and Enterprise Admins in Administrators: AD puts them back
        self.enforced_in_admins = {
            f"sid:{sid}-{rid}"
            for sid in {snap.domain_sid, snap.root_sid} - {""}
            for rid in (512, 519)
        }

        self.containers: set[str] = set()
        self.explicit_inheritable: dict[str, frozenset[str]] = {}
        # container -> its explicit inheritable ACEs: (sid, rights, object type, class)
        self.sources: dict[str, list[tuple[str, int, str | None, str | None]]] = {}
        for o in snap.objects:
            if o.kind in ("ou", "container", "domain"):
                key = o.dn.lower()
                self.containers.add(key)
                own = [a for a in o.inheritable if not a.inherited]
                self.explicit_inheritable[key] = frozenset(a.sid for a in own)
                if own:
                    self.sources[key] = [
                        (a.sid, mapped(a.mask), a.object_type, a.inherited_object_type) for a in own
                    ]
        holder: DirObject | None = None
        for o in snap.objects:
            if o.dn.lower().startswith("cn=adminsdholder,cn=system,"):
                holder = o
        self.protected = sdprop_scope(snap)
        # adminCount or a protected DACL without SDProp behind it: what is left after an
        # account leaves the protected groups (AD-ACC-006)
        self.orphans = {
            o.dn.lower()
            for o in snap.objects
            if o.dacl_protected and o.kind in ("user", "computer", "group")
        }
        self.orphans |= {a.dn.lower() for a in snap.accounts if a.admin_count}
        self.orphans -= self.protected
        self.holder_dn = (
            holder.dn.lower() if holder else f"cn=adminsdholder,cn=system,{self.domain_dn}"
        )
        holder_aces = holder.aces if holder else snap.acls.get("AdminSDHolder", [])
        self.holder_aces: dict[str, set[tuple[int, str | None]]] = {}
        for ace in holder_aces:
            self.holder_aces.setdefault(ace.sid, set()).add((ace.mask, ace.object_type))
        self._copy_owner_cache: dict[tuple[object, ...], tuple[str, ...]] = {}
        # CA right holders ca_control leaves out because they are tier 0 (set by
        # paths.build): a membership change can bring their ESC7 edge into the graph
        self.hidden_ca: set[str] = set()
        # groups whose members decide whether a delegation edge exists (set by paths.build)
        self.condition_groups: set[str] = set()
        self._lower: dict[int, str] = {}
        self.templates = {t.name: template_facts(t) for t in snap.templates}
        # SIDs whose membership a GPO security filter reads: a change there moves GPO scope
        self.filter_sids: set[str] = set()
        for g in snap.gpos:
            filter_key = gpo_scope._filter_key(g)
            if filter_key is not None:
                self.filter_sids |= filter_key[0] | filter_key[1]
        self.group_sid: dict[str, str] = {
            o.dn.lower(): o.sid for o in snap.objects if o.kind == "group" and o.sid
        }
        self.parents: dict[str, list[str]] = {}  # member DN -> groups (lower case)
        for o in snap.objects:
            if o.kind == "group":
                for m in o.members:
                    self.parents.setdefault(m.lower(), []).append(o.dn.lower())
        self.gpo_dns: dict[str, str] = {}  # GUID -> GPO DN (lower case)
        for g in snap.gpos:
            self.gpo_dns[g.guid.upper()] = (
                f"cn={g.guid.lower()},cn=policies,cn=system,{self.domain_dn}"
            )
        self.gpo_filter_sids: dict[str, set[str]] = {}  # GPO DN -> SIDs with Read or Apply
        for g in snap.gpos:
            self.gpo_filter_sids[self.gpo_dns[g.guid.upper()]] = {
                a.sid
                for a in g.aces
                if a.mask & gpo_scope.READ_RIGHTS or a.extended_right(sd.APPLY_GROUP_POLICY)
            }

    # -- the primitive table --------------------------------------------------------

    def prim(self, key: Prim) -> int:
        found = self.index.get(key)
        if found is None:
            found = self.index[key] = len(self.prims)
            self.prims.append(key)
        return found

    def lookup(self, key: Prim) -> int | None:
        return self.index.get(key)

    # -- recording, called by paths.build right after an edge is appended -----------

    def push(self, src: str, why: Why) -> None:
        arr = self.why.get(src)
        if arr is None:
            arr = self.why[src] = array("i")
            self.seq[src] = array("I")
        if not isinstance(why, int):
            self.extra[(src, len(arr))] = why
            why = why.items[0][0] if isinstance(why, Options) else why.prim
        arr.append(why)
        self.seq[src].append(self._count)
        self._count += 1

    def push_logon(self, src: str, why: Why) -> None:
        arr = self.logon_why.setdefault(src, array("i"))
        if not isinstance(why, int):
            self.logon_extra[(src, len(arr))] = why
            why = why.items[0][0] if isinstance(why, Options) else why.prim
        arr.append(why)

    # -- reasons --------------------------------------------------------------------

    def _dn(self, o: DirObject) -> str:
        key = self._lower.get(id(o))
        if key is None:
            key = self._lower[id(o)] = o.dn.lower()
        return key

    def _copy_owners(self, dn: str, ace: sd.Ace, kind: str | None) -> tuple[str, ...]:
        """The containers above `dn` whose explicit inheritable ACE this inherited copy
        can come from: same trustee and object type, rights that cover the copy's, and a
        class filter that lets the child (or the copy, as it passes on) inherit it."""
        cache_key = (dn, ace.sid, ace.mask, ace.object_type, ace.inherited_object_type, kind)
        found = self._copy_owner_cache.get(cache_key)
        if found is not None:
            return found
        rights = mapped(ace.mask)
        child_class = CLASS_OF_KIND.get(kind or "")
        out = []
        for comma in gpo_scope.RDN_SEPARATOR.finditer(dn):
            parent = dn[comma.end() :]
            for sid, mask, object_type, only in self.sources.get(parent, ()):
                if (
                    sid == ace.sid
                    and object_type == ace.object_type
                    and not rights & ~mask
                    and only in (None, child_class, ace.inherited_object_type)
                ):
                    out.append(parent)
                    break
        found = self._copy_owner_cache[cache_key] = tuple(out)
        return found

    def _object_key(self, dn: str, sid: str) -> Prim:
        if dn in self.containers and sid in self.explicit_inheritable[dn]:
            return ("inherited-ace", dn, sid)
        return ("ace", dn, sid)

    def ace_prim_keys(self, dn: str, ace: sd.Ace, kind: str | None = None) -> tuple[Prim, ...]:
        """The primitives behind one ACE in the `aces` or `inheritable` list of the object
        with this (lower-cased) DN and kind; the ACE stays while any of them does (more
        than one only for an inherited copy with several possible sources). The mutators
        in changes.py ask this too."""
        sid = ace.sid
        if ace.inherited:
            owners = self._copy_owners(dn, ace, kind)
            if owners:
                return tuple(self._object_key(owner, sid) for owner in owners)
        elif dn == self.holder_dn or (
            dn in self.protected and (ace.mask, ace.object_type) in self.holder_aces.get(sid, ())
        ):
            return (("adminsdholder-ace", sid),)
        return (self._object_key(dn, sid),)

    def ace_prim_key(self, dn: str, ace: sd.Ace, kind: str | None = None) -> Prim:
        """The first primitive of `ace_prim_keys`."""
        return self.ace_prim_keys(dn, ace, kind)[0]

    def orphan_copy(self, dn: str, sid: str, aces: Iterable[sd.Ace]) -> bool:
        """Whether one of these ACEs of the trustee equals its AdminSDHolder ACE on an
        object with adminCount (or a protected DACL) that SDProp no longer rewrites."""
        if dn not in self.orphans:
            return False
        held = self.holder_aces.get(sid, set())
        return any(a.sid == sid and (a.mask, a.object_type) in held for a in aces)

    def ace_key(self, dn: str, ace: sd.Ace, kind: str | None = None) -> int:
        return self.prim(self.ace_prim_key(dn, ace, kind))

    def ace(self, o: DirObject, ace: sd.Ace, how: str = "") -> Why:
        keys = self.ace_prim_keys(self._dn(o), ace, o.kind)
        if len(keys) == 1:
            return self.prim(keys[0])
        return Options(tuple((self.prim(k), how) for k in keys))

    def dcsync(self, o: DirObject, sid: str) -> int:
        dn = self._dn(o)
        get = {self.ace_key(dn, a, o.kind) for a in o.aces if a.sid == sid and _replicates(a)}
        if len(get) != 1:
            self.unsupported += 1
        return min(get)

    def owner(self, o: DirObject) -> int:
        return self.prim(("owner", self._dn(o)))

    def member(self, group: DirObject, member_dn: str, target: str, source: str) -> int:
        if target == "sid:S-1-5-32-544" and source in self.enforced_in_admins:
            return FIXED["builtin-nesting"]
        return self.prim(("member", self._dn(group), member_dn.lower()))

    def rewriter(self, o: DirObject, sid: str) -> Options:
        """Who can change who a filtered GPO applies to (paths._dacl_writers), by reason."""
        items: list[tuple[int, str]] = []
        if o.owner == sid:
            items.append((self.owner(o), "owns"))
        seen = set()
        for a in o.aces:
            if a.sid == sid and a.rewrites_dacl:
                p = self.ace_key(self._dn(o), a, o.kind)
                if p not in seen:
                    seen.add(p)
                    items.append((p, "full control"))
        return Options(tuple(items))

    def gplink(self, guid: str, container: str) -> int:
        if guid.upper() in DEFAULT_GPOS:
            return FIXED["default-gpo-link"]
        return self.prim(("gplink", guid.upper(), container.lower()))

    def dc_link_container(self, where: str) -> str:
        """The container behind an entry of Gpo.linked_to ("domain" or the DC OU)."""
        return self.domain_dn if where == "domain" else f"ou=domain controllers,{self.domain_dn}"

    def dc_link(self, guid: str, where: str) -> int:
        """The link behind a "linked to domain" or "linked to Domain Controllers OU" edge."""
        return self.gplink(guid, self.dc_link_container(where))

    def applies(
        self, guid: str, scope: str, how: str, entered: dict[tuple[str, str], list[str]]
    ) -> Why:
        """The links behind a "GPO applies to" edge: it stays while any of them does."""
        reasons = list(
            dict.fromkeys(self.gplink(guid, c) for c in entered.get((guid.upper(), scope), []))
        )
        if not reasons:
            return FIXED["gpo-scope"]
        if any(r < 0 for r in reasons):
            return FIXED["default-gpo-link"]
        if len(reasons) == 1:
            return reasons[0]
        return Options(tuple((r, how) for r in reasons))

    def grant(self, grant: Grant) -> int:
        item = grant.item
        return self.prim(
            ("gpo-entry", grant.gpo.guid.upper(), item.group_sid.upper(), item.member_sid.upper())
        )

    def template_ace(self, t: CertTemplate, sid: str) -> int:
        return self.prim(("template-ace", t.name, sid))

    def enroll(self, t: CertTemplate, sid: str) -> Gated:
        return Gated(self.template_ace(t, sid), self._gate("esc", t.name))

    def esc13(self, t: CertTemplate, sid: str, oid: str, group: str) -> Gated:
        """Enrollment gives the policy's group: the ACE, the link and the template's
        authentication condition."""
        gate = self._cert_gate("esc13", t.name, oid, ("oid-link", oid, group.lower()))
        return Gated(self.template_ace(t, sid), gate)

    def esc6(self, t: CertTemplate, sid: str, ca: str) -> Gated:
        """Enrollment on the CA with ESC6 and ESC16: the ACE, the two CA flags and the
        template's authentication condition."""
        flags = [("ca-flag", ca, flag) for flag in CA_FLAGS]
        return Gated(self.template_ace(t, sid), self._cert_gate("esc6", t.name, ca, *flags))

    def _cert_gate(self, kind: str, template: str, detail: str, *facts: Prim) -> int:
        key = (kind, f"{template}\0{detail}")
        found = self._gate_of.get(key)
        if found is not None:
            return found
        flags = [self.prim(fact) for fact in facts]
        f = self.templates[template]
        flags += [
            self.prim(("template-flag", template, flag))
            for flag in AUTH_FLAGS
            if flag_active(f, flag)
        ]
        found = self._gate_of[key] = len(self.gates)
        self.gates.append(Gate(kind, template, tuple(flags)))
        return found

    def pki(self, key: str, sid: str) -> int:
        return self.prim(("pki-ace", key, sid))

    def ca_right(self, ca: str, sid: str, right: str) -> Why:
        p = self.prim(("ca-right", ca, sid, right))
        if right == "ManageCertificates":
            return Gated(p, self._gate("officer", ""))
        return p

    def note_ca_edge(self, src: str, dst: str) -> None:
        self.ca_edges.append((src, len(self.why[src]) - 1, dst))

    def gmsa(self, dn: str, sid: str) -> int:
        return self.prim(("gmsa-reader", dn.lower(), sid))

    def constrained(self, dn: str, spn: str) -> Gated:
        """A constrained delegation edge: the SPN entry, and protocol transition."""
        key = dn.lower()
        p = self.prim(("delegation", key, f"constrained:{spn}"))
        return Gated(p, self._fact_gate("same-source", key, "protocol-transition"))

    def rbcd(self, dn: str, sid: str) -> Gated:
        """A resource-based edge: the listed principal, and the attribute that lists it."""
        key = dn.lower()
        return Gated(
            self.prim(("rbcd-principal", key, sid)),
            self._fact_gate("same-target", key, "rbcd"),
        )

    def sid_history(self, dn: str, sid: str) -> int:
        return self.prim(("sid-history", dn.lower(), sid))

    def _fact_gate(self, kind: str, dn: str, what: str) -> int:
        found = self._gate_of.get((kind, dn))
        if found is None:
            found = self._gate_of[(kind, dn)] = len(self.gates)
            self.gates.append(Gate(kind, dn, (self.prim(("delegation", dn, what)),)))
        return found

    def _gate(self, kind: str, template: str) -> int:
        key = (kind, template)
        found = self._gate_of.get(key)
        if found is not None:
            return found
        names = [template] if kind == "esc" else sorted(self.templates)
        flags = []
        for name in names:
            facts = self.templates[name]
            if kind == "officer" and not officer_open(facts):
                continue
            for flag in TEMPLATE_FLAGS:
                if kind == "officer" and flag == "require-approval":
                    continue  # a manager approves anyway: approval does not stop ESC7
                if flag_active(facts, flag):
                    flags.append(self.prim(("template-flag", name, flag)))
        found = self._gate_of[key] = len(self.gates)
        self.gates.append(Gate(kind, template, tuple(flags)))
        return found

    # -- evaluation -----------------------------------------------------------------

    def gate_open(self, gate: int, removed: set[int] | frozenset[int]) -> bool:
        """Whether the gate stays open after the removals (exact, from the facts)."""
        g = self.gates[gate]
        if g.kind in FACT_GATES:
            return not any(p in removed for p in g.flags)
        if g.kind in ("esc13", "esc6"):
            taken = [self.prims[p] for p in g.flags if p in removed]
            if any(key[0] != "template-flag" for key in taken):
                return False  # the policy link or a CA flag is gone
            return auth_open(without_flags(self.templates[g.template], [k[2] for k in taken]))
        gone: dict[str, list[str]] = {}
        for p in g.flags:
            if p in removed:
                _, name, flag = self.prims[p]
                gone.setdefault(name, []).append(flag)
        if g.kind == "esc":
            return esc_open(without_flags(self.templates[g.template], gone.get(g.template, [])))
        return any(
            officer_open(without_flags(facts, gone.get(name, [])))
            for name, facts in self.templates.items()
        )

    def gate_kills(self, gate: int, limit: int = 64) -> list[frozenset[int]] | None:
        """Minimal sets of flags that close the gate (None when there are too many to
        list); brute force over the gate's few flags."""
        flags = self.gates[gate].flags
        if len(flags) > 12:
            return None
        kills: list[frozenset[int]] = []
        for size in range(1, len(flags) + 1):
            for combo in itertools.combinations(flags, size):
                s = frozenset(combo)
                if any(k <= s for k in kills):
                    continue
                if not self.gate_open(gate, s):
                    kills.append(s)
                    if len(kills) > limit:
                        return None
        return kills

    def needs_rebuild(self, p: int) -> bool:
        """Whether the masked graph can miss what removing the primitive does: GPO scope
        moves, a membership change takes a CA right holder out of tier 0, which brings
        its ESC7 edge (left out while it is tier 0) into the graph, or a membership
        change decides whether a delegation edge exists."""
        if self.scope_sensitive(p):
            return True
        key = self.prims[p]
        if key[0] != "member":
            return False
        return bool(self.hidden_ca) or key[1] in self.condition_groups

    def scope_sensitive(self, p: int) -> bool:
        """Whether removing the primitive can move GPO scope (links, security filters),
        which the masked graph does not model: such a change goes through a rebuild."""
        key = self.prims[p]
        kind = key[0]
        if kind == "gplink":
            return True
        if kind == "member":
            # the group, or a group above it, is in some GPO's security filter
            todo, seen = [key[1]], set()
            while todo:
                dn = todo.pop()
                if dn in seen:
                    continue
                seen.add(dn)
                if self.group_sid.get(dn, "") in self.filter_sids:
                    return True
                todo += self.parents.get(dn, [])
            return False
        if kind in ("ace", "inherited-ace"):
            filters = self.gpo_filter_sids.get(key[1])
            return filters is not None and key[2] in filters
        return False


# generic rights as AD maps them on an object (DS generic mapping)
_GENERIC = (
    (sd.GENERIC_ALL, sd.FULL_CONTROL),
    (sd.GENERIC_WRITE, 0x00020028),
    (sd.GENERIC_READ, 0x00020094),
    (0x20000000, 0x00020004),  # GENERIC_EXECUTE
)


def mapped(mask: int) -> int:
    """The rights of a mask with the generic bits mapped: an inherited copy can hold the
    mapped rights of its source's generic ones."""
    out = mask
    for bit, rights in _GENERIC:
        if mask & bit:
            out = (out & ~bit) | rights
    return out


def sdprop_scope(snap: Snapshot) -> set[str]:
    """Lower-cased DNs of the objects SDProp rewrites from AdminSDHolder: the protected
    groups, their members (nested, and by primaryGroupID as the collector lists them),
    Administrator and krbtgt."""
    groups = {o.dn.lower(): o for o in snap.objects if o.kind == "group"}
    out: set[str] = set()
    for o in snap.objects:
        rid = o.sid.rsplit("-", 1)[-1]
        if o.sid in SDPROP_BUILTIN or (rid in SDPROP_RIDS and o.sid.startswith("S-1-5-21-")):
            out.add(o.dn.lower())
    stack = [dn for dn in out if dn in groups]
    while stack:
        for m in groups[stack.pop()].members:
            key = m.lower()
            if key not in out:
                out.add(key)
                if key in groups:
                    stack.append(key)
    for dns in snap.privileged.values():  # transitive lists from the collector
        out |= {dn.lower() for dn in dns}
    for a in snap.accounts:
        if a.rid in (500, 502) or a.primary_group in SDPROP_PRIMARY:
            out.add(a.dn.lower())
    return out


def _replicates(a: sd.Ace) -> bool:
    return a.extended_right(sd.DS_REPL_GET_CHANGES) or a.extended_right(sd.DS_REPL_GET_CHANGES_ALL)
