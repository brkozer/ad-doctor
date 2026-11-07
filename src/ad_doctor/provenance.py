"""Edge provenance for what-if: the removable snapshot fact behind each control-graph edge.

`paths.build(snap, provenance=True)` asks a `Provenance` for the reason of every edge as it
adds it and keeps the answer in arrays parallel to `Graph.edges`. A reason is a primitive
(one fact an administrator can remove: the ACEs of one trustee on one object, one
membership, one GPO link, ...) or a fixed reason (structure that no removal changes).

The rules where the snapshot and AD differ are applied here, at the edge, and the
mutators in `changes.py` ask the same functions which facts a primitive covers, so the
graph and the changed snapshot agree by construction:

- SDProp: an ACE of trustee T on a protected object that equals an ACE of T on
  AdminSDHolder (mask and object type) belongs to `adminsdholder-ace(T)`: SDProp puts the
  copy back within the hour until the AdminSDHolder ACE goes.
- Inheritance: with the INHERITED_ACE flag kept (`Snapshot.ace_inheritance_checked`), an
  inherited copy belongs to the nearest container above that holds an explicit
  inheritable ACE of the same trustee. Older snapshots cannot tell, so a copy is a change
  of its own there: a plan can be too large, never too small.
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
# objects SDProp rewrites from AdminSDHolder: these groups (domain RIDs, BUILTIN), and the
# accounts with adminCount, Administrator and krbtgt
SDPROP_RIDS = {"512", "516", "518", "519", "521", "526", "527"}
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
    """Template flags that decide whether edges exist at all: "esc" for enrollment in one
    template (ESC1-3), "officer" for ManageCertificates (ESC7), which needs some template
    whose requester supplies the subject of an authentication certificate."""

    kind: str
    template: str  # "" for officer
    flags: tuple[int, ...]  # template-flag primitives that can close it


Why = int | Options | Gated


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
        for o in snap.objects:
            if o.kind in ("ou", "container", "domain"):
                key = o.dn.lower()
                self.containers.add(key)
                self.explicit_inheritable[key] = frozenset(
                    a.sid for a in o.inheritable if not a.inherited
                )
        self.protected: set[str] = set()
        holder: DirObject | None = None
        for o in snap.objects:
            key = o.dn.lower()
            if key.startswith("cn=adminsdholder,cn=system,"):
                holder = o
            rid = o.sid.rsplit("-", 1)[-1]
            sdprop_group = o.sid in SDPROP_BUILTIN or (
                rid in SDPROP_RIDS and o.sid.startswith(("S-1-5-21-",))
            )
            if sdprop_group or (o.dacl_protected and o.kind in ("user", "computer", "group")):
                self.protected.add(key)
        for a in snap.accounts:
            if a.admin_count or a.rid in (500, 502):
                self.protected.add(a.dn.lower())
        self.holder_dn = (
            holder.dn.lower() if holder else f"cn=adminsdholder,cn=system,{self.domain_dn}"
        )
        holder_aces = holder.aces if holder else snap.acls.get("AdminSDHolder", [])
        self.holder_aces: dict[str, set[tuple[int, str | None]]] = {}
        for ace in holder_aces:
            self.holder_aces.setdefault(ace.sid, set()).add((ace.mask, ace.object_type))
        self._copy_owner_cache: dict[tuple[str, str], str | None] = {}
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

    def _copy_owner(self, dn: str, sid: str) -> str | None:
        """The nearest container above `dn` with an explicit inheritable ACE of `sid`."""
        cache_key = (dn, sid)
        if cache_key in self._copy_owner_cache:
            return self._copy_owner_cache[cache_key]
        found = None
        for comma in gpo_scope.RDN_SEPARATOR.finditer(dn):
            parent = dn[comma.end() :]
            if sid in self.explicit_inheritable.get(parent, ()):
                found = parent
                break
        self._copy_owner_cache[cache_key] = found
        return found

    def _object_key(self, dn: str, sid: str) -> Prim:
        if dn in self.containers and sid in self.explicit_inheritable[dn]:
            return ("inherited-ace", dn, sid)
        return ("ace", dn, sid)

    def ace_prim_key(self, dn: str, ace: sd.Ace) -> Prim:
        """The primitive behind one ACE in the `aces` or `inheritable` list of the object
        with this (lower-cased) DN. The mutators in changes.py ask this too."""
        sid = ace.sid
        if ace.inherited:
            owner = self._copy_owner(dn, sid)
            if owner is not None:
                return self._object_key(owner, sid)
        elif dn == self.holder_dn or (
            dn in self.protected and (ace.mask, ace.object_type) in self.holder_aces.get(sid, ())
        ):
            return ("adminsdholder-ace", sid)
        return self._object_key(dn, sid)

    def ace_key(self, dn: str, ace: sd.Ace) -> int:
        return self.prim(self.ace_prim_key(dn, ace))

    def ace(self, o: DirObject, ace: sd.Ace) -> int:
        return self.ace_key(self._dn(o), ace)

    def dcsync(self, o: DirObject, sid: str) -> int:
        dn = self._dn(o)
        get = {self.ace_key(dn, a) for a in o.aces if a.sid == sid and _replicates(a)}
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
                p = self.ace(o, a)
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


def _replicates(a: sd.Ace) -> bool:
    return a.extended_right(sd.DS_REPL_GET_CHANGES) or a.extended_right(sd.DS_REPL_GET_CHANGES_ALL)
