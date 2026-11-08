"""Naming a what-if change. Every form resolves to change IDs before anything runs, and
the resolution is printed:

    c:5d1e0a7b2c44                          a change ID
    fp:3fa1c2d4e5f60718                     a finding (rows of the findings table only)
    fp:3fa1c2d4e5f60718#2                   step 2 of that AD-PATH-001 path
    path:"Domain Users"#1                   step 1 of the path that starts there
    edge:helpdesk->"Domain Admins":"write DACL"
    edge:0a1b2c3d4e5f                       a chokepoint row of `paths --chokepoints -f json`
    member:"Domain Admins":grp171
    ace:"OU=Team,DC=lab,DC=test":helpdesk   (and inherited-ace:..., owner:<object>)
    adminsdholder:helpdesk
    gplink:"<GPO>":"<container DN>"
    gpo-entry:"<GPO>":Administrators:"Domain Users"
    template:LabESC1:enroll:"Domain Users"  template:LabESC1:enrollee-supplies-subject
    pki:NTAuthCertificates:helpdesk         ca:<CA>:<trustee>:ManageCertificates
    gmsa:<gMSA>:<reader>                    delegation:<account>:unconstrained
    rbcd:<computer>:<principal>             sid-history:<account>[:<SID>]
    all-rights-of:helpdesk[:tier0]          every change of that trustee

Names are a sAMAccountName, a name, a DN or a SID. More than one match is an error that
lists them; no match means the change is absent in this snapshot.
"""

from __future__ import annotations

import hashlib
import re
from collections.abc import Callable, Iterable
from dataclasses import dataclass, field

from . import changes, paths
from .model import WELL_KNOWN_RIDS, WELL_KNOWN_SIDS, Finding, Snapshot
from .paths import Graph, Path
from .provenance import TEMPLATE_FLAGS, Prim, fixed_reason
from .report import fingerprint

CHANGE_ID = re.compile(r"c:[0-9a-f]{12}")
EDGE_ID = re.compile(r"edge:[0-9a-f]{12}")
DELEGATIONS = ("unconstrained", "protocol-transition", "rbcd")
# where to cut instead of an edge that cannot be removed
WHERE_INSTEAD = {
    "contains": "cut at the right on the container (the step before it)",
    "gpo-scope": "cut at the GPO link or a right on the GPO",
    "sync-host": "treat the server as tier 0 (--tier0 or [assume] tier0)",
    "filter-node": "cut at the right into the GPO (the step before it)",
    "default-gpo-link": "cut at a right on the GPO or on the container",
    "builtin-nesting": "cut at the membership above it",
}


ORPHAN_NOTE = (
    "adminCount left behind: SDProp no longer rewrites this object, so the copy stays "
    "when the AdminSDHolder ACE goes"
)


class SpecError(ValueError):
    """A change that cannot be used as written: syntax, ambiguity, a fixed edge, a
    setting."""


@dataclass
class Resolved:
    spec: str
    prims: list[int] = field(default_factory=list)
    status: str = "applied"  # applied, rewritten, absent
    notes: list[str] = field(default_factory=list)


def edge_id(src: str, dst: str, how: str) -> str:
    """The ID of a graph edge (a chokepoint row), from its node IDs and label."""
    return "edge:" + hashlib.sha256(f"{src}|{dst}|{how}".encode()).hexdigest()[:12]


def split(text: str, seps: tuple[str, ...] = (":",)) -> list[str]:
    """Split on the separators outside double quotes; the quotes go."""
    out: list[str] = []
    cur: list[str] = []
    quoted = False
    i = 0
    while i < len(text):
        ch = text[i]
        if ch == '"':
            quoted = not quoted
            i += 1
            continue
        if not quoted:
            sep = next((s for s in seps if text.startswith(s, i)), None)
            if sep is not None:
                out.append("".join(cur))
                cur = []
                i += len(sep)
                continue
        cur.append(ch)
        i += 1
    if quoted:
        raise SpecError(f"unbalanced quote in {text!r}")
    out.append("".join(cur))
    return out


def quote(value: str) -> str:
    """A name as a spec token: quoted when it holds a separator, a space or a quote."""
    if value and not re.search(r'[:\s"#>-]', value):
        return value
    return '"' + value.replace('"', "") + '"'


class Resolver:
    """Resolves specs against one snapshot and its graph (built with provenance, before
    any change). `findings` gives the baseline findings when a spec needs them."""

    def __init__(
        self,
        snap: Snapshot,
        g: Graph,
        findings: Callable[[], list[Finding]] | None = None,
    ) -> None:
        assert g.prov is not None
        self.snap = snap
        self.g = g
        self.prov = g.prov
        self.where = changes.Where(snap, g.prov)
        self._findings = findings
        self._ids: dict[str, int] | None = None
        self._missing: set[str] = set()  # IDs looked up and not in the table
        self._known_sids: set[str] | None = None
        self._holders: dict[str, Path] | None = None
        self._edge_ids: dict[str, tuple[str, str, str]] | None = None
        # lower-case name -> SID or DN, a list only when names collide (large domains: no
        # set per entry)
        self.sids: dict[str, str | list[str]] = {}
        self.dns: dict[str, str | list[str]] = {}
        self.sid_dn: dict[str, str] = {}
        self.dn_sid: dict[str, str] = {}
        self._indexed = False
        self.gpos = {g.guid.upper(): g for g in snap.gpos}
        self.templates = {t.name.lower(): t for t in snap.templates}

    @staticmethod
    def _add(table: dict[str, str | list[str]], key: str, value: str) -> None:
        have = table.get(key)
        if have is None:
            table[key] = value
        elif isinstance(have, list):
            if value not in have:
                have.append(value)
        elif have != value:
            table[key] = [have, value]

    def _index(self) -> None:
        """The name indexes, built on first use (a plan without names needs none)."""
        if self._indexed:
            return
        self._indexed = True
        snap = self.snap
        for a in snap.accounts:
            self._name(a.sam, a.sid, a.dn)
            if a.sam.endswith("$"):
                self._name(a.sam[:-1], a.sid, a.dn)
        for o in snap.objects:
            self._name(o.name, o.sid, o.dn)
        for sid, name in snap.principals.items():
            self._name(name, sid, "")
        for sid, name in WELL_KNOWN_SIDS.items():
            self.sids.setdefault(name.lower(), sid)
        for rid, name in WELL_KNOWN_RIDS.items():
            self.sids.setdefault(name.lower(), f"{snap.domain_sid}-{rid}")
        for key, name in self.where.name.items():
            self._add(self.dns, name.lower(), key)

    def _name(self, name: str, sid: str, dn: str) -> None:
        low = name.lower()
        if sid:
            self._add(self.sids, low, sid)
        if dn:
            key = dn.lower()
            self._add(self.dns, low, key)
            if sid:
                self.sid_dn[sid] = key
                self.dn_sid[key] = sid

    # -- names --------------------------------------------------------------------------

    def _one(
        self,
        what: str,
        name: str,
        found: set[str],
        show: Callable[[str], str],
        written: Callable[[str], str] | None = None,
    ) -> str | None:
        if len(found) > 1 and written is not None:
            exact = {x for x in found if written(x) == name.strip()}
            if len(exact) == 1:  # names that differ only in case: the one as written
                return next(iter(exact))
        if len(found) > 1:
            listed = ", ".join(sorted(show(x) for x in found)[:10])
            raise SpecError(f"{what} {name!r} is ambiguous: {listed}")
        return next(iter(found), None)

    @staticmethod
    def _found(table: dict[str, str | list[str]], key: str) -> set[str]:
        have = table.get(key)
        if have is None:
            return set()
        return set(have) if isinstance(have, list) else {have}

    def sid(self, name: str) -> str | None:
        """The SID of a principal (sAMAccountName, name, DN or SID)."""
        self._index()
        key = name.strip().lower()
        if key.startswith("s-1-"):
            return name.strip().upper()
        found = self._found(self.sids, key)
        if not found and key in self.dn_sid:
            found = {self.dn_sid[key]}
        return self._one(
            "principal",
            name,
            found,
            lambda s: f"{self.g.name(paths._sid_node(s))} ({s})",
            lambda s: self.g.names.get(paths._sid_node(s), ""),
        )

    def dn(self, name: str) -> str | None:
        """The lower-case DN of an object, account, GPO, the domain or AdminSDHolder."""
        self._index()
        key = name.strip().lower()
        domain = self.snap.domain_dn.lower()
        if key == "domain-head":
            return domain
        if key == "domain-controllers-ou":
            return f"ou=domain controllers,{domain}"
        if key.startswith("s-1-"):
            return self.sid_dn.get(name.strip().upper())
        if key.startswith("{") and key.upper() in self.gpos:
            return self.prov.gpo_dns[key.upper()]
        if key in self.where.dn:
            return key
        return self._one(
            "object",
            name,
            self._found(self.dns, key),
            lambda d: self.where.dn.get(d, d),
            lambda d: self.where.name.get(d, ""),
        )

    def gpo(self, name: str) -> str | None:
        """A GPO GUID (upper case, braces) by name or GUID."""
        key = name.strip()
        if key.upper() in self.gpos:
            return key.upper()
        if f"{{{key.upper()}}}" in self.gpos:
            return f"{{{key.upper()}}}"
        found = {guid for guid, g in self.gpos.items() if g.name.lower() == key.lower()}
        return self._one("GPO", name, found, lambda x: f"{self.gpos[x].name} {x}")

    def node(self, name: str) -> str | None:
        """A graph node by name, SID, DN or node ID."""
        if name in self.g.names or name in self.g.edges:
            return name
        sid = self.sid(name)
        if sid is not None:
            return paths._sid_node(sid)
        dn = self.dn(name)
        if dn is not None:
            return self.prov.node_of(dn)
        key = name.lower()
        found = {n for n, label in self.g.names.items() if label.lower() == key}
        return self._one("node", name, found, lambda n: f"{self.g.name(n)} ({n})")

    # -- IDs ----------------------------------------------------------------------------

    def want_ids(self, texts: Iterable[str]) -> None:
        """Find these change IDs in one pass over the change table. Only the IDs asked
        for are kept: a table of every ID costs about 100 MB at 250,000 users."""
        if self._ids is None:
            self._ids = {}
        wanted = {t for t in texts if CHANGE_ID.fullmatch(t)} - self._ids.keys()
        wanted -= self._missing
        if not wanted:
            return
        for i, p in enumerate(self.prov.prims):
            cid = changes.change_id(p)
            if cid in wanted:
                self._ids[cid] = i
                wanted.discard(cid)
                if not wanted:
                    break
        self._missing |= wanted

    def id_lookup(self, text: str) -> int | None:
        self.want_ids([text])
        assert self._ids is not None
        return self._ids.get(text)

    def register(self, key: Prim) -> int:
        """The index of a change, added to the table when it made no edge."""
        p = self.prov.lookup(key)
        if p is None:
            p = self.prov.prim(key)
            cid = changes.change_id(key)
            self._missing.discard(cid)
            if self._ids is not None:
                self._ids[cid] = p
        return p

    # -- facts --------------------------------------------------------------------------

    def ace_keys(self, dn: str, sid: str) -> list[Prim]:
        """The changes behind the trustee's ACEs on the object, in first-seen order."""
        out: dict[Prim, None] = {}
        kind = self.where.kind.get(dn)
        for a in self.where.aces(dn):
            if a.sid == sid:
                for key in self.prov.ace_prim_keys(dn, a, kind):
                    out[key] = None
        return list(out)

    def exists(self, key: Prim) -> bool:
        """Whether the snapshot still holds the fact behind the change."""
        if self.prov.lookup(key) is not None and self._made_edges(key):
            return True
        snap = self.snap
        kind = key[0]
        if kind in ("ace", "inherited-ace"):
            return key in self.ace_keys(key[1], key[2])
        if kind == "adminsdholder-ace":
            return any(a.sid == key[1] for a in self.where.aces(self.prov.holder_dn))
        if kind == "owner":
            o = self.where.objects.get(key[1])
            owner = getattr(o, "owner", None)
            return bool(owner) and paths._sid_node(str(owner)) not in self.g.tier0
        if kind == "member":
            o = self.where.objects.get(key[1])
            members = [m.lower() for m in getattr(o, "members", [])]
            return key[2] in members
        if kind == "gplink":
            g = self.gpos.get(key[1])
            if g is None:
                return False
            if any(x.container.lower() == key[2] for x in g.links):
                return True
            return any(self.prov.dc_link_container(w) == key[2] for w in g.linked_to)
        if kind == "gpo-entry":
            return any(
                x.gpo.upper() == key[1]
                and x.group_sid.upper() == key[2]
                and x.member_sid.upper() == key[3]
                for x in snap.gpo_local_groups
            )
        if kind == "template-ace":
            t = next((t for t in snap.templates if t.name == key[1]), None)
            return t is not None and any(a.sid == key[2] for a in t.aces)
        if kind == "template-flag":
            from .provenance import flag_active, template_facts

            t = next((t for t in snap.templates if t.name == key[1]), None)
            return t is not None and flag_active(template_facts(t), key[2])
        if kind == "pki-ace":
            return any(a.sid == key[2] for a in snap.acls.get(key[1], []))
        if kind == "ca-right":
            from .checks import CA_RIGHTS

            c = next((c for c in snap.probes.ca_configs if c.name == key[1]), None)
            if c is None:
                return False
            bit = next((b for b, r in CA_RIGHTS if r == key[3]), 0)
            return any(a.sid == key[2] and a.mask & bit for a in c.aces) or (
                key[3] == "ManageCA" and c.owner == key[2]
            )
        if kind == "gmsa-reader":
            gm = next((x for x in snap.gmsas if x.dn.lower() == key[1]), None)
            return gm is not None and key[2] in gm.readers
        if kind == "delegation":
            a = next((x for x in snap.accounts if x.dn.lower() == key[1]), None)
            return a is not None and _delegates(a, key[2])
        if kind in ("rbcd-principal", "sid-history"):
            a = next((x for x in snap.accounts if x.dn.lower() == key[1]), None)
            if a is None:
                return False
            return key[2] in ((a.rbcd_principals or []) if kind[0] == "r" else a.sid_history)
        return False

    def _made_edges(self, key: Prim) -> bool:
        from .whatif import _index

        p = self.prov.lookup(key)
        return p is not None and bool(_index(self.prov).srcs.get(p))

    def sid_known(self, sid: str) -> bool:
        """Whether the SID appears anywhere in the snapshot: a principal, an account, an
        object, or the trustee of some ACE, CA right, GPO entry or gMSA reader."""
        if self._known_sids is None:
            snap = self.snap
            known = set(self.where.sid_name)
            for lists in self.where.lists.values():
                for aces in lists:
                    known.update(a.sid for a in aces)
            for t in snap.templates:
                known.update(a.sid for a in t.aces)
            for aces in snap.acls.values():
                known.update(a.sid for a in aces)
            for c in snap.probes.ca_configs:
                known.update(a.sid for a in c.aces)
                if c.owner:
                    known.add(c.owner)
            for gm in snap.gmsas:
                known.update(gm.readers)
            for a in snap.accounts:
                known.update(a.sid_history)
                known.update(a.rbcd_principals or ())
            for x in snap.gpo_local_groups:
                known.update((x.group_sid, x.member_sid))
            self._known_sids = {k.upper() for k in known if k}
        return sid.upper() in self._known_sids

    def entry_problem(self, key: Prim) -> str | None:
        """Why a plan entry cannot stand for a change in this snapshot, checked against
        what --remove accepts: an unknown flag, right or delegation, a trustee that
        appears nowhere, or a fact that is not a change (a DC's delegation)."""
        from .checks import CA_RIGHTS

        kind = key[0]
        if kind == "template-flag" and key[2] not in TEMPLATE_FLAGS:
            return f"unknown template flag {key[2]!r} (flags: {', '.join(TEMPLATE_FLAGS)})"
        if kind == "ca-right" and key[3] not in {r for _, r in CA_RIGHTS}:
            return f"unknown CA right {key[3]!r}: a CA right is ManageCA or ManageCertificates"
        if kind == "delegation":
            what = key[2]
            if what not in DELEGATIONS and not (
                what.startswith("constrained:") and len(what) > len("constrained:")
            ):
                return (
                    f"unknown delegation {what!r}: unconstrained, protocol-transition, rbcd "
                    "or constrained:<SPN>"
                )
            refused = self.dc_delegation(key[1], what)
            if refused:
                return refused
        for name, value in zip(changes.FIELDS[kind], key[1:], strict=True):
            if name in changes.SID_FIELDS and self._no_such_principal(value):
                return f"{name} {value} appears nowhere in this snapshot: unresolved trustee"
        return None

    def _no_such_principal(self, sid: str) -> bool:
        """A SID of this domain (or its forest root) that no principal, well-known name or
        ACE has: a typo. A foreign SID can leave the snapshot with the change itself."""
        prefixes = {p for p in (self.snap.domain_sid, self.snap.root_sid) if p}
        if not any(sid.upper().startswith(p.upper() + "-") for p in prefixes):
            return False
        if self.snap.name_of(sid) != sid:
            return False
        return not self.sid_known(sid)

    def dc_delegation(self, dn: str, what: str) -> str | None:
        """A domain controller needs unconstrained delegation: taking it away is not a
        change (AD-DEL-001 leaves DCs out for the same reason)."""
        if what != "unconstrained":
            return None
        a = next((x for x in self.snap.accounts if x.dn.lower() == dn), None)
        if a is not None and (a.is_dc or a.is_rodc):
            return (
                f"{a.sam} is a domain controller: DCs need unconstrained delegation, so "
                "taking it away is not a change"
            )
        return None

    def anchor_exists(self, key: Prim) -> bool:
        """Whether the object the change is about is in the snapshot (else the plan entry
        is stale: renamed, deleted or a typo)."""
        snap = self.snap
        kind = key[0]
        if kind in ("ace", "inherited-ace", "owner", "member"):
            return key[1] in self.where.dn
        if kind == "adminsdholder-ace":
            return True
        if kind in ("gplink", "gpo-entry"):
            return key[1] in self.gpos
        if kind in ("template-ace", "template-flag"):
            return any(t.name == key[1] for t in snap.templates)
        if kind == "pki-ace":
            return key[1] in snap.acls
        if kind == "ca-right":
            return any(c.name == key[1] for c in snap.probes.ca_configs)
        if kind == "gmsa-reader":
            return any(x.dn.lower() == key[1] for x in snap.gmsas)
        if kind in ("delegation", "rbcd-principal", "sid-history"):
            return key[1] in self.where.dn
        return False

    # -- the forms ----------------------------------------------------------------------

    def resolve(self, spec: str) -> Resolved:
        text = spec.strip()
        if not text:
            raise SpecError("empty change")
        if CHANGE_ID.fullmatch(text):
            p = self.id_lookup(text)
            if p is None:
                return Resolved(spec, [], "absent", ["absent in this snapshot"])
            return Resolved(spec, [p])
        head, _, rest = text.partition(":")
        head = head.lower()
        if head == "fp":
            return self._fingerprint(spec, rest)
        if head == "path":
            name, _, step = rest.rpartition("#")
            if not name:
                name, step = rest, "1"
            name = "".join(split(name, ()))
            return self._path_step(spec, self._holder_by_name(name), step)
        if head == "edge":
            if EDGE_ID.fullmatch(text):
                return self._edge_by_id(spec, text)
            return self._edge(spec, rest)
        if head == "all-rights-of":
            return self._bundle(spec, rest)
        if head == "disable":
            raise SpecError(
                "disable is not in this version: a disabled account keeps its rights in the "
                "model, and anyone who controls it can enable it again"
            )
        keys, notes = self.typed(head, split(rest))
        return self._from_keys(spec, keys, notes)

    def _from_keys(self, spec: str, keys: list[Prim], notes: list[str]) -> Resolved:
        present = [k for k in keys if self.exists(k)]
        if not present:
            return Resolved(spec, [], "absent", [*notes, "absent in this snapshot"])
        status = "rewritten" if any("resolves to" in n for n in notes) else "applied"
        return Resolved(spec, [self.register(k) for k in present], status, notes)

    def typed(self, kind: str, args: list[str]) -> tuple[list[Prim], list[str]]:
        """Typed spec -> change keys (not checked against the snapshot) and notes."""

        def need(n: int, form: str) -> None:
            if len(args) < n or not all(args[:n]):
                raise SpecError(f"write it as {form}")

        def principal(name: str) -> str:
            sid = self.sid(name)
            if sid is None:
                raise _Absent(f"no principal {name!r} in this snapshot")
            return sid

        def obj(name: str) -> str:
            dn = self.dn(name)
            if dn is None:
                raise _Absent(f"no object {name!r} in this snapshot")
            return dn

        try:
            if kind in ("ace", "inherited-ace"):
                need(2, f'{kind}:"<object DN or name>":<trustee>')
                if len(args) > 2:
                    raise SpecError(
                        "narrowing an ACE change by rights is not in this version: the change "
                        "covers every ACE of the trustee on the object"
                    )
                return self._ace(kind, obj(args[0]), principal(args[1]))
            if kind in ("adminsdholder", "adminsdholder-ace"):
                need(1, "adminsdholder:<trustee>")
                return [("adminsdholder-ace", principal(args[0]))], []
            if kind == "owner":
                need(1, 'owner:"<object>"')
                return [("owner", obj(args[0]))], []
            if kind == "member":
                need(2, 'member:"<group>":<member>')
                group_sid, member_sid = self.sid(args[0]), self.sid(args[1])
                if (
                    group_sid == "S-1-5-32-544"
                    and f"sid:{member_sid}" in self.prov.enforced_in_admins
                ):
                    raise SpecError(
                        "AD puts Domain Admins and Enterprise Admins back into Administrators: "
                        + WHERE_INSTEAD["builtin-nesting"]
                    )
                return [("member", obj(args[0]), obj(args[1]))], []
            if kind == "gplink":
                need(2, 'gplink:"<GPO>":"<container DN>"')
                guid = self.gpo(args[0])
                if guid is None:
                    raise _Absent(f"no GPO {args[0]!r} in this snapshot")
                container = obj(args[1])
                if guid in _default_gpos():
                    raise SpecError(
                        f"the links of the default domain policies cannot be removed: "
                        f"{WHERE_INSTEAD['default-gpo-link']}"
                    )
                return [("gplink", guid, container)], []
            if kind == "gpo-entry":
                need(3, 'gpo-entry:"<GPO>":<local group>:<member>')
                return self._gpo_entry(args[0], args[1], args[2]), []
            if kind == "template":
                need(2, "template:<name>:enroll:<trustee> or template:<name>:<flag>")
                t = self.templates.get(args[0].lower())
                if t is None:
                    raise _Absent(f"no template {args[0]!r} in this snapshot")
                rest = args[1:]
                if len(rest) == 1 and rest[0].lower() in TEMPLATE_FLAGS:
                    return [("template-flag", t.name, rest[0].lower())], []
                if len(rest) == 2 and rest[0].lower() in ("enroll", "write", "ace"):
                    rest = rest[1:]
                if len(rest) != 1:
                    raise SpecError(
                        "write it as template:<name>:enroll:<trustee> or template:<name>:<flag> "
                        f"(flags: {', '.join(TEMPLATE_FLAGS)})"
                    )
                return [("template-ace", t.name, principal(rest[0]))], []
            if kind in ("template-ace", "template-flag"):
                return self.typed("template", args)
            if kind in ("pki", "pki-ace"):
                need(2, "pki:<PKI object>:<trustee>")
                key = args[0] if args[0].startswith("PKI:") else f"PKI:{args[0]}"
                match = [k for k in self.snap.acls if k.lower() == key.lower()]
                if not match:
                    raise _Absent(f"no PKI object {args[0]!r} in this snapshot")
                return [("pki-ace", match[0], principal(args[1]))], []
            if kind in ("ca", "ca-right"):
                need(3, "ca:<CA>:<trustee>:ManageCA|ManageCertificates")
                right = {"manageca": "ManageCA", "managecertificates": "ManageCertificates"}
                if args[2].lower() not in right:
                    raise SpecError("a CA right is ManageCA or ManageCertificates")
                return [("ca-right", args[0], principal(args[1]), right[args[2].lower()])], []
            if kind in ("gmsa", "gmsa-reader"):
                need(2, "gmsa:<gMSA>:<reader>")
                return [("gmsa-reader", obj(args[0]), principal(args[1]))], []
            if kind == "delegation":
                need(
                    2,
                    "delegation:<account>:unconstrained|protocol-transition|rbcd|constrained:<SPN>",
                )
                what = ":".join(args[1:])
                low = what.lower()
                if low in DELEGATIONS:
                    what = low
                elif low.startswith("constrained:") and len(what) > len("constrained:"):
                    what = "constrained:" + what.split(":", 1)[1]
                else:
                    raise SpecError(
                        "a delegation is unconstrained, protocol-transition, rbcd or "
                        "constrained:<SPN>"
                    )
                dn = obj(args[0])
                refused = self.dc_delegation(dn, what)
                if refused:
                    raise SpecError(refused)
                return [("delegation", dn, what)], []
            if kind in ("rbcd", "rbcd-principal"):
                need(2, "rbcd:<computer>:<principal>")
                return [("rbcd-principal", obj(args[0]), principal(args[1]))], []
            if kind == "sid-history":
                need(1, "sid-history:<account>[:<SID>]")
                dn = obj(args[0])
                if len(args) > 1:
                    return [("sid-history", dn, principal(args[1]))], []
                held = next((a for a in self.snap.accounts if a.dn.lower() == dn), None)
                return [("sid-history", dn, s) for s in (held.sid_history if held else [])], []
        except _Absent as exc:
            return [], [str(exc)]
        raise SpecError(f"unknown kind of change {kind!r}")

    def _ace(self, kind: str, dn: str, sid: str) -> tuple[list[Prim], list[str]]:
        keys = self.ace_keys(dn, sid)
        notes = []
        if not keys:
            return [(kind, dn, sid)], []
        written = (kind, dn, sid)
        # the object's own ACEs (an SDProp copy counts: it is written on the object) win;
        # copies inherited from above are only named, never added in silence
        own = [k for k in keys if k[0] == "adminsdholder-ace" or k[1] == dn]
        above = [k for k in keys if k not in own]
        if own:
            for k in above:
                notes.append(
                    f"also inherits ACEs of this trustee from {self.where.dn.get(k[1], k[1])}: "
                    f"name that change ({changes.change_id(k)}) to remove them"
                )
            keys = own
        for k in keys:
            if k[0] == "adminsdholder-ace":
                notes.append(
                    "an SDProp copy: resolves to the AdminSDHolder change (SDProp would put the "
                    "copy back)"
                )
            elif k[1] != dn:
                notes.append(
                    f"inherited from {self.where.dn.get(k[1], k[1])}: resolves to the change there"
                )
            elif k[0] != kind and kind != "ace":
                notes.append(f"resolves to {k[0]} (how the ACE is held there)")
        if written not in keys and not any("resolves to" in n for n in notes):
            notes.append(f"resolves to {keys[0][0]}")
        return keys, notes

    def _gpo_entry(self, gpo: str, group: str, member: str) -> list[Prim]:
        guid = self.gpo(gpo)
        if guid is None:
            raise _Absent(f"no GPO {gpo!r} in this snapshot")

        def match(sid: str, written: str, want: str) -> bool:
            low = want.lower()
            if sid and (sid.lower() == low or self.snap.name_of(sid).lower() == low):
                return True
            return written.lower() == low

        found = {
            ("gpo-entry", guid, x.group_sid.upper(), x.member_sid.upper())
            for x in self.snap.gpo_local_groups
            if x.gpo.upper() == guid
            and x.member_sid
            and match(x.group_sid, x.group_name, group)
            and match(x.member_sid, x.member_name, member)
        }
        if len(found) > 1:
            raise SpecError(f"gpo-entry {gpo}:{group}:{member} is ambiguous: write SIDs")
        if not found:
            raise _Absent(f"no entry {member} -> {group} in GPO {gpo}")
        return sorted(found)

    # -- edges, paths and findings -------------------------------------------------------

    def _edge_prims(self, src: str, dst: str, how: str | None, spec: str) -> Resolved:
        from .cut import _instances

        if src in self.g.tier0:
            raise SpecError(f"{self.g.name(src)} is tier 0: its edges are not changes")
        prims: dict[int, None] = {}
        hit = False
        why = self.prov.why.get(src)
        for i, (d, label) in enumerate(self.g.edges.get(src, ())):
            if d != dst or (how is not None and label.lower() != how.lower()):
                continue
            hit = True
            assert why is not None
            found, _ = _instances(self.prov, src, i, why[i])
            if not found:
                reason = "kept by a default domain policy link"
                w = why[i]
                ex = self.prov.extra.get((src, i))
                if ex is None and w < 0:
                    reason = fixed_reason(w)
                elif ex is not None:
                    reason = next(
                        (fixed_reason(p) for p, _ in getattr(ex, "items", ()) if p < 0),
                        reason,
                    )
                where = WHERE_INSTEAD.get(reason, "cut at another step of the path")
                raise SpecError(
                    f"{self.g.name(src)} -[{label}]-> {self.g.name(dst)} cannot be removed "
                    f"({reason}): {where}"
                )
            for p in found:
                prims[p] = None
        if not hit:
            shown = f"{self.g.name(src)} -[{how}]-> {self.g.name(dst)}" if how else spec
            return Resolved(spec, [], "absent", [f"no edge {shown} in this snapshot"])
        return Resolved(spec, list(prims))

    def _edge(self, spec: str, rest: str) -> Resolved:
        parts = split(rest, ("->", ":"))
        if len(parts) not in (2, 3) or not parts[0] or not parts[1]:
            raise SpecError('write it as edge:<from>-><to>[:"<right>"]')
        src = self.node(parts[0])
        dst = self.node(parts[1])
        if src is None or dst is None:
            missing = parts[0] if src is None else parts[1]
            return Resolved(spec, [], "absent", [f"no {missing!r} in this snapshot"])
        return self._edge_prims(src, dst, parts[2] if len(parts) == 3 else None, spec)

    def _edge_by_id(self, spec: str, text: str) -> Resolved:
        if self._edge_ids is None:
            self._edge_ids = {
                edge_id(src, dst, how): (src, dst, how)
                for src, outs in self.g.edges.items()
                for dst, how in outs
            }
        found = self._edge_ids.get(text)
        if found is None:
            return Resolved(spec, [], "absent", ["no such edge in this snapshot"])
        return self._edge_prims(*found, spec)

    def holders(self) -> dict[str, Path]:
        if self._holders is None:
            found = paths.paths_to_tier0(self.g)
            self._holders = paths.direct_holders(self.g, found)
        return self._holders

    def _holder_by_name(self, name: str) -> Path | None:
        key = name.strip()
        hits = [p for n, p in self.holders().items() if self.g.ident(n) == key]
        if not hits:
            low = key.lower()
            hits = [p for n, p in self.holders().items() if self.g.ident(n).lower() == low]
        if not hits:
            node = self.node(name)
            hit = self.holders().get(node or "")
            hits = [hit] if hit else []
        if len(hits) > 1:
            raise SpecError(f"more than one path starts at {name!r}")
        return hits[0] if hits else None

    def _path_step(self, spec: str, p: Path | None, step: str) -> Resolved:
        if p is None:
            return Resolved(spec, [], "absent", ["no such tier-0 path in this snapshot"])
        if not step.isdigit() or not 1 <= int(step) <= len(p.steps):
            raise SpecError(f"the path has steps 1 to {len(p.steps)}: {p.render(self.g)}")
        n = int(step)
        src = p.start if n == 1 else p.steps[n - 2][0]
        dst, how = p.steps[n - 1]
        out = self._edge_prims(src, dst, how, spec)
        out.notes.insert(0, f"step {n} of {p.render(self.g)}")
        return out

    def findings(self) -> list[Finding]:
        if self._findings is None:
            raise SpecError("a fp: change needs the findings; leave out --paths-only")
        return self._findings()

    def finding_object(self, hexid: str) -> tuple[Finding, str]:
        key = hexid.lower()
        if len(key) < 6 or not re.fullmatch(r"[0-9a-f]+", key):
            raise SpecError("a finding fingerprint is hex, at least 6 digits")
        hits = [
            (f, o)
            for f in self.findings()
            for o in f.objects
            if fingerprint(f.check_id, f.key(o)).startswith(key)
        ]
        if len({(f.check_id, o) for f, o in hits}) > 1:
            listed = ", ".join(f"{f.check_id} {o}" for f, o in hits[:5])
            raise SpecError(f"fp:{hexid} is ambiguous: {listed}")
        if not hits:
            raise SpecError(f"no finding with fingerprint {hexid} in this snapshot")
        return hits[0]

    def _fingerprint(self, spec: str, rest: str) -> Resolved:
        hexid, _, step = rest.partition("#")
        f, obj = self.finding_object(hexid)
        if f.check_id == "AD-PATH-001":
            p = self._holder_by_name(f.key(obj))
            out = self._path_step(spec, p, step or "1")
            if not step:
                out.notes.append("a path names its first step; add #N for another")
            return out
        if step:
            raise SpecError("#N names a step of an AD-PATH-001 path only")
        typed = finding_specs(f.check_id, obj)
        if typed is None:
            raise SpecError(f"{f.check_id} is a setting, not a right: no removal clears it")
        keys: list[Prim] = []
        notes: list[str] = [f"{f.check_id} {obj}"]
        for t in typed:
            head, _, args = t.partition(":")
            k, n = self.typed(head, split(args))
            keys += k
            notes += n
        out = self._from_keys(spec, list(dict.fromkeys(keys)), notes)
        return out

    def _bundle(self, spec: str, rest: str) -> Resolved:
        args = split(rest)
        if not args or not args[0] or len(args) > 2 or (len(args) == 2 and args[1] != "tier0"):
            raise SpecError("write it as all-rights-of:<trustee>[:tier0]")
        sid = self.sid(args[0])
        if sid is None:
            return Resolved(spec, [], "absent", [f"no principal {args[0]!r} in this snapshot"])
        owned = {o.dn.lower() for o in self.snap.objects if o.owner == sid}
        own = self.sid_dn.get(sid)  # a fact of the account itself, not a trustee in it
        hits = [
            p
            for p, key in enumerate(self.prov.prims)
            if changes.trustee_of(key) == sid
            or (key[0] == "owner" and key[1] in owned)
            or (key[0] in ("delegation", "sid-history") and key[1] == own)
        ]
        if len(args) == 2:
            reach = _reaching(self.g)
            hits = [p for p in hits if self._touches(p, reach)]
        if not hits:
            return Resolved(spec, [], "absent", [f"{args[0]} holds no right in the graph"])
        return Resolved(spec, hits, "applied", [f"{len(hits)} changes of {args[0]}"])

    def _touches(self, p: int, reach: set[str]) -> bool:
        from .cut import _instances
        from .whatif import _index

        for src in _index(self.prov).srcs.get(p, ()):
            why = self.prov.why[src]
            for i, (dst, _) in enumerate(self.g.edges[src]):
                if dst in reach and p in _instances(self.prov, src, i, why[i])[0]:
                    return True
        return False

    # -- accepted findings --------------------------------------------------------------

    def finding_changes(self, f: Finding, obj: str) -> list[int]:
        """The changes behind one finding object (rows of the findings table), for
        "expected to clear" and to keep accepted findings. Empty when none map."""
        typed = finding_specs(f.check_id, obj)
        if not typed:
            return []
        out: list[int] = []
        for t in typed:
            head, _, args = t.partition(":")
            try:
                keys, _ = self.typed(head, split(args))
            except SpecError:
                continue
            out += [self.prov.index[k] for k in keys if k in self.prov.index]
        return list(dict.fromkeys(out))


class _Absent(Exception):
    pass


def _default_gpos() -> set[str]:
    from .provenance import DEFAULT_GPOS

    return DEFAULT_GPOS


def _reaching(g: Graph) -> set[str]:
    from .whatif import reaching

    return reaching(g)


def _delegates(a: object, what: str) -> bool:
    from .model import UAC, Account

    assert isinstance(a, Account)
    if what == "unconstrained":
        return a.has(UAC.TRUSTED_FOR_DELEGATION)
    if what == "protocol-transition":
        return a.has(UAC.TRUSTED_TO_AUTH_FOR_DELEGATION)
    if what == "rbcd":
        return a.rbcd
    spn = what.removeprefix("constrained:").lower()
    return any(s.lower() == spn for s in a.allowed_to_delegate_to)


# -- finding objects -> typed specs (the findings table) ---------------------------------


def _bare(text: str) -> str:
    """A name without the context ad-doctor appends: 'x (y)' -> 'x'."""
    return text.split(" (", 1)[0].strip()


def _inside(text: str) -> str:
    """The text in the last parentheses: 'x (enroll: a, b)' -> 'enroll: a, b'."""
    if "(" not in text:
        return ""
    return text.rsplit("(", 1)[1].rstrip(")").strip()


def _target_trustee(obj: str) -> tuple[str, str]:
    """'<target> (ctx): <trustee> (rights)' -> (target, trustee)."""
    target, _, rest = obj.partition(": ")
    return _bare(target), _bare(rest)


def _q(v: str) -> str:
    return '"' + v.replace('"', "") + '"'


def _list(text: str) -> list[str]:
    return [x.strip() for x in text.split(", ") if x.strip()]


def finding_specs(check: str, obj: str) -> list[str] | None:
    """Typed specs for one finding object, or None when the check is a setting."""
    if check in ("AD-ACL-001", "AD-ACL-003"):
        return [f"ace:domain-head:{_q(_bare(obj))}"]
    if check == "AD-ACL-002":
        return [f"adminsdholder:{_q(_bare(obj))}"]
    if check in ("AD-ACL-004", "AD-ACL-008"):
        target, trustee = _target_trustee(obj)
        return [f"ace:{_q(target)}:{_q(trustee)}"]
    if check == "AD-ACL-006":
        gmsa = _bare(obj)
        readers = _inside(obj).removeprefix("readable by ").strip()
        return [f"gmsa:{_q(gmsa)}:{_q(r)}" for r in _list(readers)]
    if check == "AD-ACL-007":
        return [f"ace:domain-head:{_q(obj.split(': ', 1)[0])}"]
    if check in (
        "AD-ADCS-001",
        "AD-ADCS-002",
        "AD-ADCS-003",
        "AD-ADCS-006",
        "AD-ADCS-007",
        "AD-ADCS-008",
        "AD-ADCS-017",
    ):
        who = _inside(obj).removeprefix("enroll:").strip()
        return [f"template:{_q(_bare(obj))}:enroll:{_q(t)}" for t in _list(who)]
    if check == "AD-ADCS-004":
        return [f"template:{_q(_bare(obj))}:{_q(t)}" for t in _list(_inside(obj))]
    if check == "AD-ADCS-005":
        return [f"pki:{_q(_bare(obj))}:{_q(t)}" for t in _list(_inside(obj))]
    if check == "AD-ADCS-013":
        ca, _, rest = obj.partition(": ")
        return [f"ca:{_q(ca)}:{_q(_bare(rest))}:{r}" for r in _list(_inside(rest))]
    if check in ("AD-PRIV-003", "AD-PRIV-006", "AD-PRIV-008"):
        group, member = _target_trustee(obj)
        return [f"member:{_q(group)}:{_q(member)}"]
    if check == "AD-PRIV-004":
        return [f"member:DnsAdmins:{_q(_bare(obj))}"]
    if check == "AD-PRIV-009":
        return [f'member:"Cert Publishers":{_q(_bare(obj))}']
    if check == "AD-INV-001" and ": unexpected " in obj:
        group, member = obj.split(": unexpected ", 1)
        return [f"member:{_q(group)}:{_q(member)}"]
    if check == "AD-GPO-001":
        gpo = obj.split(" -> ", 1)[0]
        return [f"ace:{_q(gpo)}:{_q(t)}" for t in _list(_inside(obj))]
    if check == "AD-GPO-002":
        where, trustee = _target_trustee(obj)
        container = {"domain": "domain-head", "Domain Controllers OU": "domain-controllers-ou"}
        return [f"ace:{container.get(where, _q(where))}:{_q(trustee)}"]
    if check == "AD-GPO-004":
        return [f"ace:{_q(_bare(obj))}:{_q(t)}" for t in _list(_inside(obj))]
    if check in ("AD-GPO-005", "AD-GPO-006", "AD-GPO-007"):
        gpo, _, rest = obj.partition(": ")
        member, _, rest = rest.partition(" -> ")
        group = rest.split(" on ", 1)[0]
        return [f"gpo-entry:{_q(gpo)}:{_q(group)}:{_q(member)}"]
    if check == "AD-ACC-007":
        return [f"sid-history:{_q(_bare(obj))}"]
    if check in ("AD-DEL-001", "AD-CHAIN-002"):
        return [f"delegation:{_q(_bare(obj))}:unconstrained"]
    if check == "AD-DEL-002":
        return [f"delegation:{_q(obj.split(' -> ', 1)[0])}:protocol-transition"]
    if check == "AD-DEL-003":
        return [f"delegation:{_q(_bare(obj))}:rbcd"]
    if check in ("AD-DEL-004", "AD-DEL-005"):
        account, _, spn = obj.partition(" -> ")
        if not spn:
            return [f"delegation:{_q(_bare(obj))}:unconstrained"]
        return [f"delegation:{_q(account)}:constrained:{_q(_bare(spn))}"]
    return None


def canonical(snap: Snapshot, prim: Prim, where: changes.Where) -> str:
    """A typed spec that names the change, for output and plan files."""
    f = changes.fields(prim)
    kind = f["kind"]

    def who(name: str) -> str:
        return quote(where.who(snap, f[name]))

    def dn(name: str) -> str:
        return quote(where.dn.get(f[name], f[name]))

    if kind in ("ace", "inherited-ace"):
        return f"{kind}:{dn('object')}:{who('trustee')}"
    if kind == "adminsdholder-ace":
        return f"adminsdholder:{who('trustee')}"
    if kind == "owner":
        return f"owner:{dn('object')}"
    if kind == "member":
        return f"member:{dn('group')}:{dn('member')}"
    if kind == "gplink":
        return f"gplink:{quote(f['gpo'])}:{dn('container')}"
    if kind == "gpo-entry":
        return f"gpo-entry:{quote(f['gpo'])}:{f['group']}:{f['member']}"
    if kind == "template-ace":
        return f"template:{quote(f['template'])}:{who('trustee')}"
    if kind == "template-flag":
        return f"template:{quote(f['template'])}:{f['flag']}"
    if kind == "pki-ace":
        return f"pki:{quote(f['object'].removeprefix('PKI:'))}:{who('trustee')}"
    if kind == "ca-right":
        return f"ca:{quote(f['ca'])}:{who('trustee')}:{f['right']}"
    if kind == "gmsa-reader":
        return f"gmsa:{dn('gmsa')}:{who('reader')}"
    if kind == "rbcd-principal":
        return f"rbcd:{dn('computer')}:{who('principal')}"
    if kind == "sid-history":
        return f"sid-history:{dn('account')}:{f['sid']}"
    return f"delegation:{dn('account')}:{f['what']}"


def names_of(items: Iterable[str]) -> list[str]:
    return sorted(set(items), key=str.lower)
