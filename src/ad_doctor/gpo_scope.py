"""Which computers GPO settings reach and, for the control graph, what a GPO's writer controls.

Scope follows Group Policy processing for the computer side: links on the site, the
domain and each OU above the computer, Block Inheritance and Enforced, disabled links,
the GPO's status flags, an empty computer version or a missing client-side extension
(Windows reports both as "Not Applied (Empty)"), and security filtering (Read plus Apply
Group Policy for any SID in the computer's token).

Domain controllers have no local groups: Restricted Groups applied to a writable DC
rewrite the domain group with that SID (BUILTIN\\Administrators, or Domain Admins itself).
GPP Local Groups items are processed on a DC but leave domain groups alone (checked on
Windows Server 2025), so they are skipped there.

Approximations, each of which can only over-report:
- WMI filters are assumed to match, and items with item-level targeting are assumed to
  apply (each such grant carries a caveat).
- Deny ACEs are not parsed, so a "Deny Apply" exclusion still counts as applied.
- An ordinary user cannot map member computers to sites; with more than one site every
  site's links are assumed to apply.
- Removals and precedence between GPOs are ignored: the result is the union of additions,
  although a higher-precedence X__Members can remove what a lower one adds.
- The token comes from the groups in the snapshot; groups of other domains are not seen.
- A holder of the remote logon right that could not be resolved to a SID is assumed to
  cover the member (with a caveat).
"""

from __future__ import annotations

import dataclasses
import hashlib
import itertools
import re
from dataclasses import dataclass, field

from . import sd
from .model import (
    Account,
    DirObject,
    GpLink,
    Gpo,
    GpoLocalGroup,
    Snapshot,
    well_known_sid,
)

CSE_SECURITY = "{827D319E-6EAC-11D2-A4EA-00C04F79F83A}"  # Restricted Groups, user rights
CSE_GROUPS = "{17D89FEC-5C44-4972-B12D-241CAEF74509}"  # GPP Local Users and Groups
CSE_OF_SOURCE = {"restricted": CSE_SECURITY, "gpp": CSE_GROUPS}
GPO_USER_DISABLED = 0x1
GPO_COMPUTER_DISABLED = 0x2
SIDES = (("computer", GPO_COMPUTER_DISABLED), ("user", GPO_USER_DISABLED))

EVERYONE = "S-1-1-0"
AUTHENTICATED_USERS = "S-1-5-11"
THIS_ORGANIZATION = "S-1-5-15"
ENTERPRISE_DCS = "S-1-5-9"
INTERACTIVE = "S-1-5-4"
ADMINISTRATORS = "S-1-5-32-544"
RDP_USERS = "S-1-5-32-555"
REMOTE_LOGON_RIGHT = "SeRemoteInteractiveLogonRight"
# a comma that ends an RDN: not escaped, i.e. after an even number of backslashes
RDN_SEPARATOR = re.compile(r"(?<!\\)(?:\\\\)*,")
ILT_CAVEAT = "item-level targeting not evaluated"
UNRESOLVED_LOGON = "remote logon right holders not resolved"
MAX_FILTER_NAMES = 3  # groups named on a filtered scope node


@dataclass(frozen=True)
class LocalGroup:
    name: str
    verb: str  # graph edge label
    admin: bool  # admin-equivalent (control) rather than a logon right


# Local groups whose membership matters; any other group name is ignored
LOCAL_GROUPS = {
    ADMINISTRATORS: LocalGroup("Administrators", "admin to", True),
    # SeBackup/SeRestore read the SAM and SECURITY hives: admin-equivalent
    "S-1-5-32-551": LocalGroup("Backup Operators", "backup operator on", True),
    "S-1-5-32-578": LocalGroup("Hyper-V Administrators", "Hyper-V admin on", True),
    RDP_USERS: LocalGroup("Remote Desktop Users", "can RDP", False),
    "S-1-5-32-580": LocalGroup("Remote Management Users", "can PSRemote", False),
    "S-1-5-32-562": LocalGroup("Distributed COM Users", "DCOM", False),
}


@dataclass(frozen=True)
class Grant:
    """A principal a GPO puts into a group: a local group on one computer, or a domain
    group rewritten through the writable DCs (computer None, domain_group True)."""

    gpo: Gpo
    item: GpoLocalGroup
    computer: Account | None
    domain_group: bool
    caveats: tuple[str, ...] = ()
    # False for Remote Desktop Users when the remote logon right does not include it
    effective: bool = True


@dataclass(frozen=True)
class Scope:
    grants: list[Grant]
    # Restricted Groups that empty a domain group through the writable DCs
    clears: list[Grant]
    notes: list[str]


def computer_side_applies(gpo: Gpo, source: str) -> bool:
    """False when Windows would not process this kind of setting in the GPO at all.

    Older snapshots carry no version or extension list; the GPO is then assumed to apply.
    """
    if gpo.flags & GPO_COMPUTER_DISABLED or gpo.machine_version == 0:
        return False
    extensions = gpo.machine_extensions
    return extensions is None or CSE_OF_SOURCE[source] in extensions


def containers(dn: str, domain_dn: str) -> list[str]:
    """Lower-cased OUs above an object, nearest first, then the domain head."""
    key, head = dn.lower(), domain_dn.lower()
    out = []
    for comma in RDN_SEPARATOR.finditer(key):
        parent = key[comma.end() :]
        if parent == head:
            out.append(parent)
            break
        if parent.startswith("ou="):
            out.append(parent)
    return out


def security_filter(gpo: Gpo, token: set[str]) -> bool | None:
    """Whether the token may read and apply the GPO; None when its DACL was not read.

    Read and Apply may come from different ACEs. AD stores mapped rights, so READ_PROPERTY
    is the real test; the generic bits are accepted for hand-made descriptors.
    """
    if not gpo.aces:
        return None
    read = sd.READ_PROPERTY | sd.GENERIC_READ | sd.GENERIC_ALL
    apply = any(a.sid in token and a.extended_right(sd.APPLY_GROUP_POLICY) for a in gpo.aces)
    return apply and any(a.sid in token and a.mask & read for a in gpo.aces)


class _Resolver:
    def __init__(self, snap: Snapshot) -> None:
        self.snap = snap
        self.links_at: dict[str, list[tuple[bool, bool, Gpo]]] = {}  # (enabled, enforced)
        self.site_links: list[tuple[str, bool, bool, Gpo]] = []
        for g in snap.gpos:
            for link in g.links:
                where = link.container.lower()
                if link.kind == "site":
                    self.site_links.append((where, link.enabled, link.enforced, g))
                else:
                    self.links_at.setdefault(where, []).append((link.enabled, link.enforced, g))
        self.blocked = {o.dn.lower() for o in snap.objects if o.gp_blocked}
        self.sid_dn = {o.sid: o.dn.lower() for o in snap.objects if o.sid}
        self.member_of: dict[str, list[DirObject]] = {}
        for o in snap.objects:
            if o.kind == "group":
                for m in o.members:
                    self.member_of.setdefault(m.lower(), []).append(o)
        self._tokens: dict[str, set[str]] = {}

    def linked(self, a: Account) -> list[tuple[Gpo, tuple[str, ...]]]:
        """GPOs linked where they reach this computer, with caveats (no filtering yet)."""
        found: dict[str, tuple[Gpo, tuple[str, ...]]] = {}
        blocked = False
        for c in containers(a.dn, self.snap.domain_dn):
            for enabled, enforced, g in self.links_at.get(c, []):
                # a disabled link never applies, even when it is enforced
                if enabled and (not blocked or enforced):
                    found[g.guid.upper()] = (g, ())
            if c in self.blocked:
                blocked = True  # stops the links above c, never c's own
        site = self.snap.dc_sites.get(a.dn.lower(), "").lower() if a.is_dc else ""
        for container, enabled, enforced, g in self.site_links:
            if not enabled or (blocked and not enforced):
                continue
            if site:
                if container != site:
                    continue
                caveats: tuple[str, ...] = ()
            else:
                single = self.snap.site_count <= 1
                caveats = () if single else ("site membership assumed",)
            if g.guid.upper() not in found or not caveats:
                found[g.guid.upper()] = (g, caveats)
        return list(found.values())

    def token(self, a: Account) -> set[str]:
        """SIDs in the account's token: its own, the well-known ones, the primary group
        and every group that holds any of them, through nesting and through the
        foreignSecurityPrincipal objects that stand for well-known SIDs."""
        known = self._tokens.get(a.dn.lower())
        if known is not None:
            return known
        dom = self.snap.domain_sid
        sids = {a.sid, EVERYONE, AUTHENTICATED_USERS, THIS_ORGANIZATION}
        sids.add(f"{dom}-{a.primary_group or (515 if a.is_computer else 513)}")
        if a.is_dc:
            sids |= {ENTERPRISE_DCS, f"{dom}-{521 if a.is_rodc else 516}"}
        sids.discard("")
        head = self.snap.domain_dn.lower()
        todo = [a.dn.lower()]
        todo += [
            self.sid_dn.get(s, f"cn={s.lower()},cn=foreignsecurityprincipals,{head}") for s in sids
        ]
        seen = set(todo)
        while todo:
            for group in self.member_of.get(todo.pop(), []):
                key = group.dn.lower()
                if key not in seen:
                    seen.add(key)
                    if group.sid:
                        sids.add(group.sid)
                    todo.append(key)
        self._tokens[a.dn.lower()] = sids
        return sids

    def applied(self, a: Account, source: str) -> list[tuple[Gpo, tuple[str, ...]]]:
        """GPOs whose settings of this kind Windows would process on the computer."""
        out = []
        for g, caveats in self.linked(a):
            if not computer_side_applies(g, source):
                continue
            if security_filter(g, self.token(a)) is not False:
                out.append((g, caveats + _gpo_caveats(g)))
        return out

    def remote_logon(self, a: Account, member_sid: str) -> tuple[bool, bool]:
        """Whether Remote Desktop Users (or the member itself) holds the remote logon right,
        and whether that is only assumed because some holder is a name, not a SID.

        Without a GPO that sets it, the built-in default applies: Administrators on a DC,
        Administrators and Remote Desktop Users on any other computer. Deny rights are
        not evaluated.
        """
        holders: set[str] | None = None
        for g, _ in self.applied(a, "restricted"):
            settings = self.snap.gpo_settings.get(g.guid)
            if settings is not None and REMOTE_LOGON_RIGHT in settings.privileges:
                named = settings.privileges[REMOTE_LOGON_RIGHT]
                holders = (holders or set()) | {_holder(h) for h in named}
        if holders is None:
            holders = {ADMINISTRATORS} if a.is_registered_dc else {ADMINISTRATORS, RDP_USERS}
        if RDP_USERS in holders or member_sid in holders:
            return True, False
        unresolved = any(not h.startswith("S-1-") for h in holders)
        return unresolved, unresolved


def _gpo_caveats(g: Gpo) -> tuple[str, ...]:
    unread = ("security filtering not readable",) if not g.aces else ()
    return unread + ((f"WMI filter {g.wmi_filter}",) if g.wmi_filter else ())


def _holder(value: str) -> str:
    if value.upper().startswith("S-1-"):
        return value.upper()
    return well_known_sid(value) or value.lower()


@dataclass(frozen=True)
class NtlmOut:
    """Outgoing NTLM on the DCs as far as Group Policy shows it."""

    # True: denied on every DC. False: some DC has no GPO that denies it. None: unknown.
    denied: bool | None
    detail: str


NTLM_DENY = 2
MAX_EXCEPTIONS = 5


def _dc_ntlm(r: _Resolver, a: Account) -> tuple[bool | None, str, list[str]]:
    """(denied, why, GPOs that deny it) for one DC. Conflicting GPOs stay unknown,
    because precedence between GPOs is not worked out here."""
    deny: list[str] = []
    other: list[str] = []
    unread: list[str] = []
    exceptions: set[str] = set()
    caveats: set[str] = set()
    for g, notes in r.applied(a, "restricted"):
        settings = r.snap.gpo_settings.get(g.guid)
        if settings is None:
            unread.append(g.name)
            continue
        exceptions.update(settings.ntlm_exceptions)
        if settings.restrict_sending_ntlm == NTLM_DENY:
            deny.append(g.name)
            caveats.update(notes)
        elif settings.restrict_sending_ntlm is not None:
            other.append(g.name)
    who = a.sam.rstrip("$")
    if deny and other:
        names = ", ".join(sorted(deny + other))
        return None, f"GPOs disagree on outgoing NTLM on {who} ({names})", []
    if deny and unread:
        names = ", ".join(sorted(unread))
        return (
            None,
            f"{', '.join(sorted(deny))} denies outgoing NTLM on {who}, but GPOs reaching it "
            f"are not readable and may set something else ({names})",
            [],
        )
    if deny and caveats:
        return (
            None,
            f"the GPO denying outgoing NTLM on {who} may not apply: "
            + (", ".join(sorted(caveats))),
            [],
        )
    if deny and exceptions:
        shown = sorted(exceptions)
        more = f" (+{len(shown) - MAX_EXCEPTIONS} more)" if len(shown) > MAX_EXCEPTIONS else ""
        listed = ", ".join(shown[:MAX_EXCEPTIONS]) + more
        return None, f"outgoing NTLM on {who} denied with exceptions: {listed}", []
    if deny:
        return True, "", deny
    if unread:
        names = ", ".join(sorted(unread))
        return None, f"security settings of GPOs reaching {who} not readable ({names})", []
    return False, f"no GPO reaching {who} denies outgoing NTLM", []


def dc_outgoing_ntlm(snap: Snapshot) -> NtlmOut:
    """Whether MSV1_0\\RestrictSendingNTLMTraffic = 2 reaches every DC through a GPO.

    "Not denied" only means no GPO sets it: a value set in the DC's own registry is not
    visible over LDAP or SYSVOL.
    """
    if not snap.ntlm_policy_collected:
        return NtlmOut(None, "GPO security settings were not read")
    dcs = _dcs(snap)
    if not dcs:
        return NtlmOut(None, "no domain controller in the snapshot")
    r = _Resolver(snap)
    results = [_dc_ntlm(r, a) for a in dcs]
    open_dcs = [why for denied, why, _ in results if denied is False]
    if open_dcs:
        return NtlmOut(False, "; ".join(sorted(open_dcs)))
    unknown = [why for denied, why, _ in results if denied is None]
    if unknown:
        return NtlmOut(None, "; ".join(sorted(unknown)))
    gpos = sorted({name for _, _, names in results for name in names})
    return NtlmOut(True, f"{', '.join(gpos)} denies outgoing NTLM on every DC")


@dataclass(frozen=True)
class ChannelAllow:
    """One GPO that sets the Netlogon vulnerable channel allow list on DCs."""

    gpo: Gpo
    sddl: str
    dcs: tuple[str, ...]
    caveats: tuple[str, ...]


def dc_channel_allow(snap: Snapshot) -> tuple[list[ChannelAllow], list[str]]:
    """GPOs that bring VulnerableChannelAllowList to a DC, and the GPOs reaching a DC whose
    security template could not be read. Every such GPO is listed: which one wins is not
    worked out. A value set in the DC's own registry is not visible here."""
    if not snap.channel_policy_collected:
        return [], []
    r = _Resolver(snap)
    found: dict[str, tuple[Gpo, str, set[str], set[str]]] = {}
    unread: set[str] = set()
    for a in _dcs(snap):
        for g, notes in r.applied(a, "restricted"):
            settings = snap.gpo_settings.get(g.guid)
            if settings is None:
                unread.add(g.name)
            elif settings.vulnerable_channel_allow:
                entry = found.setdefault(
                    g.guid.upper(), (g, settings.vulnerable_channel_allow, set(), set())
                )
                entry[2].add(a.sam)
                entry[3].update(notes)
    hits = [
        ChannelAllow(g, sddl, tuple(sorted(dcs)), tuple(sorted(caveats)))
        for g, sddl, dcs, caveats in found.values()
    ]
    return sorted(hits, key=lambda h: h.gpo.name.lower()), sorted(unread)


def _dcs(snap: Snapshot) -> list[Account]:
    return [a for a in _computers(snap) if a.is_registered_dc and not a.entra_kerberos]


def _computers(snap: Snapshot) -> list[Account]:
    return [a for a in snap.accounts if a.is_computer and a.enabled and not a.managed and a.sid]


def resolve(snap: Snapshot) -> Scope:
    """Every principal the GPOs' local group settings add somewhere, deduplicated."""
    items: dict[str, list[GpoLocalGroup]] = {}
    for x in snap.gpo_local_groups:
        items.setdefault(x.gpo.upper(), []).append(x)
    if not snap.local_groups_collected or not items:
        return Scope([], [], [])
    r = _Resolver(snap)
    grants: dict[tuple[str, ...], Grant] = {}
    clears: dict[tuple[str, str], Grant] = {}
    rodcs: set[str] = set()
    gpp_on_dcs: set[str] = set()

    def keep(key: tuple[str, ...], grant: Grant) -> None:
        old = grants.get(key)
        if old is not None:
            merged = tuple(sorted(set(old.caveats) | set(grant.caveats)))
            grant = dataclasses.replace(old, caveats=merged)
        grants[key] = grant

    def place(a: Account, g: Gpo, x: GpoLocalGroup, caveats: tuple[str, ...]) -> None:
        guid = g.guid.upper()
        if x.filtered:
            caveats = (*caveats, ILT_CAVEAT)
        adds = x.action in ("add", "set") and bool(x.member_sid)
        if not a.is_registered_dc:
            # only local groups exist here: an entry for a domain group has no effect
            if adds and x.group_sid in LOCAL_GROUPS:
                keep((guid, x.group_sid, x.member_sid, a.sid), Grant(g, x, a, False, caveats))
        elif not x.group_sid:
            return
        elif adds:  # any group: Domain Admins__Members on DCs rewrites Domain Admins
            keep((guid, x.group_sid, x.member_sid, ""), Grant(g, x, None, True, caveats))
        elif x.replaces and not x.member_name:
            clears[(guid, x.group_sid)] = Grant(g, x, None, True, caveats)

    for a in _computers(snap):
        if not any(g.guid.upper() in items for g, _ in r.linked(a)):
            continue
        for source in ("restricted", "gpp"):
            for g, caveats in r.applied(a, source):
                active = [
                    x
                    for x in items.get(g.guid.upper(), [])
                    if x.source == source and not x.disabled
                ]
                if active and a.is_rodc:
                    rodcs.add(a.sam)  # an RODC cannot write domain groups
                elif active and a.is_registered_dc and source == "gpp":
                    gpp_on_dcs.add(g.name)
                else:
                    for x in active:
                        place(a, g, x, caveats)

    writable_dcs = [a for a in _computers(snap) if a.is_registered_dc and not a.is_rodc]
    out = []
    for grant in grants.values():
        if grant.item.group_sid == RDP_USERS:
            targets = [grant.computer] if grant.computer else writable_dcs
            results = [r.remote_logon(t, grant.item.member_sid) for t in targets]
            effective = any(holds for holds, _ in results)
            assumed = effective and all(guess for holds, guess in results if holds)
            caveats = (*grant.caveats, UNRESOLVED_LOGON) if assumed else grant.caveats
            grant = dataclasses.replace(grant, effective=effective, caveats=caveats)
        out.append(grant)

    notes = []
    for grant in clears.values():
        notes.append(
            f"GPO {grant.gpo.name} empties the domain group {snap.name_of(grant.item.group_sid)} "
            "on every writable DC (Restricted Groups '__Members' with no members; GPMC writes "
            "that line when only 'This group is a member of' is filled in)"
        )
    if rodcs:
        notes.append(
            "local group settings in GPOs reaching read-only DCs are not evaluated: "
            + ", ".join(sorted(rodcs))
        )
    if gpp_on_dcs:
        notes.append(
            "GPP local group items in GPOs that reach domain controllers are ignored, as "
            "Windows ignores them there: " + ", ".join(sorted(gpp_on_dcs))
        )
    return Scope(out, list(clears.values()), notes)


@dataclass
class Reach:
    """What a GPO controls, as scope nodes for the control graph.

    A scope node stands for the accounts of one side (computers or users) at and below an
    OU or the domain head that pass one security filter. So the graph grows with accounts,
    OUs, links and distinct filters, not with GPOs times accounts: GPO -> scope of each
    linked OU -> scope of each child OU the GPO is inherited by -> the accounts held there.

    Scopes are separate from OU nodes: an OU's contains edges mean ACL inheritance, which
    also leads to groups and through Block Inheritance, where Group Policy does not go.
    """

    names: dict[str, str] = field(default_factory=dict)  # scope ID -> display name
    applies: list[tuple[Gpo, str, tuple[str, ...]]] = field(default_factory=list)
    inherits: list[tuple[str, str]] = field(default_factory=list)
    holds: list[tuple[str, Account]] = field(default_factory=list)
    dc_gpos: set[str] = field(default_factory=set)  # upper-case GUIDs that reach some DC


@dataclass
class _Tree:
    """Accounts of one side that pass one filter, by the OU or head that holds them."""

    side: str
    tag: str  # "" for no filter
    title: str  # "computers", or "users"
    filter_name: str  # "" for no filter
    direct: dict[str, list[Account]] = field(default_factory=dict)
    children: dict[str, set[str]] = field(default_factory=dict)
    block_below: dict[str, bool] = field(default_factory=dict)


FilterKey = tuple[frozenset[str], frozenset[str]]  # SIDs with Apply, SIDs with Read


def _filter_key(g: Gpo) -> FilterKey | None:
    """The SIDs the GPO's security filter depends on; None when it leaves nobody out (any
    token passes) or was not read."""
    if security_filter(g, {EVERYONE, AUTHENTICATED_USERS, THIS_ORGANIZATION}) is not False:
        return None
    read = sd.READ_PROPERTY | sd.GENERIC_READ | sd.GENERIC_ALL
    return (
        frozenset(a.sid for a in g.aces if a.extended_right(sd.APPLY_GROUP_POLICY)),
        frozenset(a.sid for a in g.aces if a.mask & read),
    )


class _ReachBuilder:
    def __init__(self, snap: Snapshot) -> None:
        self.snap = snap
        self.r = _Resolver(snap)
        self.out = Reach()
        users = [
            a for a in snap.accounts if not a.is_computer and a.enabled and not a.managed and a.sid
        ]
        # each account with the OUs above it, worked out once for every tree
        chains: dict[str, list[str]] = {}
        self.placed: dict[str, list[tuple[Account, list[str]]]] = {}
        for side, accounts in (("computer", _computers(snap)), ("user", users)):
            self.placed[side] = []
            for a in accounts:
                parent = a.dn.lower().split(",", 1)[-1]
                if parent not in chains:
                    chains[parent] = containers(a.dn, snap.domain_dn)
                if chains[parent]:
                    self.placed[side].append((a, chains[parent]))
        self.trees: dict[tuple[str, FilterKey | None], _Tree] = {}
        self.ou_dns: dict[str, str] = {}  # as written, for display

    def passes(self, key: FilterKey | None, a: Account) -> bool:
        """security_filter for a key: this runs once per account and filter."""
        if key is None:
            return True
        token = self.r.token(a)
        return not (key[0].isdisjoint(token) or key[1].isdisjoint(token))

    def tree(self, side: str, key: FilterKey | None) -> _Tree:
        found = self.trees.get((side, key))
        if found is not None:
            return found
        tag = ""
        filter_name = ""
        if key is not None:
            text = repr((sorted(key[0]), sorted(key[1])))
            tag = hashlib.sha1(text.encode(), usedforsecurity=False).hexdigest()[:10]
            names = sorted({self.snap.name_of(s) for s in key[0]})
            more = (
                f" +{len(names) - MAX_FILTER_NAMES} more" if len(names) > MAX_FILTER_NAMES else ""
            )
            filter_name = ", ".join(names[:MAX_FILTER_NAMES]) + more
        t = _Tree(side, tag, f"{side}s", filter_name)
        for a, chain in self.placed[side]:
            if self.passes(key, a):
                t.direct.setdefault(chain[0], []).append(a)
                for c in chain:
                    self.ou_dns.setdefault(c, a.dn[-len(c) :])
                for child, parent in itertools.pairwise(chain):
                    t.children.setdefault(parent, set()).add(child)
        self.trees[(side, key)] = t
        return t

    def blocked_below(self, t: _Tree, c: str) -> bool:
        """Any OU strictly below c that blocks inheritance and holds accounts of t."""
        if c not in t.block_below:
            t.block_below[c] = any(
                child in self.r.blocked or self.blocked_below(t, child)
                for child in t.children.get(c, ())
            )
        return t.block_below[c]

    def where(self, c: str) -> str:
        """An OU as a path from the domain head; the head as the domain's name."""
        head = self.snap.domain_dn.lower()
        if c == head:
            return self.snap.domain
        dn = self.ou_dns.get(c, c)[: -len(head) - 1]
        return "/".join(p.split("=", 1)[-1] for p in reversed(RDN_SEPARATOR.split(dn)))

    def name(self, t: _Tree, place: str, enforced: bool) -> str:
        suffix = f" filtered to {t.filter_name}" if t.filter_name else ""
        return f"{t.title} under {place}{' (enforced)' if enforced else ''}{suffix}"

    def scope(self, t: _Tree, c: str, enforced: bool = False) -> str:
        """The scope of a link at c. An enforced link goes through Block Inheritance; it
        needs its own node only where some OU below c blocks."""
        base = f"gpo-scope:{t.side}:{t.tag}:{c}"
        if enforced and self.blocked_below(t, c):
            node = base + ":enforced"
            if node not in self.out.names:
                self.out.names[node] = self.name(t, self.where(c), True)
                self.out.inherits.append((node, self.scope(t, c)))
                for child in sorted(t.children.get(c, ())):
                    if child in self.r.blocked or self.blocked_below(t, child):
                        self.out.inherits.append((node, self.scope(t, child, True)))
            return node
        if base not in self.out.names:
            self.out.names[base] = self.name(t, self.where(c), False)
            self.out.holds += [(base, a) for a in t.direct.get(c, [])]
            for child in sorted(t.children.get(c, ())):
                if child not in self.r.blocked:
                    self.out.inherits.append((base, self.scope(t, child)))
        return base

    def site_scope(self, t: _Tree, key: FilterKey | None, link: GpLink) -> str | None:
        """Domain controllers known to be in the site (the only computers an ordinary user
        can place); Block Inheritance anywhere above a DC stops an unenforced site link."""
        site = link.container.lower()
        node = f"gpo-scope:site:{t.tag}:{site}{':enforced' if link.enforced else ''}"
        if node not in self.out.names:
            dcs = [
                a
                for a, chain in self.placed["computer"]
                if a.is_dc
                and self.snap.dc_sites.get(a.dn.lower(), "").lower() == site
                and self.passes(key, a)
                and (link.enforced or not any(c in self.r.blocked for c in chain))
            ]
            if not dcs:
                return None
            place = RDN_SEPARATOR.split(link.container)[0].split("=", 1)[-1]
            title = f"domain controllers in site {place}"
            suffix = f" filtered to {t.filter_name}" if t.filter_name else ""
            self.out.names[node] = f"{title}{' (enforced)' if link.enforced else ''}{suffix}"
            self.out.holds += [(node, a) for a in dcs]
        return node

    def entry(self, t: _Tree, key: FilterKey | None, link: GpLink) -> str | None:
        """Where a link enters the tree; None when it reaches no account of this side."""
        c = link.container.lower()
        if link.kind == "site":
            if self.snap.site_count > 1:
                return self.site_scope(t, key, link) if t.side == "computer" else None
            # one site: its links act like links above the domain head
            c = self.snap.domain_dn.lower()
            if c in self.r.blocked and not link.enforced:
                return None
        if c not in t.direct and c not in t.children:
            return None
        return self.scope(t, c, link.enforced)

    def build(self) -> Reach:
        for g in self.snap.gpos:
            key = _filter_key(g)
            caveats = _gpo_caveats(g)
            seen: set[str] = set()
            for side, disabled in SIDES:
                if g.flags & disabled:
                    continue
                for link in g.links:
                    if link.enabled:
                        node = self.entry(self.tree(side, key), key, link)
                        if node is not None and node not in seen:
                            seen.add(node)
                            self.out.applies.append((g, node, caveats))
        for a in _dcs(self.snap):
            for g, _ in self.r.linked(a):
                if g.flags & GPO_COMPUTER_DISABLED:
                    continue
                if security_filter(g, self.r.token(a)) is not False:
                    self.out.dc_gpos.add(g.guid.upper())
        return self.out


def reach(snap: Snapshot) -> Reach:
    """Where each GPO reaches, for anyone who can write it.

    Links, Enforced, Block Inheritance, disabled links, the GPO's user and computer side
    flags and security filtering count, as in `_Resolver`. The computer version and the
    client-side extensions do not: a GPO that is empty today is what its writer fills in.
    Disabled accounts and gMSAs process no policy and are left out. With more than one site
    a site link reaches only the domain controllers of that site (see `site_note`).

    Not evaluated: WMI filters (assumed to match, with a caveat), Deny ACEs (as in the
    module docstring), and loopback processing, which brings user settings to users outside
    the GPO's scope. User-side reach assumes the user logs on somewhere.
    """
    return _ReachBuilder(snap).build()


def site_note(snap: Snapshot) -> list[str]:
    """Paths through site links the graph cannot show, for the report's notes."""
    if snap.site_count <= 1:
        return []
    names = sorted(
        {g.name for g in snap.gpos if any(x.kind == "site" and x.enabled for x in g.links)}
    )
    if not names:
        return []
    return [
        "GPOs linked to sites reach member computers and users too, but an ordinary user "
        "cannot place those in a site: the control graph follows these links to domain "
        "controllers only (" + ", ".join(names) + ")"
    ]


def grants(snap: Snapshot) -> list[Grant]:
    return resolve(snap).grants
