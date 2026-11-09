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

Security filtering knows only the groups in the snapshot. A filter that names a group the
snapshot does not hold (another domain's, or one that could not be read) cannot be judged,
so the GPO is assumed to apply, with a caveat and a note naming it.

Approximations, each of which can only over-report:
- WMI filters are assumed to match, and items with item-level targeting are assumed to
  apply (each such grant carries a caveat).
- Deny ACEs are not parsed, so a "Deny Apply" exclusion still counts as applied.
- An ordinary user cannot map member computers to sites; with more than one site every
  site's links are assumed to apply.
- Removals and precedence between GPOs are ignored: the result is the union of additions,
  although a higher-precedence X__Members can remove what a lower one adds.
- A holder of the remote logon right that could not be resolved to a SID is assumed to
  cover the member (with a caveat).

Registry policy is the exception to the precedence point: `RegistryView` plays each GPO's
Registry.pol in processing order and gives the effective value per computer. There a GPO that
may not apply (a caveat above) leaves the result undecided instead of being assumed to apply.
The same machinery plays audit.csv per subcategory, and Registry.xml after every Registry.pol:
Windows always runs the Registry extension first and the Preferences extensions later.
"""

from __future__ import annotations

import dataclasses
import hashlib
import itertools
import re
from dataclasses import dataclass, field

from . import auditpol, regpol, sd
from .model import (
    WELL_KNOWN_RIDS,
    Account,
    DirObject,
    GpLink,
    Gpo,
    GpoLocalGroup,
    RegistryEntry,
    Snapshot,
    well_known_sid,
)

CSE_SECURITY = "{827D319E-6EAC-11D2-A4EA-00C04F79F83A}"  # Restricted Groups, user rights
CSE_GROUPS = "{17D89FEC-5C44-4972-B12D-241CAEF74509}"  # GPP Local Users and Groups
CSE_REGISTRY = "{35378EAC-683F-11D2-A89A-00C04FBBCFA2}"  # Registry.pol (Administrative Templates)
CSE_AUDIT = "{F3CCC681-B74C-4060-9F26-CD84525DCA2A}"  # audit.csv ([MS-GPAC])
CSE_GPP_REGISTRY = "{B087BE9D-ED37-454F-AF9C-04291E351182}"  # Preferences Registry.xml
CSE_OF_SOURCE = {
    "restricted": CSE_SECURITY,
    "gpp": CSE_GROUPS,
    "registry": CSE_REGISTRY,
    "audit": CSE_AUDIT,
    "gpp_registry": CSE_GPP_REGISTRY,
}
GPO_USER_DISABLED = 0x1
GPO_COMPUTER_DISABLED = 0x2
SIDES = (("computer", GPO_COMPUTER_DISABLED), ("user", GPO_USER_DISABLED))

EVERYONE = "S-1-1-0"
AUTHENTICATED_USERS = "S-1-5-11"
THIS_ORGANIZATION = "S-1-5-15"
ANYONE_SIDS = frozenset({EVERYONE, AUTHENTICATED_USERS, THIS_ORGANIZATION})
LOCAL_ADMIN_CAVEAT = "assumes Domain Admins is in the local Administrators"
ENTERPRISE_DCS = "S-1-5-9"
INTERACTIVE = "S-1-5-4"
ADMINISTRATORS = "S-1-5-32-544"
RDP_USERS = "S-1-5-32-555"
REMOTE_LOGON_RIGHT = "SeRemoteInteractiveLogonRight"
DENY_LOGON_RIGHTS = (
    "SeDenyInteractiveLogonRight",
    "SeDenyRemoteInteractiveLogonRight",
    "SeDenyBatchLogonRight",
    "SeDenyServiceLogonRight",
)
USER_RIGHTS_KEY = "GptTmpl\\Privilege Rights"  # not a registry path: names the store in a layer
# a comma that ends an RDN: not escaped, i.e. after an even number of backslashes
RDN_SEPARATOR = re.compile(r"(?<!\\)(?:\\\\)*,")
ILT_CAVEAT = "item-level targeting not evaluated"
FILTER_CAVEAT = "filter group not in this snapshot"
SITE_CAVEAT = "site membership assumed"
SOFT_CAVEAT = "set only where no value exists"
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


READ_RIGHTS = sd.READ_PROPERTY | sd.GENERIC_READ | sd.GENERIC_ALL


def security_filter(gpo: Gpo, token: set[str]) -> bool | None:
    """Whether the token may read and apply the GPO; None when its DACL was not read.

    Read and Apply may come from different ACEs. AD stores mapped rights, so READ_PROPERTY
    is the real test; the generic bits are accepted for hand-made descriptors.
    """
    if not gpo.aces:
        return None
    apply = any(a.sid in token and a.extended_right(sd.APPLY_GROUP_POLICY) for a in gpo.aces)
    return apply and any(a.sid in token and a.mask & READ_RIGHTS for a in gpo.aces)


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
        self._known = {o.sid for o in snap.objects if o.sid} | {a.sid for a in snap.accounts}
        self._unresolved: dict[str, set[str]] = {}
        self._ordered: dict[str, list[tuple[GpLink, Gpo]]] | None = None

    def unresolved(self, g: Gpo) -> set[str]:
        """SIDs in the GPO's filter whose members the snapshot cannot show: nobody can say
        which tokens hold them."""
        known = self._unresolved.get(g.guid)
        if known is not None:
            return known
        prefix = self.snap.domain_sid + "-"
        found = {
            a.sid
            for a in g.aces
            if (a.mask & READ_RIGHTS or a.extended_right(sd.APPLY_GROUP_POLICY))
            and a.sid.startswith("S-1-5-21-")
            and a.sid not in self._known
            and a.sid.removeprefix(prefix) not in WELL_KNOWN_RIDS
        }
        self._unresolved[g.guid] = found
        return found

    def filtered(self, g: Gpo, a: Account) -> tuple[bool, tuple[str, ...]]:
        """Whether the GPO's filter lets the account through, and the caveat if that is only
        assumed. An unread DACL passes too; `_gpo_caveats` reports that one."""
        token = self.token(a)
        result = security_filter(g, token)
        if result is not False:
            return True, ()
        unknown = self.unresolved(g)
        if unknown and security_filter(g, token | unknown):
            return True, (FILTER_CAVEAT,)
        return False, ()

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
                caveats = () if single else (SITE_CAVEAT,)
            if g.guid.upper() not in found or not caveats:
                found[g.guid.upper()] = (g, caveats)
        return list(found.values())

    def _links_in_order(self, container: str) -> list[tuple[GpLink, Gpo]]:
        """The enabled links of a container with their GPOs, in gPLink order."""
        if self._ordered is None:
            self._ordered = {}
            for g in self.snap.gpos:
                for link in g.links:
                    self._ordered.setdefault(link.container.lower(), []).append((link, g))
            for links in self._ordered.values():
                links.sort(key=lambda item: item[0].index)
        return [(link, g) for link, g in self._ordered.get(container, []) if link.enabled]

    def processing_order(self, a: Account) -> list[tuple[Gpo, tuple[str, ...]]]:
        """The GPOs linked where they reach this computer, in the order Windows applies them:
        whatever comes later overwrites what came before.

        Not enforced: site, domain, then OUs from the top down, stopping at Block Inheritance.
        Enforced: after all of those, from the computer's own OU up to the site, so that the
        highest one wins ([MS-GPOL] GPO Search and GPO Processing Order). Within one container
        the gPLink value is applied left to right: a new link is inserted at the front and has
        the lowest precedence, so the rightmost entry is link order 1 and goes last ("Group
        Policy scope in Windows", New-GPLink -Order, and the lab's gPLink values; the wording of
        [MS-GPOL] GPO Search reads the other way round for links that are not enforced).

        The same computers and caveats as `linked`; a site link's caveat is its own.
        """
        plain: list[tuple[Gpo, tuple[str, ...]]] = []
        enforced: list[tuple[Gpo, tuple[str, ...]]] = []
        blocked = False
        for c in containers(a.dn, self.snap.domain_dn):
            links = self._links_in_order(c)
            enforced += [(g, ()) for x, g in links if x.enforced]
            if not blocked:
                plain = [(g, ()) for x, g in links if not x.enforced] + plain
            if c in self.blocked:
                blocked = True
        site = self.snap.dc_sites.get(a.dn.lower(), "").lower() if a.is_dc else ""
        caveats: tuple[str, ...] = () if site or self.snap.site_count <= 1 else (SITE_CAVEAT,)
        site_plain: list[tuple[Gpo, tuple[str, ...]]] = []
        for container in sorted({c for c, _, _, _ in self.site_links}):
            if site and container != site:
                continue
            links = self._links_in_order(container)
            enforced += [(g, caveats) for x, g in links if x.enforced]
            if not blocked:
                site_plain += [(g, caveats) for x, g in links if not x.enforced]
        return site_plain + plain + enforced

    def token(self, a: Account) -> set[str]:
        """SIDs in the account's token: its own, the well-known ones, the primary group
        and every group that holds any of them, through nesting and through the
        foreignSecurityPrincipal objects that stand for well-known SIDs."""
        known = self._tokens.get(a.dn.lower())
        if known is not None:
            return known
        dom = self.snap.domain_sid
        sids = {a.sid, *ANYONE_SIDS}
        sids.add(f"{dom}-{a.primary_group or (515 if a.is_computer else 513)}")
        if a.is_dc:
            sids |= {ENTERPRISE_DCS, f"{dom}-{521 if a.is_rodc else 516}"}
        sids.discard("")
        head = self.snap.domain_dn.lower()
        todo = [a.dn.lower()]
        todo += [
            self.sid_dn.get(s, f"cn={s.lower()},cn=foreignsecurityprincipals,{head}") for s in sids
        ]
        self._add_holders(todo, sids)
        self._tokens[a.dn.lower()] = sids
        return sids

    def _add_holders(self, todo: list[str], sids: set[str]) -> None:
        """Add the SID of every group that holds one of these DNs, through nesting."""
        seen = set(todo)
        while todo:
            for group in self.member_of.get(todo.pop(), []):
                key = group.dn.lower()
                if key not in seen:
                    seen.add(key)
                    if group.sid:
                        sids.add(group.sid)
                    todo.append(key)

    def nested_in(self, dn: str, sid: str) -> set[str]:
        """The SID of a group and of every group that holds it."""
        sids = {sid} - {""}
        self._add_holders([dn.lower()], sids)
        return sids

    def applied(self, a: Account, source: str) -> list[tuple[Gpo, tuple[str, ...]]]:
        """GPOs whose settings of this kind Windows would process on the computer."""
        out = []
        for g, caveats in self.linked(a):
            if not computer_side_applies(g, source):
                continue
            passes, assumed = self.filtered(g, a)
            if passes:
                out.append((g, caveats + assumed + _gpo_caveats(g)))
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


@dataclass(frozen=True)
class Outcome:
    """One value a registry setting can end up with."""

    present: bool  # False: Group Policy leaves no value there
    data: int | str | list[str] | None = None
    gpo: str = ""  # the GPO that decided this; "" when no GPO touches the setting
    caveats: tuple[str, ...] = ()
    unknown: bool = False  # a GPO that could not be read comes in here


NOT_SET = Outcome(False)


@dataclass(frozen=True)
class Effective:
    """What Group Policy leaves in one registry value on one computer.

    A value Group Policy leaves absent says nothing about the computer: its own registry
    or local policy may hold anything.
    """

    outcomes: tuple[Outcome, ...]

    @property
    def decided(self) -> bool:
        return len(self.outcomes) == 1 and not self.outcomes[0].unknown

    @property
    def present(self) -> bool:
        return self.decided and self.outcomes[0].present

    @property
    def value(self) -> int | str | list[str] | None:
        return self.outcomes[0].data if self.present else None

    @property
    def gpo(self) -> str:
        return self.outcomes[0].gpo if self.decided else ""

    @property
    def why(self) -> list[str]:
        """Why this could not be decided, or what the decided value depends on."""
        return sorted({c for o in self.outcomes for c in o.caveats})


@dataclass(frozen=True)
class _Layer:
    gpo: Gpo
    caveats: tuple[str, ...]  # any caveat means the GPO may not apply here
    entries: tuple[RegistryEntry, ...] | None  # None: the file could not be read
    file: str = "Registry.pol"


_HARDENED = regpol.norm(regpol.HARDENED_KEY)


def _value_name(key: str, name: str) -> str:
    """A value name for comparing, under a compared key. A hardened path is one value with or
    without its trailing backslash, as `regpol.watched` accepts it."""
    return (name.strip().rstrip("\\") if key == _HARDENED else name).casefold()


def _concerns(entry: RegistryEntry, key: str, name: str) -> bool:
    k = regpol.norm(entry.key)
    if entry.action == "delete_key":
        return key == k or key.startswith(k + "\\")
    if k != key:
        return False
    return entry.action == "delete_all" or _value_name(key, entry.name) == name


def _after(start: Outcome, entries: list[RegistryEntry], layer: _Layer) -> Outcome:
    current = start
    for e in entries:
        if e.action == "set":
            current = Outcome(True, e.data, layer.gpo.name, layer.caveats)
        elif e.action == "soft":
            if not current.present and not current.unknown:
                caveats = (*layer.caveats, SOFT_CAVEAT)
                current = Outcome(True, e.data, layer.gpo.name, caveats)
        else:
            current = Outcome(False, None, layer.gpo.name, layer.caveats)
    return current


def _distinct(outcomes: list[Outcome]) -> tuple[Outcome, ...]:
    seen: dict[tuple[bool, bool, str], Outcome] = {}
    for o in outcomes:
        seen.setdefault((o.unknown, o.present, repr(o.data)), o)
    return tuple(seen.values())


def effective_value(layers: tuple[_Layer, ...], key: str, name: str) -> Effective:
    """Plays the GPOs in processing order over one value. A GPO that may not apply adds its
    result to what is possible and takes nothing away; one that surely applies replaces it."""
    state: tuple[Outcome, ...] = (NOT_SET,)
    wanted = regpol.norm(key)
    wanted_name = _value_name(wanted, name)
    for layer in layers:
        if layer.entries is None:
            unread = (f"{layer.file} of {layer.gpo.name} not readable",)
            state = _distinct([*state, Outcome(False, None, layer.gpo.name, unread, True)])
            continue
        entries = [e for e in layer.entries if _concerns(e, wanted, wanted_name)]
        if not entries:
            continue
        after = [_after(o, entries, layer) for o in state]
        state = _distinct([*state, *after] if layer.caveats else after)
    return Effective(state)


class RegistryView:
    """Effective registry policy per computer, computed once per distinct set of GPOs."""

    def __init__(self, snap: Snapshot) -> None:
        self.snap = snap
        self.r = _Resolver(snap)
        self._layers: dict[tuple[str, str], tuple[_Layer, ...]] = {}
        self._memo: dict[tuple[object, ...], Effective] = {}
        self._rights: dict[str, list[RegistryEntry]] | None = None

    def targets(self) -> list[Account]:
        """Computers that process Windows Group Policy. A computer object with no operating
        system recorded is pre-staged or a cluster name, not a host; DCs count regardless. A
        Hyper-V Server records no 'Windows' in its name and processes Group Policy all the same."""

        def windows(a: Account) -> bool:
            name = (a.os or "").lower()
            return "windows" in name or "hyper-v" in name or (a.is_registered_dc and not a.os)

        return [
            a
            for a in _computers(self.snap)
            if not a.entra_kerberos and a.sam.upper() != "AZUREADSSOACC$" and windows(a)
        ]

    def _source_layers(
        self, a: Account, source: str, store: dict[str, list[RegistryEntry]], file: str
    ) -> tuple[_Layer, ...]:
        """The GPOs with this kind of settings that reach the computer, in processing order."""
        found = self._layers.get((source, a.dn.lower()))
        if found is not None:
            return found
        out = []
        for g, caveats in self.r.processing_order(a):
            if not computer_side_applies(g, source):
                continue
            entries = store.get(g.guid)
            if entries is not None and not entries:
                continue  # read, nothing the checks care about
            passes, assumed = self.r.filtered(g, a)
            if passes:
                layer = _Layer(
                    g,
                    caveats + assumed + _gpo_caveats(g),
                    tuple(entries) if entries is not None else None,
                    file,
                )
                out.append(layer)
        self._layers[(source, a.dn.lower())] = tuple(out)
        return self._layers[(source, a.dn.lower())]

    def layers(self, a: Account) -> tuple[_Layer, ...]:
        """The GPOs with registry policy that reach this computer, in processing order."""
        return self._source_layers(a, "registry", self.snap.gpo_registry, "Registry.pol")

    def preference_layers(self, a: Account) -> tuple[_Layer, ...]:
        """Registry.xml in processing order. An item behind item-level targeting may not apply,
        so a run of them becomes a layer of its own with that caveat."""
        out: list[_Layer] = []
        source = self._source_layers(a, "gpp_registry", self.snap.gpo_preferences, "Registry.xml")
        for layer in source:
            if layer.entries is None:
                out.append(layer)
                continue
            for filtered, run in itertools.groupby(layer.entries, key=lambda e: e.filtered):
                caveats = (*layer.caveats, ILT_CAVEAT) if filtered else layer.caveats
                out.append(_Layer(layer.gpo, caveats, tuple(run), layer.file))
        return tuple(out)

    def value(self, a: Account, key: str, name: str) -> Effective:
        """What Registry.pol alone leaves in a value."""
        return self._played("pol", self.layers(a), key, name)

    def merged(self, a: Account, key: str, name: str) -> Effective:
        """What Registry.pol and then Registry.xml leave in a value."""
        return self._played("all", self.layers(a) + self.preference_layers(a), key, name)

    def audit(self, a: Account, subcategory: str) -> Effective:
        """What audit.csv leaves for one subcategory GUID (lower case)."""
        layers = self._source_layers(a, "audit", self.snap.gpo_audit, "audit.csv")
        return self._played("audit", layers, auditpol.KEY, subcategory)

    def basic_audit(self, a: Account) -> dict[str, bool]:
        """[Event Audit] categories GPOs set on this computer, played in processing order: True
        when one audits something, False when the value left is 0, no auditing. A GPO that may
        not apply can add a category to what is possible and takes nothing away."""
        found: dict[str, bool] = {}
        for g, caveats in self.r.processing_order(a):
            settings = self.snap.gpo_settings.get(g.guid)
            if settings is None or not computer_side_applies(g, "restricted"):
                continue
            passes, assumed = self.r.filtered(g, a)
            if not passes:
                continue
            found.update(dict.fromkeys(settings.audit_categories, True))
            for category in settings.audit_off:
                if not (caveats or assumed or _gpo_caveats(g)):
                    found[category] = False
                else:
                    found.setdefault(category, False)
        return found

    def user_right(self, a: Account, right: str) -> Effective:
        """What the GPOs' security templates leave in one user right. Windows does not merge a
        right across GPOs: the one applied last that defines it decides the whole list."""
        if self._rights is None:
            self._rights = {
                guid: [
                    RegistryEntry(USER_RIGHTS_KEY, name, "set", data=holders)
                    for name, holders in s.privileges.items()
                    if name in DENY_LOGON_RIGHTS
                ]
                for guid, s in self.snap.gpo_settings.items()
            }
        layers = self._source_layers(a, "restricted", self._rights, "GptTmpl.inf")
        return self._played("rights", layers, USER_RIGHTS_KEY, right)

    def _played(self, kind: str, layers: tuple[_Layer, ...], key: str, name: str) -> Effective:
        memo = (kind, key, name, *[(x.gpo.guid, x.caveats) for x in layers])
        found = self._memo.get(memo)
        if found is None:
            found = effective_value(layers, key, name)
            self._memo[memo] = found
        return found

    def names(self, a: Account, key: str) -> list[str]:
        """Value names any GPO reaching the computer sets under this key."""
        wanted = regpol.norm(key)
        out: dict[str, str] = {}
        for layer in self.layers(a):
            for e in layer.entries or ():
                if e.action in ("set", "soft") and regpol.norm(e.key) == wanted:
                    out.setdefault(e.name.casefold(), e.name)
        return list(out.values())


def logon_rights_view(snap: Snapshot) -> RegistryView | None:
    """None when the deny logon rights were not collected: the check then does not judge."""
    return RegistryView(snap) if snap.logon_rights_collected else None


Resolver = _Resolver


def member_computer_token(token: set[str], domain_sid: str) -> set[str]:
    """A domain token as a member computer sees it. There S-1-5-32-* names the computer's own
    groups, so what the domain's Builtin groups hold says nothing about them. Joining the
    domain puts Domain Admins in the local Administrators and Domain Users in the local Users
    (Microsoft's default groups); Enterprise Admins and the members of the domain's
    Administrators are not added. That default is all that can be seen from here, the same
    assumption as LOCAL_ADMIN_CAVEAT."""
    out = {sid for sid in token if not sid.startswith("S-1-5-32-")}
    if f"{domain_sid}-512" in token:
        out.add("S-1-5-32-544")
    if f"{domain_sid}-513" in token:
        out.add("S-1-5-32-545")
    return out


def denied_accounts(
    effective: Effective, tokens: dict[str, set[str]]
) -> tuple[bool | None, list[str]]:
    """Whether what a right can end up holding denies every account in `tokens` (name -> SIDs in
    its token), and who is left out. None: it depends on something that cannot be decided, or
    on a name that could not be resolved to a SID."""
    states: set[bool | None] = set()
    left: set[str] = set()
    for o in effective.outcomes:
        if o.unknown:
            states.add(None)
        elif not o.present or not isinstance(o.data, list):
            states.add(False)
            left |= tokens.keys()
        else:
            holders = {_holder(h) for h in o.data}
            missed = {name for name, token in tokens.items() if not holders & token}
            if missed and any(not h.startswith("S-1-") for h in holders):
                states.add(None)
            else:
                states.add(not missed)
                left |= missed
    if len(states) == 1:
        state = states.pop()
        return state, sorted(left) if state is False else []
    return None, []


def registry_view(snap: Snapshot) -> RegistryView | None:
    """None when registry policy was not collected: the checks then do not judge."""
    return RegistryView(snap) if snap.registry_policy_collected else None


def policy_view(snap: Snapshot) -> RegistryView | None:
    """None when audit.csv and Registry.xml were not collected: those checks do not judge."""
    return RegistryView(snap) if snap.policy_files_collected else None


def unread_policy_gpos(snap: Snapshot) -> list[Gpo]:
    """GPOs Windows would process whose audit.csv or Registry.xml is not in the snapshot."""
    missing = []
    for g in snap.gpos:
        no_audit = g.guid not in snap.gpo_audit and computer_side_applies(g, "audit")
        no_xml = g.guid not in snap.gpo_preferences and computer_side_applies(g, "gpp_registry")
        if no_audit or no_xml:
            missing.append(g)
    return missing


def unread_registry_gpos(snap: Snapshot) -> list[Gpo]:
    """GPOs Windows would process whose Registry.pol is not in the snapshot."""
    return [
        g
        for g in snap.gpos
        if g.guid not in snap.gpo_registry and computer_side_applies(g, "registry")
    ]


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
    OU or the domain head that pass one security filter, and filters that pass the same
    accounts share their nodes. So the graph grows with accounts, OUs, links and the different
    sets of accounts filters let through, not with GPOs times accounts: GPO -> scope of each
    linked OU -> scope of each child OU the GPO is inherited by -> the accounts held there.

    Scopes are separate from OU nodes: an OU's contains edges mean ACL inheritance, which
    also leads to groups and through Block Inheritance, where Group Policy does not go.
    """

    names: dict[str, str] = field(default_factory=dict)  # scope ID -> display name
    applies: list[tuple[Gpo, str, tuple[str, ...]]] = field(default_factory=list)
    inherits: list[tuple[str, str]] = field(default_factory=list)
    holds: list[tuple[str, Account]] = field(default_factory=list)
    # upper-case GUID -> caveats, for GPOs that reach a writable DC
    dc_gpos: dict[str, tuple[str, ...]] = field(default_factory=dict)
    # for whoever can rewrite a filtered GPO's DACL: GUID -> where it goes with no filter
    widened: dict[str, list[tuple[str, tuple[str, ...]]]] = field(default_factory=dict)
    dc_widened: set[str] = field(default_factory=set)  # GUIDs a filter keeps away from the DCs
    # (GUID, scope ID) -> lower-cased containers of the links that enter there, for what-if
    entered_by: dict[tuple[str, str], list[str]] = field(default_factory=dict)


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
    return (
        frozenset(a.sid for a in g.aces if a.extended_right(sd.APPLY_GROUP_POLICY)),
        frozenset(a.sid for a in g.aces if a.mask & READ_RIGHTS),
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
        self.ou_dns: dict[str, str] = {}  # as written, for display
        self.placed: dict[str, list[tuple[Account, list[str]]]] = {}
        for side, accounts in (("computer", _computers(snap)), ("user", users)):
            self.placed[side] = []
            for a in accounts:
                key = a.dn.lower()
                comma = RDN_SEPARATOR.search(key)
                parent = key[comma.end() :] if comma else ""
                if parent not in chains:
                    chains[parent] = containers(a.dn, snap.domain_dn)
                    # by separator: lower() can change a name's length (dotted capital I)
                    for sep in RDN_SEPARATOR.finditer(a.dn):
                        above = a.dn[sep.end() :]
                        self.ou_dns.setdefault(above.lower(), above)
                if chains[parent]:
                    self.placed[side].append((a, chains[parent]))
        self.trees: dict[tuple[str, FilterKey | None], _Tree] = {}
        self.populations: dict[tuple[str, bytes], _Tree] = {}
        self.site_assumed: set[str] = set()  # site scopes holding a DC of unknown site
        self._computer_sids: set[str] | None = None

    def filter_of(self, g: Gpo) -> tuple[FilterKey | None, tuple[str, ...]]:
        """The GPO's filter, with a SID nobody can place standing for "anyone": a side of
        the filter that names one cannot be said to leave anybody out."""
        key = _filter_key(g)
        unknown = self.r.unresolved(g)
        if key is None or not unknown:
            return key, ()
        anyone = frozenset({EVERYONE})
        apply = key[0] if key[0].isdisjoint(unknown) else anyone
        read = key[1] if key[1].isdisjoint(unknown) else anyone
        if (apply, read) == key:
            return key, ()
        return (None if apply == read == anyone else (apply, read)), (FILTER_CAVEAT,)

    def computers_read(self, key: FilterKey | None) -> bool:
        """Since MS16-072 Windows fetches user policy as the computer, so a GPO only some
        users may read stays unapplied unless some computer can read it too."""
        if key is None:
            return True
        if self._computer_sids is None:
            self._computer_sids = {EVERYONE, AUTHENTICATED_USERS, THIS_ORGANIZATION}
            self._computer_sids.add(f"{self.snap.domain_sid}-515")
            for a, _ in self.placed["computer"]:
                self._computer_sids |= self.r.token(a)
        return not key[1].isdisjoint(self._computer_sids)

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
        placed = self.placed[side]
        passing = placed if key is None else [p for p in placed if self.passes(key, p[0])]
        population = b""
        if key is not None:
            # filters that differ in a group nobody here is in need no tree of their own
            text = "\0".join(a.sid for a, _ in passing)
            population = hashlib.sha1(text.encode(), usedforsecurity=False).digest()
            shared = (
                self.tree(side, None)
                if len(passing) == len(placed)
                else self.populations.get((side, population))
            )
            if shared is not None:
                self.trees[(side, key)] = shared
                return shared
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
        for a, chain in passing:
            t.direct.setdefault(chain[0], []).append(a)
            for child, parent in itertools.pairwise(chain):
                t.children.setdefault(parent, set()).add(child)
        self.trees[(side, key)] = t
        if key is not None:
            self.populations[(side, population)] = t
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
        """Domain controllers in the site (the only computers an ordinary user can place),
        and DCs whose site is unknown, as in `_Resolver.linked`; Block Inheritance anywhere
        above a DC stops an unenforced site link."""
        site = link.container.lower()
        node = f"gpo-scope:site:{t.tag}:{site}{':enforced' if link.enforced else ''}"
        if node not in self.out.names:
            dcs = [
                a
                for a, chain in self.placed["computer"]
                if a.is_dc
                and self.snap.dc_sites.get(a.dn.lower(), "").lower() in (site, "")
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
            if any(a.dn.lower() not in self.snap.dc_sites for a in dcs):
                self.site_assumed.add(node)
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
            key, assumed = self.filter_of(g)
            caveats = assumed + _gpo_caveats(g)
            seen: set[str] = set()
            for side, disabled in SIDES:
                off = _side_off(g, side, disabled)
                for link in g.links:
                    if not link.enabled:
                        continue
                    if side == "computer" or self.computers_read(key):
                        node = self.entry(self.tree(side, key), key, link)
                        if node is not None:
                            where = self.out.entered_by.setdefault((g.guid.upper(), node), [])
                            if link.container.lower() not in where:
                                where.append(link.container.lower())
                        if node is not None and node not in seen:
                            seen.add(node)
                            site = (SITE_CAVEAT,) if node in self.site_assumed else ()
                            self.out.applies.append((g, node, caveats + off + site))
                    if key is not None:
                        wide = self.entry(self.tree(side, None), None, link)
                        scopes = self.out.widened.setdefault(g.guid.upper(), [])
                        if wide is not None and wide not in [s for s, _ in scopes]:
                            scopes.append((wide, off))
        # an RODC cannot write the domain: it is reached through its own scope, not this way
        for a in _dcs(self.snap):
            if a.is_rodc:
                continue
            for g, _ in self.r.linked(a):
                guid = g.guid.upper()
                passes, assumed = self.r.filtered(g, a)
                if not passes:
                    self.out.dc_widened.add(guid)
                elif guid not in self.out.dc_gpos or not assumed:
                    off = _side_off(g, "computer", GPO_COMPUTER_DISABLED)
                    self.out.dc_gpos[guid] = assumed + _gpo_caveats(g) + off
        self.out.dc_widened -= self.out.dc_gpos.keys()
        return self.out


def _side_off(g: Gpo, side: str, disabled: int) -> tuple[str, ...]:
    return (f"{side} side disabled, the writer can enable it",) if g.flags & disabled else ()


def reach(snap: Snapshot) -> Reach:
    """Where each GPO reaches, for anyone who can write it.

    Links, Enforced, Block Inheritance, disabled links and security filtering count, as in
    `_Resolver`: a GPO's writer cannot change the first four, which sit on the OU. What sits
    on the GPO does not limit its writer. The computer version and the client-side
    extensions do not count, because a GPO that is empty today is what its writer fills in,
    and the status flags do not, because the writer can flip them; a disabled side stays in
    with a caveat. A filter stops a writer of values but not one who can rewrite the DACL,
    so `widened` lists where the GPO goes without it. User-side reach also needs some
    computer to be able to read the GPO (see `computers_read`).

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


def filter_note(snap: Snapshot) -> list[str]:
    """GPOs assumed to apply because their filter names a group the snapshot does not hold."""
    r = _Resolver(snap)
    names = sorted({g.name for g in snap.gpos if _filter_key(g) and r.unresolved(g)})
    if not names:
        return []
    return [
        "security filters of these GPOs name a group this snapshot does not hold (another "
        "domain's, or one not readable), so the GPOs are assumed to apply: " + ", ".join(names)
    ]


def grants(snap: Snapshot) -> list[Grant]:
    return resolve(snap).grants
