"""RC4 readiness, faked pwdLastSet, CA audit filter, Onelogon, unreadable tier-0 members."""

from __future__ import annotations

import json
from datetime import timedelta
from typing import Any

import pytest
from ldap3.core.exceptions import LDAPNoSuchObjectResult

from ad_doctor import collect, fixes, gpo_scope, probes, redact, report, sd, sysvol, winreg
from ad_doctor.checks import run_all
from ad_doctor.collect import Collector
from ad_doctor.model import (
    UAC,
    Account,
    CaConfig,
    DirObject,
    GpLink,
    GpoSettings,
    Severity,
    Snapshot,
    UnreadableMember,
)

from .test_checks import NOW, computer, ids, only, snapshot, user
from .test_round5 import CA_HOST, POLICY, FakeRegistry, _snap, _tree, ca
from .test_round6 import HEAD, SID, gpo

CUTOVER = NOW - timedelta(days=4000)
OLD = CUTOVER - timedelta(days=100)
DOMAIN = "DC=lab,DC=test"
CONFIG = "CN=Configuration,DC=lab,DC=test"
SPN = ["HTTP/app.lab.test"]
DC_UAC = 0x2000 | UAC.TRUSTED_FOR_DELEGATION
KEPT = "svc_old: no AES in msDS-SupportedEncryptionTypes (0x4)"


# --- item 4: AD-KRB-005, RC4 readiness --------------------------------------------------


def test_explicit_rc4_only_is_medium_and_keeps_its_fingerprint() -> None:
    f = only(snapshot(user("svc_old", spns=SPN, enc_types=0x4)), "AD-KRB-005")
    assert f.severity is Severity.MEDIUM
    assert f.objects == [KEPT]
    assert f.key(KEPT) == "svc_old"
    assert report.fingerprint(f.check_id, f.key(KEPT)) == report.fingerprint(f.check_id, "svc_old")
    assert "reads configuration, not keys" in f.detail
    assert "honoured" in f.detail


def test_microsofts_0x24_counts_as_rc4_only() -> None:
    f = only(snapshot(user("svc_a", spns=SPN, enc_types=0x24)), "AD-KRB-005")
    assert f.objects == ["svc_a: no AES in msDS-SupportedEncryptionTypes (0x24)"]


@pytest.mark.parametrize("value", [None, 0])
def test_no_value_relies_on_the_default_and_is_low(value: int | None) -> None:
    f = only(snapshot(user("svc_a", spns=SPN, enc_types=value)), "AD-KRB-005")
    assert f.severity is Severity.LOW
    assert f.objects == ["svc_a: no value set, the domain default applies"]
    assert "KDC default" in f.detail
    assert "honoured" not in f.detail


def test_a_value_with_aes_and_accounts_without_spn_stay_silent() -> None:
    snap = snapshot(
        user("svc_a", spns=SPN, enc_types=0x18),
        user("svc_b", spns=SPN, enc_types=0x1C),
        user("plain"),
        computer("WS01"),
    )
    assert "AD-KRB-005" not in ids(run_all(snap))


def test_a_computer_with_an_spn_and_no_value_is_counted() -> None:
    f = only(snapshot(computer("NAS01", spns=SPN)), "AD-KRB-005")
    assert f.objects == [
        "1 computer(s) with an SPN: no value set, the domain default applies (NAS01$)"
    ]


def test_managed_and_disabled_accounts_are_skipped() -> None:
    snap = snapshot(
        user("gmsa$", spns=SPN, enc_types=0x4, managed=True),
        user("gone", 0x200 | UAC.ACCOUNTDISABLE, spns=SPN, enc_types=0x4),
    )
    assert "AD-KRB-005" not in ids(run_all(snap))


def test_password_older_than_the_cutover_is_suspected_of_no_aes_keys() -> None:
    old = user("svc_a", spns=SPN, enc_types=0x18, pwd_last_set=OLD)
    f = only(snapshot(old, aes_cutover=CUTOVER), "AD-KRB-005")
    assert f.severity is Severity.MEDIUM
    assert "suspected no AES keys" in f.objects[0]
    assert "probably never turned into AES keys" in f.detail


def test_old_password_and_no_value_are_one_line_per_account() -> None:
    old = user("svc_a", spns=SPN, pwd_last_set=OLD)
    f = only(snapshot(old, aes_cutover=CUTOVER), "AD-KRB-005")
    assert len(f.objects) == 1
    assert f.objects[0].startswith("svc_a: no value set, the domain default applies; suspected")
    assert f.severity is Severity.MEDIUM
    assert f.key(f.objects[0]) == "svc_a"


def test_cutover_margin_covers_accounts_made_with_the_domain() -> None:
    close = user("svc_a", spns=SPN, enc_types=0x18, pwd_last_set=CUTOVER - timedelta(minutes=30))
    assert "AD-KRB-005" not in ids(run_all(snapshot(close, aes_cutover=CUTOVER)))


def test_without_a_cutover_the_password_part_is_not_judged() -> None:
    old = user("svc_a", spns=SPN, enc_types=0x18, pwd_last_set=OLD)
    assert "AD-KRB-005" not in ids(run_all(snapshot(old)))


def test_no_pwd_last_set_falls_back_on_when_created() -> None:
    old = user("svc_a", spns=SPN, enc_types=0x18, pwd_last_set=None, when_created=OLD)
    assert "suspected" in only(snapshot(old, aes_cutover=CUTOVER), "AD-KRB-005").objects[0]


def test_faked_pwd_last_set_does_not_hide_an_old_password() -> None:
    faked = user("svc_a", spns=SPN, enc_types=0x18, pwd_changed=OLD)
    assert "suspected" in only(snapshot(faked, aes_cutover=CUTOVER), "AD-KRB-005").objects[0]


def test_krbtgt_is_judged_on_its_password_only_although_disabled() -> None:
    snap = snapshot(aes_cutover=CUTOVER)
    snap.accounts[0].pwd_last_set = OLD
    f = only(snap, "AD-KRB-005")
    assert f.objects[0].startswith("krbtgt: suspected no AES keys")
    assert f.severity is Severity.MEDIUM


def test_dc_encryption_types() -> None:
    snap = snapshot(
        computer("DC02", DC_UAC, spns=SPN, enc_types=0x4),
        computer("DC03", DC_UAC, spns=SPN),
        computer("DC04", DC_UAC, spns=SPN, enc_types=0x1C),
    )
    f = only(snap, "AD-KRB-005")
    assert f.objects == [
        "DC02$: DC, no AES in msDS-SupportedEncryptionTypes (0x4)",
        "DC03$: DC, no value set, the domain default applies",
    ]
    assert f.severity is Severity.MEDIUM


def test_fix_script_only_changes_explicit_user_values() -> None:
    snap = snapshot(
        user("svc_old", spns=SPN, enc_types=0x4),
        user("svc_new", spns=SPN),
        computer("DC02", DC_UAC, spns=SPN, enc_types=0x4),
    )
    lines = fixes.snippet(only(snap, "AD-KRB-005"), snap)
    assert "Set-ADUser 'svc_old' -KerberosEncryptionType AES128,AES256 -WhatIf" in lines
    assert sum(not line.startswith("#") for line in lines) == 1


# --- item 6: pwdLastSet against replication metadata ------------------------------------


def faked(sam: str = "adm", **kw: object) -> Account:
    changed = NOW - timedelta(days=500)
    return user(sam, pwd_last_set=NOW - timedelta(days=1), pwd_changed=changed, **kw)


def test_faked_pwd_last_set_on_a_tier0_user_is_medium() -> None:
    f = only(snapshot(faked()), "AD-ACC-012")
    assert f.severity is Severity.MEDIUM
    assert f.objects == ["adm (pwdLastSet 2026-10-31, written 2025-06-19)"]
    assert f.key(f.objects[0]) == "adm"


def test_faked_krbtgt_is_high_and_fails_the_age_check() -> None:
    snap = snapshot()
    snap.accounts[0].pwd_changed = NOW - timedelta(days=400)
    assert only(snap, "AD-ACC-012").severity is Severity.HIGH
    assert "400 days" in only(snap, "AD-KRB-001").detail


def test_age_check_of_admins_uses_the_older_time() -> None:
    admin = faked()
    assert "AD-ACC-011" in ids(run_all(snapshot(admin, privileged={"Domain Admins": [admin.dn]})))


def test_must_change_at_next_logon_is_judged_by_the_metadata() -> None:
    admin = user("adm", pwd_last_set=None, pwd_changed=NOW - timedelta(days=500))
    assert admin.password_changed == admin.pwd_changed
    assert "AD-ACC-011" in ids(run_all(snapshot(admin, privileged={"Domain Admins": [admin.dn]})))
    assert "AD-ACC-012" not in ids(run_all(snapshot(admin)))


def test_within_tolerance_and_the_other_direction_are_silent() -> None:
    same = NOW - timedelta(days=1)
    rounded = user("a", pwd_last_set=same + timedelta(seconds=4), pwd_changed=same)
    # the built-in Administrator of a new forest: pwdLastSet from before the promotion
    earlier = user("b", pwd_last_set=same - timedelta(minutes=3), pwd_changed=same)
    assert "AD-ACC-012" not in ids(run_all(snapshot(rounded, earlier)))
    assert earlier.password_changed == same - timedelta(minutes=3)


def test_a_disabled_account_other_than_krbtgt_is_skipped() -> None:
    assert "AD-ACC-012" not in ids(run_all(snapshot(faked(uac=0x200 | UAC.ACCOUNTDISABLE))))


def test_accounts_without_metadata_keep_trusting_pwd_last_set() -> None:
    assert user("a").password_changed == user("a").pwd_last_set
    assert "AD-ACC-012" not in ids(run_all(snapshot(user("a"))))


META = (
    "<DS_REPL_ATTR_META_DATA><pszAttributeName>{}</pszAttributeName>"
    "<ftimeLastOriginatingChange>{}</ftimeLastOriginatingChange></DS_REPL_ATTR_META_DATA>"
)


def test_pwd_change_time_from_the_metadata() -> None:
    values = [
        META.format("pwdLastSet", "2026-11-06T10:00:00Z").encode(),
        META.format("unicodePwd", "2025-01-02T03:04:05Z").encode(),
    ]
    changed = collect._pwd_changed([{"msds-replattributemetadata": values}])
    assert changed is not None and changed.isoformat() == "2025-01-02T03:04:05+00:00"


def test_no_or_empty_metadata_is_no_time() -> None:
    assert collect._pwd_changed([]) is None
    assert collect._pwd_changed([{}]) is None
    never = META.format("unicodePwd", "1601-01-01T00:00:00Z").encode()
    assert collect._pwd_changed([{"msds-replattributemetadata": [never]}]) is None


class Recorder(Collector):
    """A collector whose searches come from a table of DN -> entry."""

    def __init__(self, entries: dict[str, list[dict[str, Any]]] | None = None) -> None:
        super().__init__(None)  # type: ignore[arg-type]
        self.entries = entries or {}
        self.reads: list[tuple[str, list[str]]] = []

    def search(
        self,
        base: str,
        flt: str,
        attrs: list[str],
        scope: str = "SUBTREE",
        controls: list[Any] | None = None,
    ) -> list[dict[str, list[Any]]]:
        self.reads.append((base, attrs))
        if flt == "(objectClass=crossRef)":
            return self.entries.get("crossref", [])
        if base in self.entries:
            return self.entries[base]
        if scope == "BASE" and "objectSid" in attrs and "objectClass" in attrs:
            raise LDAPNoSuchObjectResult()
        return []


def test_metadata_is_asked_for_tier0_accounts_only() -> None:
    admin = user("adm", sid=f"{SID}-1100")
    sync = user("sync", sync_host="SRV", sid=f"{SID}-1101")
    plain = user("plain", sid=f"{SID}-1102")
    meta = META.format("unicodePwd", "2025-01-02T03:04:05Z").encode()
    c = Recorder(
        {admin.dn: [{"distinguishedname": [admin.dn], "msds-replattributemetadata": [meta]}]}
    )
    c._objects(DOMAIN, [admin, sync, plain], {admin.dn.lower()})
    asked = [base for base, attrs in c.reads if collect.REPL_METADATA in attrs]
    assert asked == [admin.dn, sync.dn]  # a sync account is read for keys, not for age
    assert admin.pwd_changed is not None and sync.pwd_changed is None
    assert plain.dn not in {base for base, _ in c.reads}


def test_unread_metadata_is_named() -> None:
    admin = user("adm", sid=f"{SID}-1100")
    c = Recorder()
    c._objects(DOMAIN, [admin], {admin.dn.lower()})
    assert c.pwd_unread == ["adm"]


# --- item 9: CA AuditFilter -------------------------------------------------------------


def audit_ca(value: int | None, **kw: object) -> CaConfig:
    base: dict[str, object] = {
        "policy_module": POLICY, "edit_flags": 0x11014E, "interface_flags": 0x641,
        "request_disposition": 1, "disabled_extensions": [], "owner": "S-1-5-32-544",
        "audit_filter": value, "audit_checked": True,
    }  # fmt: skip
    return ca(**{**base, **kw})


def test_audit_filter_is_read_from_the_ca_key() -> None:
    tree = _tree()
    tree[f"{probes.CA_CONFIGURATION}\\adlab-CA"]["AuditFilter"] = 127
    cfg = probes.read_ca_config(FakeRegistry(tree), CA_HOST, "adlab-CA")
    assert cfg.audit_filter == 127 and cfg.audit_checked


def test_unreadable_audit_filter_is_unknown_not_clean() -> None:
    f = only(_snap(audit_ca(None)), "AD-ADCS-016")
    assert f.objects == [f"{CA_HOST}: AuditFilter unreadable; AD-ADCS-018 not judged"]
    assert "AD-ADCS-018" not in ids(run_all(_snap(audit_ca(None))))


def test_denied_audit_filter_keeps_the_other_values() -> None:
    class Denied(FakeRegistry):
        def query_value(self, key: bytes, name: str) -> winreg.RegValue:
            if name == "AuditFilter":
                raise winreg.RegistryError(winreg.ERROR_ACCESS_DENIED, "read")
            return super().query_value(key, name)

    cfg = probes.read_ca_config(Denied(_tree()), CA_HOST, "adlab-CA")
    assert cfg.audit_filter is None and cfg.audit_checked
    assert cfg.error is None and cfg.interface_flags == 0x641


def test_ca_read_error_is_one_line() -> None:
    f = only(_snap(ca(error="boom")), "AD-ADCS-016")
    assert f.objects == [f"{CA_HOST}: boom"]


def test_older_snapshot_gets_no_new_line_in_adcs_016() -> None:
    assert "AD-ADCS-016" not in ids(run_all(_snap(audit_ca(None, audit_checked=False))))


def test_all_categories_on_is_silent() -> None:
    assert not {"AD-ADCS-016", "AD-ADCS-018"} & ids(run_all(_snap(audit_ca(127))))


@pytest.mark.parametrize("value", [0, 3, 123])
def test_requests_not_audited_is_medium(value: int) -> None:
    f = only(_snap(audit_ca(value)), "AD-ADCS-018")
    assert f.severity is Severity.MEDIUM
    assert "certificate requests" in f.objects[0]
    assert "ESC1 or ESC8" in f.detail
    assert f.key(f.objects[0]) == "adlab-CA"


def test_other_category_off_is_low_and_names_it() -> None:
    f = only(_snap(audit_ca(127 - 32)), "AD-ADCS-018")
    assert f.severity is Severity.LOW
    assert f.objects == ["adlab-CA: AuditFilter 95, off: archived keys"]
    assert "subcategory must also be on" in f.detail


# --- item 10: Onelogon ------------------------------------------------------------------

KEY = r"MACHINE\System\CurrentControlSet\Services\Netlogon\Parameters\VulnerableChannelAllowList"
LISTED = f"{SID}-1200"


def test_gpttmpl_value_is_read_without_quotes() -> None:
    text = f'[Registry Values]\n{KEY}=1,"O:BAG:BAD:(A;;RC;;;WD)"\n'
    assert sysvol.parse_gpttmpl(text).vulnerable_channel_allow == "O:BAG:BAD:(A;;RC;;;WD)"


def test_gpttmpl_key_is_case_insensitive_and_absent_is_none() -> None:
    text = f'[Registry Values]\n{KEY.upper()}=1,"O:BAG:BAD:(A;;RC;;;WD)"\n'
    assert sysvol.parse_gpttmpl(text).vulnerable_channel_allow
    assert sysvol.parse_gpttmpl("[Registry Values]\n").vulnerable_channel_allow is None


def test_sddl_aliases_and_sids() -> None:
    text = f"O:BAG:BAD:(A;;RC;;;WD)(A;;RC;;;DD)(A;;RC;;;EA)(A;;RC;;;{LISTED})(D;;RC;;;BA)"
    allow, deny = sd.sddl_trustees(text, SID, "S-1-5-21-9-9-9")
    assert allow == ["S-1-1-0", f"{SID}-516", "S-1-5-21-9-9-9-519", LISTED]
    assert deny == ["S-1-5-32-544"]


def test_sddl_flags_lower_case_and_sacl() -> None:
    assert sd.sddl_trustees("D:PAI(A;;RC;;;wd)S:(AU;SA;RC;;;WD)", SID) == (["S-1-1-0"], [])


def test_sddl_empty_dacl_has_nobody() -> None:
    assert sd.sddl_trustees("O:BAG:BAD:", SID) == ([], [])


@pytest.mark.parametrize(
    "text", ["garbage", "O:BAG:BA", "D:(A;;RC;;;ZZ)", "D:(XA;;RC;;;WD)", "D:(A;;RC)"]
)
def test_sddl_that_is_not_understood_raises(text: str) -> None:
    with pytest.raises(ValueError):
        sd.sddl_trustees(text, SID)


def channel_snapshot(sddl: str | None, *accounts: Account, **kw: object) -> Snapshot:
    g = kw.pop("policy", None) or gpo("Legacy", "{B}")
    defaults: dict[str, object] = {
        "gpos": [g],
        "gpo_settings": {g.guid: GpoSettings(vulnerable_channel_allow=sddl)},  # type: ignore[attr-defined]
        "channel_policy_collected": True,
        "principals": {LISTED: "legacy_group"},
    }
    snap = snapshot(*accounts, **{**defaults, **kw})
    next(a for a in snap.accounts if a.sam == "DC01$").sid = f"{SID}-1000"
    return snap


def test_a_listed_ordinary_principal_is_medium_and_named() -> None:
    f = only(channel_snapshot(f"O:BAG:BAD:(A;;RC;;;{LISTED})"), "AD-GPO-008")
    assert f.severity is Severity.MEDIUM
    assert f.objects == ["Legacy: legacy_group on DC01$"]
    assert f.key(f.objects[0]) == "Legacy"
    assert "no finding means no GPO sets it" in f.detail


@pytest.mark.parametrize("trustee", ["WD", "AU", "DC", "DD", "BA", "DA"])
def test_broad_and_tier0_principals_are_high(trustee: str) -> None:
    f = only(channel_snapshot(f"O:BAG:BAD:(A;;RC;;;{trustee})"), "AD-GPO-008")
    assert f.severity is Severity.HIGH


def test_a_dc_on_the_list_is_high() -> None:
    f = only(channel_snapshot(f"O:BAG:BAD:(A;;RC;;;{SID}-1000)"), "AD-GPO-008")
    assert f.severity is Severity.HIGH


def test_a_trust_account_on_the_list_is_high() -> None:
    trust = user("PARTNER$", 0x800, sid=LISTED)
    f = only(channel_snapshot(f"O:BAG:BAD:(A;;RC;;;{LISTED})", trust), "AD-GPO-008")
    assert f.severity is Severity.HIGH


def test_a_group_with_a_dc_inside_is_high() -> None:
    dc_dn = "CN=DC01,CN=Computers,DC=lab,DC=test"
    inner = DirObject(f"CN=inner,{HEAD}", "inner", "group", sid=f"{SID}-1201", members=[dc_dn])
    outer = DirObject(f"CN=outer,{HEAD}", "outer", "group", sid=LISTED, members=[inner.dn])
    snap = channel_snapshot(f"O:BAG:BAD:(A;;RC;;;{LISTED})", objects=[inner, outer])
    assert only(snap, "AD-GPO-008").severity is Severity.HIGH


def test_deny_takes_the_same_sid_off_the_list() -> None:
    text = f"O:BAG:BAD:(D;;RC;;;{LISTED})(A;;RC;;;{LISTED})"
    assert "AD-GPO-008" not in ids(run_all(channel_snapshot(text)))


def test_deny_everyone_empties_the_list() -> None:
    text = f"O:BAG:BAD:(D;;RC;;;WD)(A;;RC;;;{LISTED})"
    assert "AD-GPO-008" not in ids(run_all(channel_snapshot(text)))


def test_empty_list_and_no_setting_are_silent() -> None:
    assert "AD-GPO-008" not in ids(run_all(channel_snapshot("O:BAG:BAD:")))
    assert "AD-GPO-008" not in ids(run_all(channel_snapshot(None)))


def test_a_list_that_cannot_be_parsed_is_reported_raw() -> None:
    f = only(channel_snapshot("O:BAG:BAD:(XA;;RC;;;WD)"), "AD-GPO-008")
    assert f.severity is Severity.MEDIUM
    assert f.objects == ["Legacy: list not understood on DC01$: O:BAG:BAD:(XA;;RC;;;WD)"]


def test_a_gpo_that_does_not_reach_a_dc_is_ignored() -> None:
    elsewhere = gpo("Legacy", "{B}", links=[GpLink(f"OU=Clients,{HEAD}", "ou", True, False, 0)])
    snap = channel_snapshot("O:BAG:BAD:(A;;RC;;;WD)", policy=elsewhere)
    assert "AD-GPO-008" not in ids(run_all(snap))


def test_a_disabled_link_or_a_filtered_gpo_is_ignored() -> None:
    off = gpo("Legacy", "{B}", links=[GpLink(HEAD, "domain", False, False, 0)])
    assert "AD-GPO-008" not in ids(run_all(channel_snapshot("D:(A;;RC;;;WD)", policy=off)))
    no_cse = gpo("Legacy", "{B}", machine_extensions=[])
    assert "AD-GPO-008" not in ids(run_all(channel_snapshot("D:(A;;RC;;;WD)", policy=no_cse)))


def test_a_wmi_filter_is_a_caveat_not_a_silence() -> None:
    filtered = gpo("Legacy", "{B}", wmi_filter="Only 2016")
    f = only(channel_snapshot("D:(A;;RC;;;WD)", policy=filtered), "AD-GPO-008")
    assert "[WMI filter Only 2016]" in f.objects[0]


def test_unread_template_and_unread_sysvol_are_notes_not_clean() -> None:
    snap = channel_snapshot(None)
    snap.gpo_settings = {}
    assert gpo_scope.dc_channel_allow(snap) == ([], ["Legacy"])
    assert "Legacy" in collect._channel_notes(snap)[0]
    snap.channel_policy_collected = False
    assert "not judged" in collect._channel_notes(snap)[0]


def test_clean_note_says_only_gpos_were_read() -> None:
    assert "no GPO reaching a DC sets" in collect._channel_notes(channel_snapshot(None))[0]
    assert collect._channel_notes(channel_snapshot("D:(A;;RC;;;WD)")) == []


def test_listed_sids_are_sent_to_name_resolution() -> None:
    settings = {"{B}": GpoSettings(vulnerable_channel_allow=f"D:(A;;RC;;;{LISTED})")}
    assert collect._channel_trustees(settings, SID, SID) == {LISTED}
    broken = {"{B}": GpoSettings(vulnerable_channel_allow="D:(XA;;RC;;;WD)")}
    assert collect._channel_trustees(broken, SID, SID) == set()


# --- item 12: unreadable tier-0 members -------------------------------------------------

HIDDEN = f"CN=ghost,OU=Hidden,{DOMAIN}"
# in a forest root, the Configuration partition sits below the domain's own DN
CROSSREFS = [{"ncname": [nc.encode()]} for nc in (DOMAIN, f"DC=child,{DOMAIN}", CONFIG)]


def admins(*members: str) -> DirObject:
    return DirObject(
        f"CN=Domain Admins,CN=Users,{DOMAIN}", "Domain Admins", "group", sid=f"{SID}-512",
        members=list(members),
    )  # fmt: skip


def builtin_admins(*members: str) -> DirObject:
    return DirObject(
        f"CN=Administrators,CN=Builtin,{DOMAIN}", "Administrators", "group", sid="S-1-5-32-544",
        members=list(members),
    )  # fmt: skip


def compare(
    *members: str,
    entries: dict[str, list[dict[str, Any]]] | None = None,
    accounts: list[Account] | None = None,
    extra: list[DirObject] | None = None,
) -> tuple[list[UnreadableMember] | None, Recorder]:
    c = Recorder({"crossref": CROSSREFS, **(entries or {})})
    objects = [admins(*members), builtin_admins(), *(extra or [])]
    return c._unreadable_members(DOMAIN, CONFIG, SID, accounts or [], objects), c


def test_a_member_nobody_returned_is_reported() -> None:
    found, _ = compare(HIDDEN)
    assert found == [UnreadableMember(HIDDEN, "Domain Admins", collect.NOT_RETURNED)]


def test_a_known_member_needs_no_read() -> None:
    known = user("adm")
    found, c = compare(known.dn.upper(), accounts=[known])
    assert found == [] and c.reads == []


def test_a_hidden_member_of_a_nested_group_is_found() -> None:
    nested = DirObject(f"CN=Tier0,{DOMAIN}", "Tier0", "group", sid=f"{SID}-1300", members=[HIDDEN])
    found, _ = compare(nested.dn, extra=[nested])
    assert found == [UnreadableMember(HIDDEN, "Tier0", collect.NOT_RETURNED)]


def test_group_loops_end() -> None:
    a = DirObject(f"CN=a,{DOMAIN}", "a", "group", sid=f"{SID}-1300", members=[f"CN=b,{DOMAIN}"])
    b = DirObject(f"CN=b,{DOMAIN}", "b", "group", sid=f"{SID}-1301", members=[a.dn])
    assert compare(a.dn, extra=[a, b])[0] == []


def test_groups_outside_tier0_are_not_walked() -> None:
    other = DirObject(f"CN=Sales,{DOMAIN}", "Sales", "group", sid=f"{SID}-1300", members=[HIDDEN])
    assert compare(extra=[other])[0] == []


def test_foreign_principals_and_other_domains_are_not_reported() -> None:
    fsp = f"CN=S-1-5-21-7-8-9-1000,CN=ForeignSecurityPrincipals,{DOMAIN}"
    other = "CN=admin,CN=Users,DC=other,DC=test"
    found, c = compare(fsp, other, f"CN=x,{CONFIG}")
    assert found == []
    assert not {fsp, other, f"CN=x,{CONFIG}"} & {base for base, _ in c.reads}


def test_child_domains_and_dns_partitions_are_not_read() -> None:
    child = f"CN=admin,CN=Users,DC=child,{DOMAIN}"
    found, c = compare(child)
    assert found == []
    assert child not in {base for base, _ in c.reads}


def test_without_crossrefs_nothing_is_read_and_it_stays_unknown() -> None:
    c = Recorder()
    assert (
        c._unreadable_members(DOMAIN, CONFIG, SID, [], [admins(HIDDEN), builtin_admins()]) is None
    )
    assert HIDDEN not in {base for base, _ in c.reads}
    assert any("AD-PRIV-012 not judged" in n for n in c.notes)


def test_missing_main_groups_stay_unknown() -> None:
    c = Recorder({"crossref": CROSSREFS})
    assert c._unreadable_members(DOMAIN, CONFIG, SID, [], [admins()]) is None
    assert any("not readable" in n for n in c.notes)


def test_an_entry_without_attributes_is_unreadable() -> None:
    found, _ = compare(HIDDEN, entries={HIDDEN: [{"distinguishedname": [HIDDEN]}]})
    assert found == [UnreadableMember(HIDDEN, "Domain Admins", collect.NO_ATTRIBUTES)]


def test_a_readable_contact_is_not_reported() -> None:
    entry = {"distinguishedname": [HIDDEN], "objectclass": [b"top", b"person", b"contact"]}
    assert compare(HIDDEN, entries={HIDDEN: [entry]})[0] == []


def test_a_user_only_readable_by_dn_is_reported() -> None:
    entry = {"distinguishedname": [HIDDEN], "objectclass": [b"top", b"person", b"user"]}
    found, _ = compare(HIDDEN, entries={HIDDEN: [entry]})
    assert found == [UnreadableMember(HIDDEN, "Domain Admins", collect.SEARCH_MISSED)]


def test_same_object_under_another_dn_spelling_is_not_reported() -> None:
    known = user("adm", sid=f"{SID}-1100")
    raw = sd_sid(f"{SID}-1100")
    entry = {"distinguishedname": [HIDDEN], "objectclass": [b"user"], "objectsid": [raw]}
    assert compare(HIDDEN, entries={HIDDEN: [entry]}, accounts=[known])[0] == []


def sd_sid(sid: str) -> bytes:
    parts = sid.split("-")
    subs = [int(p) for p in parts[3:]]
    head = bytes([1, len(subs)]) + int(parts[2]).to_bytes(6, "big")
    return head + b"".join(s.to_bytes(4, "little") for s in subs)


def test_reads_are_capped(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(collect, "MAX_MEMBER_READS", 2)
    found, c = compare(*(f"CN=g{i},{DOMAIN}" for i in range(5)))
    assert found is not None and len(found) == 2
    assert any("read only the first 2" in n for n in c.notes)


def test_the_finding_is_high_and_keeps_its_identity() -> None:
    m = UnreadableMember(HIDDEN, "Domain Admins", collect.NOT_RETURNED)
    f = only(snapshot(unreadable_members=[m]), "AD-PRIV-012")
    assert f.severity is Severity.HIGH
    assert f.objects == [f"Domain Admins: {HIDDEN} ({collect.NOT_RETURNED})"]
    assert f.key(f.objects[0]) == f"Domain Admins: {HIDDEN}"


# --- snapshot schema --------------------------------------------------------------------


def full_snapshot() -> Snapshot:
    m = UnreadableMember(HIDDEN, "Tier0 Secret", collect.NOT_RETURNED)
    return channel_snapshot(
        f"O:BAG:BAD:(A;;RC;;;{LISTED})",
        faked(),
        aes_cutover=CUTOVER,
        pwd_metadata_checked=True,
        unreadable_members=[m],
        tier0_members_checked=True,
    )


def test_new_fields_survive_a_round_trip() -> None:
    snap = full_snapshot()
    snap.probes.ca_configs = [audit_ca(3)]
    back = Snapshot.from_json(json.loads(json.dumps(snap.to_json())))
    assert back == snap


def test_older_snapshot_loads_and_says_what_was_not_evaluated() -> None:
    data = json.loads(json.dumps(_snap(audit_ca(3)).to_json()))
    for key in (
        "aes_cutover", "pwd_metadata_checked", "channel_policy_collected",
        "unreadable_members", "tier0_members_checked",
    ):  # fmt: skip
        del data[key]
    for a in data["accounts"]:
        del a["pwd_changed"]
    for c in data["probes"]["ca_configs"]:
        del c["audit_filter"], c["audit_checked"]
    for g in data["gpo_settings"].values():
        del g["vulnerable_channel_allow"]
    loaded = Snapshot.from_json(data)
    text = " ".join(loaded.notes)
    for check_id in ("AD-KRB-005", "AD-ACC-012", "AD-GPO-008", "AD-PRIV-012", "AD-ADCS-018"):
        assert check_id in text
    assert not {"AD-ADCS-016", "AD-ADCS-018"} & ids(run_all(loaded))


def test_redaction_covers_the_new_names_sids_and_dns() -> None:
    snap = full_snapshot()
    out = json.dumps(redact.redact(json.loads(json.dumps(snap.to_json())), b"k"))
    for secret in ("ghost", "Hidden", "Tier0 Secret", "Legacy", SID):
        assert secret not in out, secret
    back = Snapshot.from_json(redact.redact(json.loads(json.dumps(snap.to_json())), b"k"))
    assert "AD-GPO-008" in ids(run_all(back))
    assert "AD-PRIV-012" in ids(run_all(back))
    assert "AD-ACC-012" in ids(run_all(back))
