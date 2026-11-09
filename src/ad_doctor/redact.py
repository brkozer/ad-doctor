"""Pseudonymize a snapshot so it can be shared (with a vendor, in a bug report, with an
auditor) while keeping every finding reproducible.

Names, DNs, host names, domain labels, template and CA names, file names and domain SIDs
are replaced with stable HMAC-derived tokens: the same input and key always give the same
output, so two redacted snapshots taken months apart can still be diffed. Built-in names
(Administrator, krbtgt, Domain Admins, the default templates...) and well-known SIDs are
kept so findings remain readable. This is a best-effort transformation of a JSON
document, not anonymization in the cryptographic sense; review the output before sharing
it outside the organization.
"""

from __future__ import annotations

import dataclasses
import hashlib
import hmac
import ipaddress
import re
import uuid
from typing import Any
from urllib.parse import urlsplit

from . import gpo_scope, model, regpol

KEEP = {
    "administrator", "guest", "krbtgt", "defaultaccount", "wdagutilityaccount",
    "domain admins", "domain users", "domain computers", "domain controllers",
    "domain guests", "enterprise admins", "schema admins", "administrators", "users",
    "account operators", "server operators", "print operators", "backup operators",
    "protected users", "dnsadmins", "cert publishers", "key admins", "enterprise key admins",
    "group policy creator owners", "read-only domain controllers",
    "enterprise read-only domain controllers", "denied rodc password replication group",
    "allowed rodc password replication group", "pre-windows 2000 compatible access",
    "computers", "system", "builtin", "policies", "adminsdholder", "managed service accounts",
    "foreignsecurityprincipals", "configuration", "schema", "services", "sites",
    "displayspecifiers",
    "public key services", "certificate templates", "enrollment services", "ntauthcertificates",
    "oid", "default domain policy", "default domain controllers policy",
    "machine", "user", "preferences", "groups", "scripts", "logon", "logoff", "startup",
    # in operatingSystem values, which AD-GPO-009 to -012 read
    "windows", "server", "hyper-v",
    "registry", "registry.xml", "registry.pol", "audit", "audit.csv",
    # the [Event Audit] categories AD-GPO-013 compares
    "auditaccountlogon", "auditaccountmanage", "auditdsaccess", "auditlogonevents",
    "auditobjectaccess", "auditpolicychange", "auditprivilegeuse", "auditprocesstracking",
    "auditsystemevents",
    "shutdown", "microsoft", "windows nt", "secedit", "gpttmpl.inf", "groups.xml",
    "services.xml", "scheduledtasks.xml", "datasources.xml", "drives.xml", "printers.xml",
    "scheduledtasks", "scripts.ini", "psscripts.ini", "sysvol",
    # built-in certificate templates
    "domaincontroller", "domaincontrollerauthentication", "webserver", "subca", "efs",
    "efsrecovery", "kerberosauthentication", "directoryemailreplication", "workstation",
    "ca", "caexchange", "ceprecovery", "clientauth", "codesigning",
    "crosscertificationauthority", "enrollmentagent", "enrollmentagentoffline",
    "exchangeuser", "exchangeusersignature", "ipsecintermediateoffline",
    "ipsecintermediateonline", "keyrecoveryagent", "ocspresponsesigning",
    "rasandiasserver", "smartcardlogon", "smartcarduser", "userSignature".lower(),
    "machineenrollmentagent", "offlinerouter", "rootcertificationauthority",
    # local groups and well-known principals in Group Policy settings
    "remote desktop users", "remote management users", "distributed com users",
    "hyper-v administrators", "administrators (built-in)", "remote desktop users (built-in)",
    "authenticated users", "everyone", "nt authority", "guests", "interactive",
    # fixed vocabulary of local group entries and links
    "add", "remove", "set", "gpp", "restricted", "ou", "site", "domain",
    # the checks find Exchange servers by these group names
    *model.EXCHANGE_GROUPS,
    model.DEFAULT_POLICY_MODULE.lower(),
    # where Active Directory keeps DNS zones
    "microsoftdns", "domaindnszones", "forestdnszones",
    # the fixed parts of enrollment URLs
    "certsrv", "service.svc", "ces",
    # DN attribute types: a host label with one of these names must not rewrite every DN
    "dc", "cn",
    # the Entra Kerberos realm is the same everywhere, and the checks skip it by name
    "kerberos.microsoftonline.com",
    # fixed names of the Entra Kerberos objects, which AD-KRB-007 reads
    "azureadkerberos", "azureadkerberos$", "krbtgt_azuread", "krbtgt-azuread",
    # service classes the checks read, and those of a default sPNMappings
    "host", "ldap", "gc", "wsman", "alerter", "appmgmt", "cisvc", "clipsrv", "browser",
    "dhcp", "dnscache", "replicator", "eventlog", "eventsystem", "policyagent", "oakley",
    "dmserver", "dns", "mcsvc", "fax", "msiserver", "ias", "messenger", "netlogon", "netman",
    "netdde", "netddedsm", "nmagent", "plugplay", "protectedstorage", "rasman", "rpclocator",
    "rpc", "rpcss", "remoteaccess", "rsvp", "samss", "scardsvr", "scesrv", "seclogon", "scm",
    "dcom", "cifs", "spooler", "snmp", "schedule", "tapisrv", "trksvr", "trkwks", "ups", "time",
    "wins", "www", "http", "w3svc", "iisadmin", "msdtc",
}  # fmt: skip
UNKNOWN_SYNC_HOST = "unknown server"
SID_PREFIX = re.compile(r"S-1-5-21-\d+-\d+-\d+")
# not inside a longer dotted string: OIDs (1.3.6.1.4.1.311.25.2) must survive
IPV4 = re.compile(r"(?<![\d.])(?:\d{1,3}\.){3}\d{1,3}(?![\d.])")
# full and compressed forms with at least two groups and one '::' or seven ':'
IPV6 = re.compile(
    r"(?<![\w:])(?:[0-9a-f]{1,4}:){7}[0-9a-f]{1,4}(?![\w:])"
    r"|(?<![\w:])(?:[0-9a-f]{1,4}(?::[0-9a-f]{1,4})*)?::(?:[0-9a-f]{1,4}(?::[0-9a-f]{1,4})*)?"
    r"(?:%\w+)?(?![\w:])",
    re.IGNORECASE,
)
GUID_LIKE = re.compile(r"^\{?[0-9a-fA-F-]{36}\}?$")
# altSecurityIdentities: X509:<I>issuer<SR>serial; the tags decide weak or strong
MAPPING_PART = re.compile(r"(<(?:I|S|SR|SKI|SHA1-PUKEY|RFC822)>)([^<]*)", re.IGNORECASE)
MAPPING_SCHEMES = ("X509", "KERBEROS")
# SIDs as Restricted Groups writes them (*S-1-...): rewritten by SID_PREFIX, not tokenized
SID_TOKEN = re.compile(r"^\*?S-1-", re.IGNORECASE)
# a timestamp as to_json writes it: a digit-only name must not reach inside it
TIMESTAMP = re.compile(r"\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d(?:\.\d+)?(?:[+-]\d\d:\d\d|Z)?")
# a name starts and ends where these runs do, so a run is the key to look a name up by
NAME_RUN = re.compile(r"[\w$]+")
# a backslash pair of a DN: \, \+ \" \\ \< \> \; \= \# and a leading or trailing space
DN_ESCAPE = re.compile(r"\\([,+\"\\<>;=# ])")
# keys that are field names or fixed labels, never data
FIXED_KEYS = {
    f.name
    for cls in (model.Snapshot, model.Account, model.DomainPolicy, model.CertTemplate,
                model.DirObject, model.GpoSettings, model.Probes, model.DcProbe, model.CaConfig,
                model.Gmsa, model.Rodc, model.Trust, model.Gpo, model.GppPassword,
                model.ScriptSecret, model.GpoLocalGroup, model.GpLink, model.RegistryEntry,
                model.GpoAutologon,
                model.UnreadableMember, model.KeyCredential, model.Site, model.Subnet,
                model.ConflictObject, model.Pso, model.Dmsa, model.DnsZone, model.DnsNode,
                model.AuthSilo, model.AuthPolicy, model.MemberChange, model.SidHistoryChange,
                model.SccmObject, model.CaCertificate, model.DisplaySpecifierCommand,
                model.GpoScript, model.SysvolAcl, model.HostSmb, model.HostPatch)
    for f in dataclasses.fields(cls)
} | {"domain", "AdminSDHolder", "sid", "mask", "object_type", "inherited_object_type",
     *model.CONFIG_ACL_LABELS}  # fmt: skip
# values from a fixed list, which the checks compare: never data, whatever the names around
# (stores: where a CA certificate is published; attribute: a display specifier's attribute name)
FIXED_VALUES = {"kind", "source", "action", "stores", "attribute", "key_type", "signature_hash",
                "side", "phase", "location", "run_as"}  # fmt: skip


# GUID -> RegistryEntry lists; a path or value name in them is vocabulary
POLICY_STORES = ("gpo_registry", "gpo_audit", "gpo_preferences")


class Redactor:
    def __init__(self, key: bytes) -> None:
        self.key = key
        self.names: dict[str, str] = {}
        self.sids: dict[str, str] = {}
        # first word of a name -> (lengths, longest first; lower-cased name -> token)
        self._index: dict[str, tuple[list[int], dict[str, str]]] = {}
        # the few names that start with neither a letter nor a digit
        self._odd: re.Pattern[str] | None = None

    def _digest(self, value: str) -> str:
        return hmac.new(self.key, value.lower().encode(), hashlib.sha256).hexdigest()

    def token(self, value: str) -> str:
        # a computer's sAMAccountName (NAME$) and its bare name share one token, so the
        # checks that match one against the other still match after redaction
        suffix = "$" if value.endswith("$") else ""
        return f"x{self._digest(value.removesuffix('$'))[:8]}{suffix}"

    def fake_sid(self, prefix: str) -> str:
        if prefix not in self.sids:
            d = self._digest(prefix)
            parts = (str(int(d[i : i + 8], 16) % 4_000_000_000) for i in (0, 8, 16))
            self.sids[prefix] = "S-1-5-21-" + "-".join(parts)
        return self.sids[prefix]

    def fake_guid(self, value: str) -> str:
        return str(uuid.UUID(self._digest(value)[:32]))

    def mapping(self, value: str) -> str:
        """Every value of a certificate mapping replaced, its type kept: subjects and
        e-mail addresses in it need not belong to any object the scan saw. Only known tags
        and schemes survive; anything else in a malformed value is a token."""
        kind, sep, rest = value.partition(":")
        if not sep or kind.upper() not in MAPPING_SCHEMES:
            return self.token(value)
        if kind.upper() != "X509":
            return f"{kind}:{self.token(rest)}"
        kept = "".join(tag + self.token(text) for tag, text in MAPPING_PART.findall(rest))
        left = MAPPING_PART.sub("", rest)
        return f"{kind}:{kept}" + (self.token(left) if left else "")

    def collect(self, data: dict[str, Any]) -> None:
        """Learn which words are sensitive: account, object, host, file and domain names."""
        words: set[str] = {data["domain"], *data["domain"].split(".")}
        # a host name that is the computer's own takes the computer's token, so AD-ACC-016
        # compares the same two things after redaction
        own_hosts: dict[str, str] = {}
        for a in data["accounts"]:
            words.add(a["sam"])
            words.update(_dn_values(a["dn"]))
            if a.get("dns_host"):
                words.update([a["dns_host"], *a["dns_host"].split(".")])
                if a.get("is_computer") and model.dns_host_matches(a["dns_host"], a["sam"]):
                    own_hosts[a["dns_host"].lower()] = a["sam"].removesuffix("$")
            if a.get("upn"):
                # in parts: a bare UPN must keep the token of the sAMAccountName it equals
                local, at, suffix = a["upn"].rpartition("@")
                words.add(local if at else suffix)
                if at:
                    words.update([suffix, *suffix.split(".")])
            for dn in (a.get("krbtgt_link"), a.get("superseded_by")):
                if dn:
                    words.update(_dn_values(dn))
            if a.get("sync_host") and a["sync_host"] != UNKNOWN_SYNC_HOST:
                words.add(a["sync_host"])
            # label by label: a delegation target's host need not be a computer in the
            # snapshot, and AD-DEL-005 tells other domains by the dots that stay
            for spn in [*a.get("spns", []), *a.get("allowed_to_delegate_to", [])]:
                service, slash, rest = spn.partition("/")
                words.update(p for p in re.split(r"[.:/]", rest or service) if not p.isdigit())
                if slash:
                    words.add(service)
        for d in data.get("probes", {}).get("dcs", []):
            words.update(_host_words(d["name"]))
        for c in data.get("probes", {}).get("ca_configs", []):
            words.update([c["name"], *_host_words(c["host"])])
            if c.get("policy_module"):
                words.add(c["policy_module"])  # a vendor name; Microsoft's is in KEEP
        probes = data.get("probes", {})
        for url in [
            *probes.get("web_enrollment_ntlm", []),
            *probes.get("enrollment_https", []),
            *data.get("enrollment_urls", []),
        ]:
            words.update(_url_words(url))
        for mapping in data.get("spn_mappings", []):
            words.update(p.strip() for p in re.split(r"[=,]", mapping))
        for dc_dn, site_dn in data.get("dc_sites", {}).items():
            words.update(_dn_values(dc_dn))
            words.update(_dn_values(site_dn))
        for site in data.get("sites", []):
            words.update(_dn_values(site["dn"]))
        for subnet in data.get("subnets", []):
            words.update(_dn_values(subnet["site"]))
        for dn in [*data.get("sysvol_frs_dcs", []), *data.get("sysvol_dfsr_dcs", [])]:
            words.update(_dn_values(dn))
        for conflict in data.get("conflicts", []):
            words.update(_dn_values(conflict["dn"]))
        for pso in data.get("psos", []):
            words.update([pso["name"], *_dn_values(pso["dn"])])
            for dn in [*pso["applies_to"], *pso["not_global"]]:
                words.update(_dn_values(dn))
        for dmsa in data.get("dmsas", []):
            words.update([dmsa["name"], *_dn_values(dmsa["dn"])])
            if dmsa.get("preceded_by"):
                words.update(_dn_values(dmsa["preceded_by"]))
        # the whole name only: the labels of a reverse zone are the digits of its network
        for zone in data.get("dns_zones", []):
            words.update([zone["name"], *_dn_values(zone["dn"])])
        for node in data.get("dns_nodes", []):
            words.add(node["zone"])
            words.update(label for label in node["name"].split(".") if label != "*")
        for silo in data.get("auth_silos", []):
            words.update([silo["name"], *_dn_values(silo["dn"])])
            for dn in [*silo["members"], *silo["assigned"], silo["user_policy"]]:
                words.update(_dn_values(dn))
        for policy in data.get("auth_policies", []):
            words.update([policy["name"], *_dn_values(policy["dn"])])
        for change in data.get("member_changes", []):
            words.update([change["group"], *_dn_values(change["group_dn"])])
            words.update(_dn_values(change["member_dn"]))
        for change in data.get("sid_history_changes", []):
            words.update(_dn_values(change["dn"]))
        for held in [data.get("sccm_container"), *data.get("dkm_containers", [])]:
            if held:
                words.update([held["name"], *_dn_values(held["dn"])])
        for x in data.get("sccm_objects", []):
            words.update(_dn_values(x["dn"]))
            words.update([x["site_code"], *_host_words(x["host"])])
        for dn in data.get("dynamic_objects", []):
            words.update(_dn_values(dn))
        words.update(c["name"] for c in data.get("ca_certificates", []))
        for x in data.get("gpo_scripts", []):
            for path in (x["config"], x["path"], x["target"]):
                words.update(_path_words(path))
            if x["host"]:
                words.update(_host_words(x["host"]))
        for x in data.get("sysvol_acls", []):
            words.update(_path_words(x["path"]))
        for x in data.get("probes", {}).get("tier0_smb", []):
            words.add(x["name"])
        for x in data.get("probes", {}).get("patch_levels", []):
            words.update(_host_words(x["name"]))
        for x in data.get("display_specifiers", []):
            words.update(v for v in _dn_values(x["dn"]) if not _numeric(v))
        for o in data.get("objects", []):
            words.add(o["name"])
            words.update(_dn_values(o["dn"]))
        for g in data.get("gpos", []):
            words.add(g["name"])
            for link in g.get("links", []):
                words.update(_dn_values(link["container"]))
            if g.get("wmi_filter"):
                words.add(g["wmi_filter"])
        for x in data.get("gpo_local_groups", []):
            for name in (x["member_name"], x["group_name"]):
                words.update([name, *name.split("\\")])
        for s in data.get("gpo_settings", {}).values():
            for server in s.get("ntlm_exceptions", []):
                words.update([server, *server.split(".")])
            for right in gpo_scope.DENY_LOGON_RIGHTS:
                for holder in s.get("privileges", {}).get(right, []):
                    # a name that did not resolve stays as written, and a note repeats it
                    if not holder.upper().startswith("S-1-") and not model.well_known_sid(holder):
                        words.update([holder, *re.split(r"[\\@]", holder)])
        for store in POLICY_STORES:
            for entries in data.get(store, {}).values():
                for e in entries:
                    words.update(_registry_words(e))
        for m in data.get("unreadable_members", []):
            words.add(m["group"])
            words.update(_dn_values(m["dn"]))
        words.update(t["name"] for t in data.get("templates", []))
        for t in data.get("trusts", []):
            if t["name"].lower() not in KEEP:
                words.update([t["name"], *t["name"].split(".")])
        words.update(data.get("principals", {}).values())
        words.update(
            k.removeprefix("PKI:CA ") for k in data.get("acls", {}) if k.startswith("PKI:CA ")
        )
        words.update(g["user"] for g in data.get("gpp_passwords", []))
        for item in [
            *data.get("gpp_passwords", []),
            *data.get("script_secrets", []),
            *data.get("gpo_local_groups", []),
        ]:
            words.update(_path_words(item["path"]))
        words.update(data.get("ca_hosts", []))
        odd = []
        for w in words:
            if w and w.lower() not in KEEP and not GUID_LIKE.match(w) and not SID_TOKEN.match(w):
                # an escaped DN value and its plain form are one name, with one token
                token = self.token(own_hosts.get(w.lower()) or DN_ESCAPE.sub(r"\1", w))
                self.names[w.lower()] = token
                first = NAME_RUN.match(w)
                if first is None:
                    odd.append(w.lower())
                    continue
                lengths, names = self._index.setdefault(first.group().lower(), ([], {}))
                names[w.lower()] = token
                if len(w) not in lengths:
                    lengths.append(len(w))
                    lengths.sort(reverse=True)
        if odd:
            alternatives = "|".join(re.escape(n) for n in sorted(odd, key=len, reverse=True))
            self._odd = re.compile(rf"(?<![\w$])(?:{alternatives})(?![\w$])", re.IGNORECASE)

    def _replace_names(self, value: str) -> str:
        """Whole names only, longest first, leftmost first. Looking each word up keeps the
        cost linear in the text; one alternation of all names is not, on a large domain."""
        if self._odd is not None:
            value = self._odd.sub(lambda m: self.names[m.group(0).lower()], value)
        out: list[str] = []
        last = 0
        for run in NAME_RUN.finditer(value):
            start = run.start()
            found = self._index.get(run.group().lower()) if start >= last else None
            if found is None:
                continue
            for length in found[0]:
                end = start + length
                token = found[1].get(value[start:end].lower())
                if token is not None and not NAME_RUN.match(value, end):
                    out += [value[last:start], token]
                    last = end
                    break
        return "".join([*out, value[last:]]) if out else value

    def text(self, value: str) -> str:
        if TIMESTAMP.fullmatch(value):
            return value
        if "S-1-5-21-" in value:
            value = SID_PREFIX.sub(lambda m: self.fake_sid(m.group(0)), value)
        if "." in value:
            value = IPV4.sub("0.0.0.0", value)
        if ":" in value:
            value = IPV6.sub("::", value)
        return self._replace_names(value)

    def walk(self, value: Any) -> Any:
        if isinstance(value, str):
            return self.text(value)
        if isinstance(value, list):
            return [self.walk(v) for v in value]
        if isinstance(value, dict):
            return {
                self._key(k): v if k in FIXED_VALUES else self.walk(v) for k, v in value.items()
            }
        return value

    def _key(self, key: Any) -> Any:
        if not isinstance(key, str) or key in FIXED_KEYS:
            return key
        return self.text(key)


def _dn_values(dn: str) -> list[str]:
    """Each RDN value as the DN writes it, for the DN itself, and in its plain form, which
    is how a display name or a group name holds the same words."""
    out = []
    for part in re.split(r"(?<!\\),", dn):
        if "=" in part:
            value = part.split("=", 1)[1].strip()
            out += [value, DN_ESCAPE.sub(r"\1", value)]
    return out


def _numeric(word: str) -> bool:
    """Digits and dots: a name made of them would rewrite SIDs, OIDs and version numbers."""
    return not word.strip("0123456789.")


def _host_words(host: str) -> list[str]:
    """A host name and its labels. An address has none: `text` replaces it whole."""
    return [p for p in [host, *host.split(".")] if p and not _numeric(p)]


def _path_words(path: str) -> list[str]:
    return [p for p in re.split(r"[\\/]", path) if p and not GUID_LIKE.match(p) and not _numeric(p)]


def _url_words(url: str) -> list[str]:
    """The sensitive parts of a URL: a CES path holds the CA name, a host need not be a
    computer in the snapshot, and a URL can carry a user and a password."""
    try:
        parts = urlsplit(url)
        host = parts.hostname or ""
        found = [parts.username or "", parts.password or "", *parts.path.split("/")]
    except ValueError:  # still text someone wrote in the directory
        return [p for p in re.split(r"[/:@\s\[\]]+", url) if len(p) > 1 and not p.isdigit()]
    try:
        ipaddress.ip_address(host)  # text() replaces addresses; their digits are not names
    except ValueError:
        found += [host, *host.split(".")]
    return [p for p in found if len(p) > 1 and not p.isdigit()]


def _server_words(server: str) -> list[str]:
    """A WSUS server as a GPO writes it, with or without a scheme."""
    text = server.strip()
    return _url_words(text if "://" in text else f"//{text}")


def _registry_words(entry: dict[str, Any]) -> list[str]:
    """Names in a registry entry: a WSUS server, the host of a hardened path, a module."""
    key = regpol.norm(entry["key"])
    if key == regpol.norm(regpol.WSUS_KEY):
        data = entry.get("data")
        servers = data if isinstance(data, list) else [data] if isinstance(data, str) else []
        return [word for server in servers for word in _server_words(server)]
    if key == regpol.norm(regpol.HARDENED_KEY):
        host = entry["name"].lstrip("\\").split("\\")[0]
        if host == "*" or not host:
            return []
        labels = [label for label in host.split(".") if label != "*"]
        return labels if "*" in host else [host, *labels]  # the wildcard stays readable
    if key == regpol.norm(regpol.MODULE_NAMES_KEY) and entry["name"] != "*":
        return [entry["name"]]
    return []


def _redact_server(r: Redactor, server: str) -> str:
    scheme, sep, rest = server.partition("://")
    return f"{scheme}{sep}{r.text(rest)}" if sep else r.text(server)


def _redact_registry(r: Redactor, before: dict[str, Any], after: dict[str, Any]) -> None:
    """Paths, fixed value names and flags are vocabulary the checks compare, whatever an OU
    happens to be called; only what `_registry_words` learned is replaced."""
    after["key"] = before["key"]
    key = regpol.norm(before["key"])
    data = before.get("data")
    if key == regpol.norm(regpol.WSUS_KEY) and isinstance(data, str):
        after["data"] = _redact_server(r, data)
    elif key == regpol.norm(regpol.WSUS_KEY) and isinstance(data, list):
        after["data"] = [_redact_server(r, server) for server in data]
    elif key == regpol.norm(regpol.MODULE_NAMES_KEY):
        after["data"] = ""  # no check reads it, and a snapshot can hold the module's name here
    else:
        after["data"] = data
    if key == regpol.norm(regpol.HARDENED_KEY) and before["name"]:
        host, _, share = before["name"].lstrip("\\").partition("\\")
        after["name"] = f"\\\\{r.text(host)}\\{share}"
    elif key == regpol.norm(regpol.MODULE_NAMES_KEY):
        after["name"] = before["name"] if before["name"] == "*" else r.text(before["name"])
    else:
        after["name"] = before["name"]


def _redact_note(r: Redactor, note: str, walked: str) -> str:
    """The location of a value named like a password is free text from a GPO, in words the
    snapshot gives no other reason to learn: one token, unless it is Winlogon's own."""
    head, sep, location = note.partition(regpol.SECRET_NOTE)
    if not sep:
        return walked
    kept = location if regpol.is_default_password(location) else r.token(location)
    return f"{r.text(head)}{sep}{kept}"


def _keep_invisible(original: str, redacted: str) -> str:
    """The invisible characters of an SPN, moved to its end: a name token drops them, and
    AD-ACC-016 must still see that they were there. They identify nobody."""
    hidden = model.invisible_chars(original)
    if not hidden:
        return redacted
    return "".join(c for c in redacted if c not in hidden) + hidden


def redact(data: dict[str, Any], key: bytes) -> dict[str, Any]:
    r = Redactor(key)
    r.collect(data)
    out: dict[str, Any] = r.walk(data)
    for before, after in zip(data["accounts"], out["accounts"], strict=True):
        if before.get("spns"):
            after["spns"] = [
                _keep_invisible(spn, kept)
                for spn, kept in zip(before["spns"], after["spns"], strict=True)
            ]
        if before.get("alt_security_identities"):
            after["alt_security_identities"] = [
                r.mapping(m) for m in before["alt_security_identities"]
            ]
        for credential in after.get("key_credentials", []):
            if credential["device_id"]:
                credential["device_id"] = r.fake_guid(credential["device_id"])
            if credential.get("key_id"):
                credential["key_id"] = r.fake_guid(credential["key_id"]).replace("-", "")[:16]
    for store in POLICY_STORES:
        for guid, entries in data.get(store, {}).items():
            for before, after in zip(entries, out[store][r._key(guid)], strict=True):
                _redact_registry(r, before, after)
    if data.get("notes"):
        pairs = zip(data["notes"], out["notes"], strict=True)
        out["notes"] = [_redact_note(r, note, walked) for note, walked in pairs]
    # an address block names the network; 0.0.0.0/24 would make every subnet the same one
    for before, after in zip(data.get("subnets", []), out.get("subnets", []), strict=True):
        after["name"] = r.token(before["name"])
    for before, after in zip(
        data.get("display_specifiers", []), out.get("display_specifiers", []), strict=True
    ):
        after["command"] = r.token(before["command"])  # free text: a path, a URL, a host
    out["redacted"] = True
    # read from the input: redacting an old redacted file again cannot relate its tokens
    out["host_names_comparable"] = model.host_names_comparable(data)
    return out
