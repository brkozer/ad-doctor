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
import re
from typing import Any

from . import model

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
    "public key services", "certificate templates", "enrollment services", "ntauthcertificates",
    "oid", "default domain policy", "default domain controllers policy",
    "machine", "user", "preferences", "groups", "scripts", "logon", "logoff", "startup",
    "shutdown", "microsoft", "windows nt", "secedit", "gpttmpl.inf", "groups.xml",
    "services.xml", "scheduledtasks.xml", "datasources.xml", "drives.xml", "printers.xml",
    # built-in certificate templates
    "domaincontroller", "domaincontrollerauthentication", "webserver", "subca", "efs",
    "efsrecovery", "kerberosauthentication", "directoryemailreplication", "workstation",
    "ca", "caexchange", "ceprecovery", "clientauth", "codesigning",
    "crosscertificationauthority", "enrollmentagent", "enrollmentagentoffline",
    "exchangeuser", "exchangeusersignature", "ipsecintermediateoffline",
    "ipsecintermediateonline", "keyrecoveryagent", "ocspresponsesigning",
    "rasandiasserver", "smartcardlogon", "smartcarduser", "userSignature".lower(),
    "machineenrollmentagent", "offlinerouter", "rootcertificationauthority",
}  # fmt: skip
UNKNOWN_SYNC_HOST = "unknown server"
SID_PREFIX = re.compile(r"S-1-5-21-\d+-\d+-\d+")
IPV4 = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
GUID_LIKE = re.compile(r"^\{?[0-9a-fA-F-]{36}\}?$")
# keys that are field names or fixed labels, never data
FIXED_KEYS = {
    f.name
    for cls in (model.Snapshot, model.Account, model.DomainPolicy, model.CertTemplate,
                model.DirObject, model.GpoSettings, model.Probes, model.DcProbe,
                model.Gmsa, model.Rodc, model.Trust, model.Gpo, model.GppPassword,
                model.ScriptSecret)
    for f in dataclasses.fields(cls)
} | {"domain", "AdminSDHolder", "sid", "mask", "object_type", "inherited_object_type"}  # fmt: skip


class Redactor:
    def __init__(self, key: bytes) -> None:
        self.key = key
        self.names: dict[str, str] = {}
        self.sids: dict[str, str] = {}
        self._pattern: re.Pattern[str] | None = None

    def _digest(self, value: str) -> str:
        return hmac.new(self.key, value.lower().encode(), hashlib.sha256).hexdigest()

    def token(self, value: str) -> str:
        suffix = "$" if value.endswith("$") else ""
        return f"x{self._digest(value)[:8]}{suffix}"

    def fake_sid(self, prefix: str) -> str:
        if prefix not in self.sids:
            d = self._digest(prefix)
            parts = (str(int(d[i : i + 8], 16) % 4_000_000_000) for i in (0, 8, 16))
            self.sids[prefix] = "S-1-5-21-" + "-".join(parts)
        return self.sids[prefix]

    def collect(self, data: dict[str, Any]) -> None:
        """Learn which words are sensitive: account, object, host, file and domain names."""
        words: set[str] = {data["domain"], *data["domain"].split(".")}
        for a in data["accounts"]:
            words.add(a["sam"])
            words.update(_dn_values(a["dn"]))
            if a.get("dns_host"):
                words.update([a["dns_host"], *a["dns_host"].split(".")])
            if a.get("sync_host") and a["sync_host"] != UNKNOWN_SYNC_HOST:
                words.add(a["sync_host"])
        for d in data.get("probes", {}).get("dcs", []):
            words.update([d["name"], *d["name"].split(".")])
        for o in data.get("objects", []):
            words.add(o["name"])
            words.update(_dn_values(o["dn"]))
        words.update(g["name"] for g in data.get("gpos", []))
        words.update(t["name"] for t in data.get("templates", []))
        for t in data.get("trusts", []):
            words.update([t["name"], *t["name"].split(".")])
        words.update(data.get("principals", {}).values())
        words.update(
            k.removeprefix("PKI:CA ") for k in data.get("acls", {}) if k.startswith("PKI:CA ")
        )
        words.update(g["user"] for g in data.get("gpp_passwords", []))
        for item in [*data.get("gpp_passwords", []), *data.get("script_secrets", [])]:
            words.update(
                p for p in re.split(r"[\\/]", item["path"]) if p and not GUID_LIKE.match(p)
            )
        words.update(data.get("ca_hosts", []))
        for w in words:
            if w and w.lower() not in KEEP and not GUID_LIKE.match(w):
                self.names[w.lower()] = self.token(w)
        if self.names:
            alternatives = "|".join(re.escape(n) for n in sorted(self.names, key=len, reverse=True))
            # whole names only: not inside a longer word
            self._pattern = re.compile(rf"(?<![\w$])(?:{alternatives})(?![\w$])", re.IGNORECASE)

    def text(self, value: str) -> str:
        value = SID_PREFIX.sub(lambda m: self.fake_sid(m.group(0)), value)
        value = IPV4.sub("0.0.0.0", value)
        if self._pattern is None:
            return value
        return self._pattern.sub(lambda m: self.names[m.group(0).lower()], value)

    def walk(self, value: Any) -> Any:
        if isinstance(value, str):
            return self.text(value)
        if isinstance(value, list):
            return [self.walk(v) for v in value]
        if isinstance(value, dict):
            return {self._key(k): self.walk(v) for k, v in value.items()}
        return value

    def _key(self, key: Any) -> Any:
        if not isinstance(key, str) or key in FIXED_KEYS:
            return key
        return self.text(key)


def _dn_values(dn: str) -> list[str]:
    out = []
    for part in re.split(r"(?<!\\),", dn):
        if "=" in part:
            out.append(part.split("=", 1)[1].strip().replace("\\,", ","))
    return out


def redact(data: dict[str, Any], key: bytes) -> dict[str, Any]:
    r = Redactor(key)
    r.collect(data)
    out: dict[str, Any] = r.walk(data)
    out["redacted"] = True
    return out
