"""Scan every domain of a forest, one domain at a time, from one domain controller.

The Configuration partition is replicated to every domain controller, so any one of them can
name the whole forest: the crossRef objects under CN=Partitions list the naming contexts, and
the server and nTDSDSA objects under CN=Sites say which DC holds which domain. Each domain is
then collected by the ordinary per-domain collector into an ordinary snapshot, with nothing in
memory carried from one domain to the next.

A domain that cannot be read is written down as not evaluated, and `complete` stays false: a
forest result must not read as whole when part of it is missing.

Enterprise Admins and Schema Admins exist only in the forest root but can hold principals of
any domain, and a per-domain scan sees only its own domain's members. They are read here,
following each member to a DC of the domain that holds it.
"""

from __future__ import annotations

import hashlib
import json
import re
from collections import deque
from collections.abc import Callable
from dataclasses import dataclass, field, replace
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import ldap3
from ldap3.core.exceptions import LDAPException

from . import __version__
from .collect import (
    BindRejected,
    CollectError,
    Collector,
    Target,
    _first,
    _int,
    _optional_bool,
    _parent,
    _str,
    connect,
    sid_to_str,
)
from .model import UAC, Snapshot
from .report import write_private

MANIFEST = "forest.json"
MANIFEST_TOOL = "ad-doctor-forest"
MANIFEST_SCHEMA = 1
SNAPSHOT_SUFFIX = ".snapshot.json"
REPORT_SUFFIX = ".report.json"

# systemFlags of a crossRef (MS-ADTS): a naming context of this forest, and a domain among them
FLAG_CR_NTDS_NC = 0x1
FLAG_CR_NTDS_DOMAIN = 0x2
FOREST_GROUPS = {"Enterprise Admins": 519, "Schema Admins": 518}
# a domain with many DCs down must not cost one connect timeout for each of them
MAX_DC_TRIES = 5
# BASE reads while following the members of one group
MAX_HOLDER_READS = 2000
PRINCIPAL_ATTRS = ["objectClass", "objectSid", "sAMAccountName", "member", "userAccountControl"]
CROSSREF_ATTRS = ["cn", "nCName", "dnsRoot", "nETBIOSName", "systemFlags", "Enabled"]
_SAFE_STEM = re.compile(r"[a-z0-9][a-z0-9_-]*(?:\.[a-z0-9][a-z0-9_-]*)*")

Connector = Callable[[Target], Any]
Reader = Callable[[Any, Target], Snapshot]
Analyzer = Callable[[Snapshot, str], None]


@dataclass
class Domain:
    dn: str
    name: str
    netbios: str = ""
    root: bool = False
    # domain controllers of this domain, writable ones first
    dcs: list[str] = field(default_factory=list)
    # why this domain cannot even be tried; it counts as not evaluated
    skip: str | None = None


@dataclass
class Layout:
    root_dn: str
    seed_dn: str
    domains: list[Domain]
    # crossRefs that point outside the forest (for example at another directory)
    referrals: list[dict[str, str]]
    notes: list[str]
    # the list of domains itself may be short
    partial: bool = False


@dataclass
class _Read:
    """A domain that was collected, and the target that reached it (never written out)."""

    domain: Domain
    target: Target


def _norm(dn: str) -> str:
    return ",".join(part.strip() for part in dn.lower().split(","))


def dns_name(dn: str) -> str:
    """The DNS name of a domain DN, the way the collector derives it, in lower case."""
    return ".".join(p.split("=", 1)[-1].strip() for p in dn.lower().split(","))


def file_stem(dn: str) -> str:
    """A file name for a domain: its whole DNS name, so that two domains sharing a first label
    stay apart. The name comes from the directory, so anything else in it is not used as a path."""
    name = dns_name(dn)
    if _SAFE_STEM.fullmatch(name) and len(name) <= 200:
        return name
    return "domain-" + hashlib.sha256(_norm(dn).encode()).hexdigest()[:16]


def _context(conn: Any, name: str) -> str:
    info = conn.server.info
    values = info.other.get(name) if info is not None else None
    return str(values[0]) if values else ""


def _classify(entry: dict[str, list[Any]], layout: Layout, seen: set[str]) -> None:
    label = _first(entry, "cn") or _first(entry, "distinguishedName")
    dn = _first(entry, "nCName")
    flags = entry.get("systemflags")
    if not flags or not dn:
        layout.partial = True
        layout.notes.append(
            f"crossRef {label}: systemFlags or nCName not readable, so it is not known whether "
            "it is a domain of this forest"
        )
        return
    value = _int(entry, "systemFlags")
    if not value & FLAG_CR_NTDS_NC:
        layout.referrals.append({"name": label, "target": _first(entry, "dnsRoot"), "dn": dn})
        return
    if not value & FLAG_CR_NTDS_DOMAIN:
        return  # Configuration, Schema and application partitions such as DomainDnsZones
    if _norm(dn) in seen:
        return
    seen.add(_norm(dn))
    domain = Domain(dn, dns_name(dn), _first(entry, "nETBIOSName"))
    if _optional_bool(entry, "Enabled") is False:
        domain.skip = "its crossRef is disabled: the domain is being created or removed"
    domain.dcs = [host] if (host := _first(entry, "dnsRoot").lower()) else []
    layout.domains.append(domain)


def _locate_dcs(collector: Collector, config: str, layout: Layout) -> None:
    """Which DCs hold which domain, from the Configuration partition. A DC's nTDSDSA object
    is a child of its server object, and that object carries the host name. The domain's own
    DNS name stays the only candidate of a domain with no server object."""
    sites = f"CN=Sites,{config}"
    dsas = collector.attempt(
        sites,
        "(objectClass=nTDSDSA)",
        ["msDS-HasDomainNCs", "hasMasterNCs", "msDS-hasMasterNCs", "objectCategory"],
        must_exist=True,
    )
    servers = collector.attempt(sites, "(objectClass=server)", ["dNSHostName"], must_exist=True)
    if dsas is None or servers is None:
        layout.notes.append(
            "domain controllers not readable under CN=Sites: only each domain's own DNS name "
            "is tried"
        )
        return
    hosts = {_norm(_first(s, "distinguishedName")): _first(s, "dNSHostName") for s in servers}
    held: dict[str, list[tuple[bool, str]]] = {}
    for dsa in dsas:
        host = hosts.get(_norm(_parent(_first(dsa, "distinguishedName"))), "")
        if not host:
            continue
        read_only = "cn=ntds-dsa-ro," in _first(dsa, "objectCategory").lower()
        contexts = {
            _norm(v)
            for attr in ("msds-hasdomainncs", "hasmasterncs", "msds-hasmasterncs")
            for v in _str(dsa.get(attr, []))
        }
        for context in contexts:
            held.setdefault(context, []).append((read_only, host))
    for domain in layout.domains:
        found = sorted(set(held.get(_norm(domain.dn), [])), key=lambda c: (c[0], c[1].lower()))
        if found:
            domain.dcs = [host for _, host in found]


def discover(collector: Collector) -> Layout:
    """The domains of the forest and a list of DCs for each, read from one domain controller."""
    conn = collector.conn
    seed, config = (
        _context(conn, "defaultNamingContext"),
        _context(conn, "configurationNamingContext"),
    )
    root = _context(conn, "rootDomainNamingContext")
    if not seed or not config:
        raise CollectError("rootDSE did not return the naming contexts of this forest")
    refs = collector.attempt(
        f"CN=Partitions,{config}",
        "(objectClass=crossRef)",
        CROSSREF_ATTRS,
        must_exist=True,
        scope=ldap3.LEVEL,
    )
    if not refs:
        raise CollectError("no crossRef objects under CN=Partitions: cannot list this forest")
    layout = Layout(root, seed, [], [], [])
    seen: set[str] = set()
    for entry in refs:
        _classify(entry, layout, seen)
    if _norm(seed) not in seen:
        layout.partial = True
        layout.notes.append(
            f"the crossRef of {dns_name(seed)}, the domain scanned first, was not returned: the "
            "list of domains may be short"
        )
        layout.domains.append(Domain(seed, dns_name(seed)))
    if not root:
        layout.partial = True
        layout.notes.append("rootDSE did not name the forest root")
    for domain in layout.domains:
        domain.root = bool(root) and _norm(domain.dn) == _norm(root)
    _locate_dcs(collector, config, layout)
    # the domain scanned first, then a stable order
    layout.domains.sort(key=lambda d: (_norm(d.dn) != _norm(seed), d.name))
    return layout


def _connector(target: Target) -> Any:
    # a referral must not send this account's credentials to the host it names
    return connect(target, auto_referrals=False)


def _read(conn: Any, target: Target) -> Snapshot:
    return Collector(conn, target).snapshot()


def _other_dc(target: Target, host: str) -> Target:
    """The same credentials and choices for another DC. The port options describe the path to
    the DC the run started from (often a tunnel), so another DC gets the standard ports; a
    probe that was switched off stays off."""
    return replace(
        target,
        host=host,
        port=636 if target.use_ssl else 389,
        smb_port=445,
        plain_port=389 if target.plain_port else 0,
        http_port=80 if target.http_port else 0,
        https_port=443 if target.https_port else 0,
    )


def _open(target: Target, domain: Domain, connector: Connector) -> Any:
    """A connection to a DC that is shown to serve this domain, or CollectError."""
    conn = connector(target)
    try:
        served = _context(conn, "defaultNamingContext")
        if _norm(served) != _norm(domain.dn):
            raise CollectError(f"{target.host} serves {served or 'no domain'}, not {domain.dn}")
    except BaseException:
        conn.unbind()
        raise
    return conn


def _scrub(text: object, target: Target) -> str:
    out = str(text)
    return out.replace(target.password, "***") if target.password else out


def _collect(
    domain: Domain, targets: list[Target], connector: Connector, read: Reader
) -> tuple[Snapshot, Target] | str:
    """A snapshot and the target that reached it, or why there is none. A refused bind is
    final for this domain: each try at another DC would count against the account's lockout."""
    failures = []
    for target in targets[:MAX_DC_TRIES]:
        try:
            conn = _open(target, domain, connector)
        except BindRejected as exc:
            failures.append(_scrub(exc, target))
            break
        except (CollectError, LDAPException, OSError) as exc:
            failures.append(_scrub(exc, target))
            continue
        try:
            return read(conn, target), target
        except Exception as exc:  # one domain's failure must not lose the others
            return f"collection failed: {_scrub(exc, target)}"
        finally:
            conn.unbind()
    if len(targets) > MAX_DC_TRIES and len(failures) == MAX_DC_TRIES:
        failures.append(f"{len(targets) - MAX_DC_TRIES} more domain controllers not tried")
    return "; ".join(failures) or "no domain controller found for this domain"


class _Sessions:
    """One connection per domain while following group members; closed together at the end."""

    def __init__(self, reads: list[_Read], connector: Connector, notes: list[str]) -> None:
        self.reads = {_norm(r.domain.dn): r for r in reads}
        self.connector = connector
        self.notes = notes
        self.open: dict[str, Collector | None] = {}

    def reader(self, domain_dn: str) -> Collector | None:
        key = _norm(domain_dn)
        if key not in self.open:
            read = self.reads.get(key)
            self.open[key] = None
            if read is not None:
                try:
                    conn = _open(read.target, read.domain, self.connector)
                except (CollectError, LDAPException, OSError) as exc:
                    self.notes.append(
                        f"{read.domain.name}: not reachable again for group members: "
                        f"{_scrub(exc, read.target)}"
                    )
                else:
                    self.open[key] = Collector(conn, read.target)
        return self.open[key]

    def close(self) -> None:
        for session in self.open.values():
            if session is not None:
                session.conn.unbind()


def _ask(reader: Collector, base: str, flt: str, **kw: Any) -> list[dict[str, Any]] | None:
    """A read that may be refused or cut off: None, which is not the same as no entries."""
    try:
        return reader.attempt(base, flt, PRINCIPAL_ATTRS, **kw)
    except LDAPException:
        return None


def _domain_of(dn: str, domains: list[Domain]) -> Domain | None:
    """The domain that holds a DN: the longest suffix, so a child is not taken for its parent."""
    key = _norm(dn)
    found = [d for d in domains if key == _norm(d.dn) or key.endswith("," + _norm(d.dn))]
    return max(found, key=lambda d: len(_norm(d.dn)), default=None)


def _kind(classes: set[str]) -> str:
    if "foreignsecurityprincipal" in classes:
        return "foreign"
    if "computer" in classes:
        return "computer"
    return "user" if "user" in classes or "inetorgperson" in classes else "other"


def _holder(entry: dict[str, Any], domain: Domain, via: list[str], primary: bool) -> dict[str, Any]:
    dn = _first(entry, "distinguishedName")
    raw_sid = entry.get("objectsid")
    uac = entry.get("useraccountcontrol")
    return {
        "name": _first(entry, "sAMAccountName") or dn.split(",", 1)[0].split("=", 1)[-1],
        "dn": dn,
        "domain": domain.name,
        "kind": _kind({c.lower() for c in _str(entry.get("objectclass", []))}),
        "sid": sid_to_str(raw_sid[0]) if raw_sid else "",
        "enabled": None if not uac else not _int(entry, "userAccountControl") & UAC.ACCOUNTDISABLE,
        "via": via,
        "primary_group": primary,
    }


def _expand(
    name: str, rid: int, root: Domain, root_sid: str, domains: list[Domain], sessions: _Sessions
) -> dict[str, Any]:
    """Who holds one forest-root group, following nested groups into whichever domain has them."""
    out: dict[str, Any] = {
        "group": name,
        "domain": root.name,
        "status": "read",
        "holders": [],
        "unresolved": [],
    }
    reader = sessions.reader(root.dn)
    found = None
    if reader is not None and root_sid:
        found = _ask(reader, root.dn, f"(objectSid={root_sid}-{rid})")
    if not found or not found[0].get("objectsid"):
        out["status"] = "not_evaluated"
        out["reason"] = f"the group of RID {rid} could not be read in the forest root"
        return out
    holders: dict[str, dict[str, Any]] = {}
    unresolved: list[dict[str, str]] = []
    seen = {_norm(_first(found[0], "distinguishedName"))}
    queue: deque[tuple[Domain, dict[str, Any], list[str]]] = deque([(root, found[0], [])])
    reads = 0

    def add(entry: dict[str, Any], domain: Domain, via: list[str], primary: bool) -> None:
        holder = _holder(entry, domain, via, primary)
        holders[_norm(holder["dn"])] = holder

    def keep_group(entry: dict[str, Any], domain: Domain, via: list[str]) -> None:
        queue.append((domain, entry, [*via, _first(entry, "sAMAccountName") or "(unnamed)"]))

    while queue:
        domain, group, via = queue.popleft()
        group_dn = _first(group, "distinguishedName")
        reader = sessions.reader(domain.dn)
        if reader is None:
            unresolved.append({"name": group_dn, "reason": "its domain could not be read"})
            continue
        if (group_dn.lower(), "member") in reader.ranged:
            unresolved.append({"name": group_dn, "reason": "only part of its member list was read"})
        # primaryGroupID membership never shows in the member attribute
        group_rid = sid_to_str(group["objectsid"][0]).rsplit("-", 1)[-1]
        hidden = _ask(reader, domain.dn, f"(primaryGroupID={group_rid})")
        if hidden is None:
            unresolved.append({"name": group_dn, "reason": "primary-group members not readable"})
        for entry in hidden or []:
            key = _norm(_first(entry, "distinguishedName"))
            if key not in seen:
                seen.add(key)
                add(entry, domain, via, True)
        for member in _str(group.get("member", [])):
            key = _norm(member)
            if key in seen:
                continue
            seen.add(key)
            home = _domain_of(member, domains)
            if home is None:
                unresolved.append({"name": member, "reason": "outside every domain of this forest"})
                continue
            member_reader = sessions.reader(home.dn)
            if member_reader is None:
                unresolved.append({"name": member, "reason": f"{home.name} could not be read"})
                continue
            reads += 1
            if reads > MAX_HOLDER_READS:
                unresolved.append({"name": member, "reason": "read limit reached, not followed"})
                continue
            hit = _ask(member_reader, member, "(objectClass=*)", scope=ldap3.BASE)
            if hit is None:
                unresolved.append({"name": member, "reason": "the read was refused"})
            elif not hit or not hit[0].get("objectclass"):
                unresolved.append(
                    {"name": member, "reason": "not returned: hidden, or not readable"}
                )
            elif "group" in {c.lower() for c in _str(hit[0]["objectclass"])}:
                if hit[0].get("objectsid"):
                    keep_group(hit[0], home, via)
                else:
                    unresolved.append({"name": member, "reason": "group without a readable SID"})
            else:
                add(hit[0], home, via, False)
    if not holders and not unresolved:
        unresolved.append(
            {"name": name, "reason": "no members visible: empty, or hidden from this account"}
        )
    out["holders"] = sorted(holders.values(), key=lambda h: (h["domain"], h["name"].lower()))
    out["unresolved"] = unresolved
    out["status"] = "partial" if unresolved else "read"
    return out


def _groups(
    layout: Layout, reads: list[_Read], connector: Connector, notes: list[str]
) -> dict[str, dict[str, Any]]:
    root = next((r.domain for r in reads if r.domain.root), None)
    if root is None:
        return {
            name: {
                "group": name,
                "domain": dns_name(layout.root_dn) if layout.root_dn else "",
                "status": "not_evaluated",
                "reason": "the forest root domain was not read",
                "holders": [],
                "unresolved": [],
            }
            for name in FOREST_GROUPS
        }
    sessions = _Sessions(reads, connector, notes)
    out: dict[str, dict[str, Any]] = {}
    try:
        reader = sessions.reader(root.dn)
        head = _ask(reader, root.dn, "(objectClass=domain)", scope=ldap3.BASE) if reader else None
        raw = head[0].get("objectsid") if head else None
        sid = sid_to_str(raw[0]) if raw else ""
        for name, rid in FOREST_GROUPS.items():
            out[name] = _expand(name, rid, root, sid, layout.domains, sessions)
    finally:
        sessions.close()
    return out


def is_complete(manifest: dict[str, Any]) -> bool:
    return (
        not manifest.get("partial")
        and all(d.get("status") == "read" for d in manifest["domains"])
        and all(g.get("status") == "read" for g in manifest.get("groups", {}).values())
    )


def run(
    target: Target,
    out: Path,
    analyze: Analyzer | None = None,
    connector: Connector | None = None,
    read: Reader | None = None,
) -> dict[str, Any]:
    """Collect every domain into `out`, keeping forest.json current after each one so that a
    run cut short still says what it did not reach. Returns the manifest."""
    connector = connector or _connector
    read = read or _read
    conn = connector(target)
    try:
        collector = Collector(conn, target)
        layout = discover(collector)
        layout.notes = [*layout.notes, *collector.notes]
    except LDAPException as exc:
        raise CollectError(f"listing the forest failed: {_scrub(exc, target)}") from exc
    finally:
        conn.unbind()
    if (out / MANIFEST).exists():
        raise CollectError(f"{out}: already holds a forest scan; use a new directory")
    out.mkdir(mode=0o700, parents=True, exist_ok=True)

    rows: list[dict[str, Any]] = [
        {
            "domain": d.name,
            "dn": d.dn,
            "netbios": d.netbios,
            "forest_root": d.root,
            "stem": file_stem(d.dn),
            "status": "not_evaluated" if d.skip else "pending",
            "reason": d.skip or "not reached: the run stopped before this domain",
            "dcs": d.dcs,
            "dc": None,
            "snapshot": None,
            "accounts": None,
        }
        for d in layout.domains
    ]
    manifest: dict[str, Any] = {
        "tool": MANIFEST_TOOL,
        "schema": MANIFEST_SCHEMA,
        "version": __version__,
        "collected_at": datetime.now(UTC).isoformat(),
        "root": dns_name(layout.root_dn) if layout.root_dn else "",
        "seed": dns_name(layout.seed_dn),
        "partial": layout.partial,
        "complete": False,
        "domains": rows,
        "referrals": layout.referrals,
        "groups": {},
        "notes": layout.notes,
    }

    def save() -> None:
        write_private(out / MANIFEST, json.dumps(manifest, indent=2) + "\n")

    save()
    reads: list[_Read] = []
    for domain, row in zip(layout.domains, rows, strict=True):
        if domain.skip:
            continue
        if _norm(domain.dn) == _norm(layout.seed_dn):
            targets = [target]
        else:
            targets = [_other_dc(target, host) for host in domain.dcs]
        got = _collect(domain, targets, connector, read)
        if isinstance(got, str):
            row.update(status="not_evaluated", reason=got)
            save()
            continue
        snap, used = got
        name = f"{row['stem']}{SNAPSHOT_SUFFIX}"
        write_private(out / name, json.dumps(snap.to_json(), indent=2))
        row.update(
            status="read", reason=None, dc=used.host, snapshot=name, accounts=len(snap.accounts)
        )
        reads.append(_Read(domain, used))
        save()
        if analyze is not None:
            try:
                analyze(snap, row["stem"])
            except Exception as exc:  # the snapshot is saved; the next domains still run
                row.update(status="not_evaluated", reason=f"analysis failed: {exc}")
        del snap
        save()
    manifest["groups"] = _groups(layout, reads, connector, layout.notes)
    manifest["complete"] = is_complete(manifest)
    save()
    return manifest
