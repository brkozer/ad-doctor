"""Scale benchmark: build a synthetic domain and time every analysis stage.

    uv run python scripts/bench.py --users 100000

The domain is shaped like a large enterprise: users and computers spread over a deep
OU tree, nested groups, delegated OU permissions that inherit, a few hundred GPOs and
templates, and a handful of real misconfigurations so every stage has work to do.
Nothing touches the network; the numbers measure analysis only (collection is bounded
by the DC's LDAP paging).
"""

from __future__ import annotations

import argparse
import json
import random
import resource
import time
from collections.abc import Callable
from datetime import UTC, datetime, timedelta
from typing import Any

from ad_doctor import cut, opengraph, paths, sd
from ad_doctor.checks import run_all
from ad_doctor.model import (
    UAC,
    Account,
    CertTemplate,
    DirObject,
    DomainPolicy,
    GpLink,
    Gpo,
    Snapshot,
)

SID = "S-1-5-21-1000-2000-3000"
DN = "DC=bench,DC=test"
NOW = datetime(2026, 11, 1, tzinfo=UTC)
USER_ACCOUNT = 0x200
WORKSTATION = 0x1000


def build(users: int, seed: int) -> Snapshot:
    rng = random.Random(seed)
    rid = iter(range(10_000, 10_000_000))

    # OU tree: regions > sites > departments
    ous: list[DirObject] = []
    leaves: list[str] = []
    for r in range(8):
        region = f"OU=Region{r},{DN}"
        ous.append(DirObject(region, f"Region{r}", "ou"))
        for s in range(10):
            site = f"OU=Site{s},{region}"
            ous.append(DirObject(site, f"Site{s}", "ou"))
            for d in range(6):
                dept = f"OU=Dept{d},{site}"
                ous.append(DirObject(dept, f"Dept{d}", "ou"))
                leaves.append(dept)

    accounts: list[Account] = []
    for i in range(users):
        ou = rng.choice(leaves)
        accounts.append(
            Account(
                dn=f"CN=user{i},{ou}",
                sam=f"user{i}",
                uac=USER_ACCOUNT | (UAC.DONT_EXPIRE_PASSWORD if i % 50 == 0 else 0),
                sid=f"{SID}-{next(rid)}",
                pwd_last_set=NOW - timedelta(days=rng.randint(1, 900)),
                last_logon=NOW - timedelta(days=rng.randint(0, 400)),
                spns=[f"http/app{i}.bench.test"] if i % 500 == 0 else [],
            )
        )
    for i in range(users // 3):
        ou = rng.choice(leaves)
        accounts.append(
            Account(
                dn=f"CN=WS{i},{ou}",
                sam=f"WS{i}$",
                uac=WORKSTATION,
                is_computer=True,
                sid=f"{SID}-{next(rid)}",
                laps=i % 10 != 0,
                os="Windows 11 Enterprise",
                last_logon=NOW - timedelta(days=rng.randint(0, 200)),
            )
        )
    for i in range(4):
        accounts.append(
            Account(
                dn=f"CN=DC{i},OU=Domain Controllers,{DN}",
                sam=f"DC{i}$",
                uac=0x2000 | UAC.TRUSTED_FOR_DELEGATION,
                is_computer=True,
                sid=f"{SID}-{next(rid)}",
                dns_host=f"dc{i}.bench.test",
            )
        )
    accounts.append(
        Account(dn=f"CN=krbtgt,CN=Users,{DN}", sam="krbtgt", uac=0x202, sid=f"{SID}-502",
                pwd_last_set=NOW - timedelta(days=30))
    )  # fmt: skip
    people = [a for a in accounts if not a.is_computer and a.sam.startswith("user")]

    # groups: one per department plus role groups, nested two or three levels deep
    groups: list[DirObject] = []
    for i in range(max(users // 10, 50)):
        g = DirObject(f"CN=grp{i},OU=Groups,{DN}", f"grp{i}", "group", sid=f"{SID}-{next(rid)}")
        g.members = [rng.choice(people).dn for _ in range(rng.randint(5, 40))]
        groups.append(g)
    for g in groups:
        if rng.random() < 0.3:
            g.members.append(rng.choice(groups).dn)
    admins = [rng.choice(people) for _ in range(12)]
    da = DirObject(f"CN=Domain Admins,CN=Users,{DN}", "Domain Admins", "group",
                   sid=f"{SID}-512", members=[a.dn for a in admins])  # fmt: skip
    for a in admins:
        a.admin_count = True

    # delegated permissions: helpdesk groups manage users and groups in their OUs
    for ou in ous:
        if rng.random() < 0.4:
            helpdesk = rng.choice(groups).sid
            ou.inheritable = [
                sd.Ace(helpdesk, sd.CONTROL_ACCESS, sd.RESET_PASSWORD, sd.USER_CLASS),
                sd.Ace(helpdesk, sd.WRITE_PROPERTY, sd.MEMBER, sd.GROUP_CLASS),
            ]
            ou.aces = [sd.Ace(helpdesk, sd.GENERIC_ALL)] if rng.random() < 0.05 else []
    # a few real misconfigurations on groups and one path into tier 0
    for g in rng.sample(groups, max(len(groups) // 100, 3)):
        g.aces.append(sd.Ace(rng.choice(groups).sid, sd.GENERIC_ALL))
    risky = rng.choice(groups)
    da.members.append(risky.dn)
    risky.aces.append(sd.Ace(rng.choice(groups).sid, sd.WRITE_PROPERTY, sd.MEMBER))

    # the default DACL every object carries (SYSTEM, admins, read access for users)
    read = 0x20094
    defaults = [
        sd.Ace("S-1-5-18", sd.FULL_CONTROL),
        sd.Ace(f"{SID}-512", sd.FULL_CONTROL),
        sd.Ace("S-1-5-32-544", sd.FULL_CONTROL),
        sd.Ace(f"{SID}-519", sd.FULL_CONTROL),
        sd.Ace("S-1-5-32-548", sd.FULL_CONTROL),
        sd.Ace("S-1-5-11", read),
        sd.Ace("S-1-5-10", read),
        sd.Ace("S-1-5-32-554", read),
        sd.Ace("S-1-5-9", read),
        sd.Ace("S-1-5-32-561", read),
        sd.Ace("S-1-5-32-560", read),
        sd.Ace(f"{SID}-553", read),
    ]
    for o in [*ous, *groups, da]:
        o.aces = defaults + o.aces
        o.owner = f"{SID}-512"

    head = DirObject(DN, "bench.test", "domain")
    # most GPOs apply to everyone; every tenth to Domain Computers or one group. Links
    # go to the head, to OUs at every level, and one OU in ten blocks inheritance
    gpos = []
    for i in range(300):
        where = DN if i < 3 else ous[i % len(ous)].dn
        kind = "domain" if i < 3 else "ou"
        who = "S-1-5-11"
        if i % 10 == 5:
            who = f"{SID}-515" if i % 20 == 5 else groups[i % len(groups)].sid
        aces = [
            sd.Ace(who, read),
            sd.Ace(who, sd.CONTROL_ACCESS, sd.APPLY_GROUP_POLICY),
        ]
        if i % 40 == 0:
            aces.append(sd.Ace(rng.choice(groups).sid, sd.GENERIC_WRITE))
        gpos.append(
            Gpo(
                f"Policy {i}",
                f"{{{i:08X}-0000-0000-0000-000000000000}}",
                ["domain"] if i < 3 else [],
                aces,
                links=[GpLink(where, kind, True, i % 30 == 7, 0)],
            )
        )
    for ou in ous[::10]:
        ou.gp_blocked = True
    templates = [
        CertTemplate(f"Tmpl{i}", i % 3 == 0, i == 7, False, 0, ["1.3.6.1.5.5.7.3.2"],
                     [sd.Ace("S-1-5-21-1000-2000-3000-513", sd.CONTROL_ACCESS, sd.CERT_ENROLL)])
        for i in range(60)
    ]  # fmt: skip
    # the collector lists transitive members, so nested admins are tier 0 as in a real
    # collection
    by_dn = {g.dn: g for g in groups}
    admin_dns: set[str] = set()
    todo, seen = list(da.members), set()
    while todo:
        dn = todo.pop()
        if dn in seen:
            continue
        seen.add(dn)
        if dn in by_dn:
            todo += by_dn[dn].members
        else:
            admin_dns.add(dn)
    return Snapshot(
        domain="bench.test",
        domain_dn=DN,
        domain_sid=SID,
        collected_at=NOW,
        policy=DomainPolicy(12, True, 10, 365, 10, 10),
        accounts=accounts,
        privileged={"Domain Admins": sorted(admin_dns)},
        protected_users=[],
        templates=templates,
        acls={"domain": []},
        gpos=gpos,
        objects=[*ous, *groups, da, head],
    )


def timed(label: str, fn: Callable[[], Any], rows: list[tuple[str, float]]) -> Any:
    start = time.perf_counter()
    result = fn()
    rows.append((label, time.perf_counter() - start))
    return result


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--users", type=int, default=100_000)
    parser.add_argument("--seed", type=int, default=7)
    parser.add_argument("--json", action="store_true", help="print the results as JSON")
    args = parser.parse_args()

    rows: list[tuple[str, float]] = []
    snap = timed("build synthetic snapshot", lambda: build(args.users, args.seed), rows)
    text = timed("serialize to JSON", lambda: json.dumps(snap.to_json()), rows)
    snap = timed("load snapshot", lambda: Snapshot.from_json(json.loads(text)), rows)
    findings = timed("run every check (incl. paths)", lambda: run_all(snap), rows)
    g = timed("build control graph", lambda: paths.build(snap), rows)
    timed("paths to tier 0", lambda: paths.paths_to_tier0(g), rows)
    graph = timed("OpenGraph export", lambda: opengraph.export(snap, g=g), rows)
    edges = sum(len(v) for v in g.edges.values())
    opengraph_edges = len(graph["graph"]["edges"])
    peak_mb = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss / 1024
    snapshot_mb = round(len(text) / 2**20, 1)
    text, graph = "", {}  # let go of the big ones before the what-if stage
    g.edges.clear()
    gp = timed("control graph with provenance", lambda: paths.build(snap, provenance=True), rows)
    plan = timed("plan (what-if, paths only)", lambda: cut.plan(snap, gp), rows)
    plan_peak_mb = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss / 1024

    aces = sum(len(o.aces) + len(o.inheritable) for o in snap.objects)
    summary = {
        "users": sum(1 for a in snap.accounts if not a.is_computer),
        "computers": sum(1 for a in snap.accounts if a.is_computer),
        "objects": len(snap.objects),
        "aces": aces,
        "snapshot_mb": snapshot_mb,
        "graph_edges": edges,
        "opengraph_edges": opengraph_edges,
        "findings": len(findings),
        "plan_changes": len(plan.changes),
        "plan_cost": plan.cost,
        "plan_proven": plan.proven,
        "peak_rss_mb": round(peak_mb),
        "peak_rss_mb_with_plan": round(plan_peak_mb),
        "seconds": {label: round(sec, 2) for label, sec in rows},
    }
    if args.json:
        print(json.dumps(summary, indent=2))
        return
    for key, value in summary.items():
        if key != "seconds":
            print(f"{key:18} {value}")
    for label, sec in rows:
        print(f"{label:32} {sec:7.2f} s")


if __name__ == "__main__":
    main()
