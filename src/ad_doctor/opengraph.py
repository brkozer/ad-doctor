"""Export the control graph as a BloodHound OpenGraph payload.

Principals keep their SID as the node id, the identifier SharpHound uses, so the edges
attach to an existing BloodHound graph of the same domain; well-known SIDs get the
domain prefix SharpHound gives them. Objects without a SID (OUs, GPOs, templates, the
domain head) get a stable hashed id. Every kind carries the ADD_ prefix so nothing
collides with BloodHound's built-in kinds or is removed by its post-processing.
"""

from __future__ import annotations

import hashlib
import re
from typing import Any

from .model import Snapshot
from .paths import Graph, build, paths_to_tier0

SOURCE_KIND = "ADDoctor"
PREFIX = "ADD_"

EDGE_KINDS = {
    "member of": "MemberOf",
    "owns": "Owns",
    "full control": "FullControl",
    "write/WriteDacl/WriteOwner": "WriteDaclOwner",
    "write msDS-KeyCredentialLink": "WriteKeyCredentialLink",
    "write RBCD": "WriteRBCD",
    "write members": "WriteMembers",
    "add self": "AddSelf",
    "write altSecurityIdentities (ESC14)": "WriteAltSecurityIdentities",
    "write SPN": "WriteSPN",
    "reset password": "ResetPassword",
    "link GPOs": "LinkGPOs",
    "DCSync": "DCSync",
    "contains": "Contains",
    "enroll (ESC1-3)": "EnrollExploitableTemplate",
    "write template (ESC4)": "WriteTemplate",
    "read gMSA password": "ReadGMSAPassword",
    "ManageCA (ESC7)": "ManageCA",
    "ManageCertificates (ESC7)": "ManageCertificates",
    "admin to": "AdminTo",
    "backup operator on": "LocalBackupOperator",
    "Hyper-V admin on": "HyperVAdmin",
    "hosts sync account": "HostsSyncAccount",
    "can RDP": "CanRDP",
    "can PSRemote": "CanPSRemote",
    "DCOM": "ExecuteDCOM",
}
INHERITED = " (inherited)"
VIA_GPO = " via GPO "


def edge_kinds(label: str) -> list[tuple[str, bool]]:
    """(edge kind, inherited) for each right in a path label such as 'a, b (inherited)'."""
    if VIA_GPO in label:
        # the GPO's name goes into the edge properties, never into the kind
        right = label.split(VIA_GPO, 1)[0]
        kind = "MemberOfViaGPO" if right == "member of" else EDGE_KINDS.get(right, "Controls")
        return [(PREFIX + kind, False)]
    inherited = label.endswith(INHERITED)
    label = label.removesuffix(INHERITED)
    if label.startswith("linked to "):
        return [(PREFIX + "GPLink", inherited)]
    # 'write/WriteDacl/WriteOwner' contains no comma; other labels join rights with ', '
    parts = [label] if label in EDGE_KINDS else label.split(", ")
    out = []
    for part in parts:
        kind = EDGE_KINDS.get(part) or re.sub(r"[^A-Za-z0-9]+", "", part.title()) or "Controls"
        out.append((PREFIX + kind, inherited))
    return out


def node_id(snap: Snapshot, node: str) -> str:
    if node.startswith("sid:"):
        sid = node[4:]
        if sid.startswith("S-1-5-21-"):
            return sid.upper()
        return f"{snap.domain.upper()}-{sid.upper()}"
    digest = hashlib.sha1(node.encode("utf-8"), usedforsecurity=False).hexdigest()[:20]
    return f"ADD-{digest.upper()}"  # no colons: OpenGraph ids must not contain them


def export(snap: Snapshot, paths_only: bool = False, g: Graph | None = None) -> dict[str, Any]:
    g = g or build(snap)
    found = paths_to_tier0(g)
    keep: set[str] | None = None
    if paths_only:
        keep = set(g.tier0) | set(found)
    nodes: dict[str, dict[str, Any]] = {}
    edges = []

    def add_node(node: str) -> str:
        nid = node_id(snap, node)
        if nid not in nodes:
            props: dict[str, Any] = {
                "name": g.name(node).upper(),
                "tier0": node in g.tier0,
                "pathtotier0": node in found,
            }
            if node in found:
                props["hopstotier0"] = len(found[node].steps)
            if node.startswith("dn:"):
                props["distinguishedname"] = node[3:].upper()
            kind = "Principal" if node.startswith("sid:") else "Object"
            nodes[nid] = {"id": nid, "kinds": [PREFIX + kind], "properties": props}
        return nid

    for traversable, graph_edges in ((True, g.edges), (False, g.logon_edges)):
        for src in sorted(graph_edges):
            for dst, label in graph_edges[src]:
                # a logon edge is kept when it ends on a kept node
                if keep is not None and (dst not in keep or (traversable and src not in keep)):
                    continue
                start, end = add_node(src), add_node(dst)
                extra = g.edge_props.get((src, dst, label), {})
                for kind, inherited in edge_kinds(label):
                    props = {"label": label, "inherited": inherited, "traversable": traversable}
                    edges.append(
                        {
                            "kind": kind,
                            "start": {"value": start, "match_by": "id"},
                            "end": {"value": end, "match_by": "id"},
                            "properties": {**props, **extra},
                        }
                    )
    for node in g.tier0:  # tier-0 nodes appear even when nothing points at them
        add_node(node)
    return {
        "metadata": {"source_kind": SOURCE_KIND},
        "graph": {"nodes": sorted(nodes.values(), key=lambda n: n["id"]), "edges": edges},
    }
