# BloodHound export

`ad-doctor export-graph` writes the control graph as a BloodHound
[OpenGraph](https://bloodhound.specterops.io/) payload, so the relationships ad-doctor finds
can be explored next to SharpHound data instead of in a second tool.

```bash
ad-doctor export-graph 2026-11.json -o graph.json
ad-doctor export-graph 2026-11.json -o graph.json --paths-only
```

Load `graph.json` through BloodHound CE's File Ingest, which accepts OpenGraph JSON.

## What BloodHound does with it

The payload is a generic OpenGraph graph with no extension schema. According to BloodHound's
[OpenGraph FAQ](https://bloodhound.specterops.io/opengraph/faq), generic graphs get Search and
Cypher queries, but not Pathfinding, findings or analysis: those need traversable relationship
kinds defined in an extension schema, and generic data counts as non-traversable.

So you can find ad-doctor's nodes and query its edges, but BloodHound's Pathfinding will not walk
them. For attack paths use ad-doctor itself: `AD-PATH-001` and `ad-doctor blast-radius`.

## SIDs attach it to an existing graph

Principals keep their real SIDs in the export. BloodHound keys nodes by SID, so ad-doctor's
edges land on the same nodes as a SharpHound collection of the domain: you get ad-doctor's
view (takeover ACLs, DCSync, GPO-granted local admin, exploitable templates and CA rights, an
Entra Connect server holding its sync account) overlaid on the standard graph, rather than a
disconnected copy.

## Edges

Every edge carries a `traversable` property. It is ad-doctor's own marker for your Cypher
queries, not a BloodHound setting, and BloodHound ignores it for pathfinding.

It is `true` on the control edges ad-doctor's path search follows: group membership, takeover
ACEs, ownership, DCSync, GPO links, exploitable templates, gMSA readers, `ADD_AdminTo`,
`ADD_LocalBackupOperator`, `ADD_HyperVAdmin`, `ADD_MemberOfViaGPO`, `ADD_HostsSyncAccount`,
and the ESC7 edges `ADD_ManageCA` / `ADD_ManageCertificates`.

It is `false` on the remote-logon rights that GPOs grant: `ADD_CanRDP`, `ADD_CanPSRemote`,
`ADD_ExecuteDCOM`. A remote logon is a foothold, not control, so ad-doctor's path search does
not follow them. Edges carry `gpo` and `caveats` properties where they apply.

## Removing the data again

The payload sets `source_kind` to `ADDoctor`. The FAQ warns that `source_kind` also lands on the
AD nodes a payload refers to, so deleting that source can delete those nodes from your SharpHound
data too. Expect to ingest SharpHound again after removing an ad-doctor import, or follow the
two-step upload in the FAQ.

## `--paths-only`

With `--paths-only` the export keeps only the nodes and edges that lie on a path from a
non-tier-0 principal to tier 0 (a remote-logon edge is kept only when its end node is
kept). That is the smaller, more readable graph for showing how an ordinary user reaches
domain control; drop the flag for the full picture.
