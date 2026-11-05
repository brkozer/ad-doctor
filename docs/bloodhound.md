# BloodHound export

`ad-doctor export-graph` writes the control graph as a BloodHound
[OpenGraph](https://bloodhound.specterops.io/) payload, so the relationships ad-doctor finds
can be explored next to SharpHound data instead of in a second tool.

```bash
ad-doctor export-graph 2026-11.json -o graph.json
ad-doctor export-graph 2026-11.json -o graph.json --paths-only
```

Load `graph.json` through BloodHound CE's File Ingest, which accepts OpenGraph JSON.

## SIDs attach it to an existing graph

Principals keep their real SIDs in the export. BloodHound keys nodes by SID, so ad-doctor's
edges land on the same nodes as a SharpHound collection of the domain: you get ad-doctor's
view (takeover ACLs, DCSync, GPO-granted local admin, exploitable templates and CA rights, an
Entra Connect server holding its sync account) overlaid on the standard graph, rather than a
disconnected copy.

## Edges

Control edges that form attack paths are traversable: group membership, takeover ACEs,
ownership, DCSync, GPO links, exploitable templates, gMSA readers, `ADD_AdminTo`,
`ADD_LocalBackupOperator`, `ADD_HyperVAdmin`, `ADD_MemberOfViaGPO`, `ADD_HostsSyncAccount`,
and the ESC7 edges `ADD_ManageCA` / `ADD_ManageCertificates`.

Remote-logon rights that GPOs grant &mdash; `ADD_CanRDP`, `ADD_CanPSRemote`,
`ADD_ExecuteDCOM` &mdash; are exported with `traversable: false`: a remote logon is a foothold,
not control, so ad-doctor's own path search does not follow them, and they are marked so
BloodHound can treat them the same way. Edges carry `gpo` and `caveats` properties where they
apply.

## `--paths-only`

With `--paths-only` the export keeps only the nodes and edges that lie on a path from a
non-tier-0 principal to tier 0 (a non-traversable logon edge is kept only when its end node is
kept). That is the smaller, more readable graph for showing how an ordinary user reaches
domain control; drop the flag for the full picture.
