# Force-shrink: run source seed cleanup before etcd migration

Date: 2026-11-17
Branch: `gep-39/force-shrink`
Area: `pkg/gardenlet/controller/shoot/shoot/reconciler_livemigrate.go`

## Problem

The live control-plane migration flow runs these top-level steps, alternating
between the source and destination gardenlets (owner in parentheses):

1. `sourceEtcdReadyForPeerJoin` (Source)
2. `destinationEtcdPeersJoined` (Destination)
3. `migrateExtensionsNeededBeforeKubeAPIServer` (Source)
4. `destinationKubeAPIServerReady` (Destination)
5. `sourceSeedCleanup` (Source)
6. `etcdMigrationComplete` (Destination)
7. `migrationCompleted` (Destination)
8. `sourceSeedFinalTeardown` (Source)

In the **normal** flow the irreversible etcd migration (scale destination etcd
to 3, remove source members, switch DNS) happens in step 6
(`etcdMigrationComplete`), which runs *after* step 5 (`sourceSeedCleanup`). So
source cleanup already precedes etcd-member removal.

The **force-shrink** path (commit "Run etcd migration before destination
kube-apiserver on force-shrink") hoists the `etcdMigrationCompleteTaskGroup`
*into* step 4 (`destinationKubeAPIServerReady`) so the destination apiserver's
linearized reads are served from a local quorum. This moves the etcd migration
*ahead* of step 5 — source members are removed before `sourceSeedCleanup` runs.

That ordering is wrong. `sourceSeedCleanup` →
`MigrateAndDeleteManagedResourcesTaskGroup(true)` deploys gardener-resource-manager
on the source, scales it up, and **deletes managed resources from the shoot's
namespace** via GRM talking to the *shoot* kube-apiserver. Once the etcd
migration removes the source members and cuts DNS over:

- the source shoot-apiserver goes down, so this cleanup can no longer reach a
  working apiserver through the expected path, and
- after DNS cutover, `api.<internalDomain>` resolves to the destination, so the
  source GRM would act against the destination apiserver the destination is
  simultaneously bringing up.

So in force-shrink the source cleanup must complete **before** the etcd
migration removes the source members.

## Constraint

Step 4 (`destinationKubeAPIServerReady`) is owned by the **destination**
gardenlet and the etcd migration is embedded in it; the destination cannot
perform source-side cleanup. Therefore the cleanup must execute in a
**source-owned step that runs before step 4** when the force-shrink annotation
is present. `sourceSeedCleanup` is already a source-owned task group, so the fix
is to reorder it ahead of `destinationKubeAPIServerReady` for force-shrink only.

### Why the etcd migration stays embedded in step 4 (not pulled out as its own step)

The reorder deliberately does **not** un-embed the etcd migration.
`etcdMigrationCompleteTaskGroup` deploys the destination internal/external DNS
records, which target the kube-apiserver address that `destinationKubeAPIServerReady`
creates (`deployService`/`waitService`), while the apiserver *pod* needs the
shrunk local quorum. The real ordering inside the step is:

```
deploy KAS service → etcd shrink (DNS cutover + remove source members) → deploy KAS pod
```

Pulling the etcd migration into a standalone step before `destinationKubeAPIServerReady`
would run the DNS reconcile before the apiserver service exists. So the embedding
stays; the `sourceSeedCleanup` reorder is orthogonal and only guarantees source
cleanup finishes before the source etcd members are removed.

## Entry state and condition reset

Force-shrink is gated by `ValidateForceShrinkEtcd`
(`pkg/api/core/validation/shoot.go`): the annotation can only be newly added
when `DestinationEtcdPeersJoined == True` and `DestinationKubeAPIServerReady ==
False`. At that single entry point the live-migration conditions are:

- `SourceEtcdPreparedForPeerJoin`, `DestinationEtcdPeersJoined`,
  `MigrateExtensionsNeededBeforeKubeAPIServer`: True
- `DestinationKubeAPIServerReady`: False (exists)
- `SourceSeedCleanup`, `EtcdMigrationComplete`: **not set**

No conditions need to be reset. In the reordered graph the only `SkipIf` that
could wrongly skip the now-earlier `sourceSeedCleanup` is its
`SkipIf(EtcdMigrationComplete exists)`, and that condition is guaranteed absent
at the validated entry point. `DestinationKubeAPIServerReady == False` does not
block re-running step 4: `executeStepOrWait` does not gate a step on its own
condition, so the destination re-runs `destinationKubeAPIServerReady` (now after
`sourceSeedCleanup`) and drives it to True.

**Invariant this relies on:** the validation gate. If it is ever relaxed to
allow force-shrink after `SourceSeedCleanup` or `EtcdMigrationComplete` has
started, the reorder could skip cleanup and a reset of those two conditions
would become necessary. Noted here so the coupling is explicit.

## Design

Swap three dependency edges in the flow graph builder in
`runLiveMigrateShootFlow`, gated on `forceShrinkEtcd` (already computed from the
annotation and identical on both gardenlets, so both compile the same graph and
the condition-based peer-wait handshake follows the edges):

| Task | normal dependency | force-shrink dependency |
|---|---|---|
| `sourceSeedCleanup` (S) | `destinationKubeAPIServerReady` | `migrateExtensionsNeededBeforeKubeAPIServer` |
| `destinationKubeAPIServerReady` (D) | `migrateExtensionsNeededBeforeKubeAPIServer` | `sourceSeedCleanup` |
| `etcdMigrationComplete` (D) | `sourceSeedCleanup` | `destinationKubeAPIServerReady` |

Resulting force-shrink order:

```
migrateExtsBeforeKAS(S) → sourceSeedCleanup(S) → destKASReady + etcdMigration(D)
  → etcdMigrationComplete(D, no-ops via skipIfSourceMembersAlreadyRemoved)
  → migrationCompleted(D) → sourceSeedFinalTeardown(S)
```

In force-shrink, step 6 (`etcdMigrationComplete`) still runs as a step but its
tasks no-op because `skipIfSourceMembersAlreadyRemoved` short-circuits them
(source members were already removed inside step 4). Its dependency is retargeted
to `destinationKubeAPIServerReady` so it cannot run before the real migration.

### What does not change

- No new fields, conditions, or task groups; no edits to any `*TaskGroup`
  helper.
- Downstream edges unchanged: `migrationCompleted` → `etcdMigrationComplete`,
  `sourceSeedFinalTeardown` → `migrationCompleted`.
- The `SkipIf` resumption guards on each task group key off *later* conditions
  (`EtcdMigrationComplete`, `MigrationCompleted`, `SourceSeedFinalTeardown`),
  which are still unset at the reordered points, so none skips prematurely.
- `liveMigrationConditionOrder` is display-sort only and stays as is.

### Reverse-dependency check (why cleanup-first is safe for the destination)

`destinationKubeAPIServerReady` deploys a fresh *destination* control plane and
restores from `ShootState`. `sourceSeedCleanup`'s migrate steps only *persist
additional* state (infrastructure/control-plane state the destination restores
later in `destinationCompletion`, not in step 4). No task in step 4 reads a live
source-seed resource that cleanup destroys, so running cleanup first is safe and
strictly gives step 4 a more complete `ShootState`.

## Testing

The flow graph is built inline in `runLiveMigrateShootFlow` using local
variables; the task dependencies are not exposed, and the existing test file
(`reconciler_livemigrate_test.go`) only covers `checkGardenletVersionParity`.
Adding a graph-shape unit test would require refactoring the builder to return
an inspectable structure — disproportionate for a three-edge swap and out of
scope.

Verification for this change:

- `go build` + `go vet` the package (compilation proves the conditional edge
  wiring references valid task IDs and has no cycles at build time).
- The force-shrink end-to-end migration test exercises the reordered flow
  against a real source/destination seed pair; that is the authoritative check
  that source cleanup completes before the source apiserver goes down.

## Additional fix: embedded etcd-migration DNS must wait for the apiserver service

Found while reviewing the embedding (pre-existing on this branch, not introduced
by the reorder). In force-shrink the `etcdMigrationCompleteTaskGroup` is embedded
in `destinationKubeAPIServerReady` and was added with
`TasksWithDependencies(refreshShootState)`. Its first tasks re-point the shoot's
internal/external apiserver DNS records, whose target comes from
`b.APIServerAddress`. That field is populated only by the kube-apiserver
Service's ingress callback, which fires inside `KubeAPIServerService.Wait`
(`waitService`). The destination always runs in restore phase, so the DNS
reconcile takes the `Restore` path, which rebuilds the record spec (including the
target `Values`) from the in-memory component values — nil until `SetValues` runs.

Because the embedded group depended only on `refreshShootState` (a much shorter
chain than `… → deployService → waitService`), the DNS reconcile raced ahead of
`waitService` and restored the records with an empty target, stranding the
destination apiserver behind unresolvable DNS. The race recurs each reconcile, so
it does not reliably self-heal.

Fix: depend the embedded group on `waitService` instead of `refreshShootState`.
This gives the correct force-shrink order — `waitService` (sets
`b.APIServerAddress`) → etcd migration (DNS re-point + source-member removal) →
apiserver pod (local quorum). No cycle: `reconcileKubeAPIServer` already depends
on both `waitService` and the etcd-migration group.

## Out of scope

- Any change to the task-group contents (managed resources, infra, control
  plane, DNS migration logic).
- The force-shrink validation/annotation handling (already implemented on this
  branch).
