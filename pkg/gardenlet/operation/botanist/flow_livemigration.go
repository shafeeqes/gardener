// SPDX-FileCopyrightText: Contributors to the Gardener project
//
// SPDX-License-Identifier: Apache-2.0

package botanist

import (
	"context"
	"time"

	v1beta1helper "github.com/gardener/gardener/pkg/api/core/v1beta1/helper"
	"github.com/gardener/gardener/pkg/utils/flow"
	gardenerutils "github.com/gardener/gardener/pkg/utils/gardener"
	shootstate "github.com/gardener/gardener/pkg/utils/gardener/shootstate"
)

// TaskGroupSourceEtcdPreparedForPeerJoin is a flow.TaskID for a logical flow.TaskGroup.
const TaskGroupSourceEtcdPreparedForPeerJoin flow.TaskID = "TaskGroupSourceEtcdPreparedForPeerJoin"

// SourceEtcdPreparedForPeerJoinTaskGroup returns the flow.TaskGroup for making the source etcd ready for peer join.
func (b *Botanist) SourceEtcdPreparedForPeerJoinTaskGroup() flow.TaskGroup {
	var (
		g = flow.NewTaskGroup(TaskGroupSourceEtcdPreparedForPeerJoin)

		deployEtcdPeerExposure = g.Add(flow.Task{
			Name: "Deploying etcd peer exposure",
			Fn:   b.DeployEtcdMemberExposure,
		})
		persistShootState = g.Add(flow.Task{
			Name: "Persisting shoot state",
			Fn: func(ctx context.Context) error {
				return shootstate.Deploy(ctx, b.Clock, b.GardenClient, b.SeedClientSet.Client(), b.Shoot.GetInfo(), b.Shoot.ControlPlaneNamespace, false)
			},
			Dependencies: flow.NewTaskIDs(deployEtcdPeerExposure),
		})
		initSecretsManagement = g.Add(flow.Task{
			Name:         "Initializing secrets management",
			Fn:           b.InitializeSecretsManagement,
			Dependencies: flow.NewTaskIDs(persistShootState),
		})
		deployEtcd = g.Add(flow.Task{
			Name:         "Deploying etcd",
			Fn:           b.DeployEtcd,
			Dependencies: flow.NewTaskIDs(initSecretsManagement),
		})
		waitEtcdsReady = g.Add(flow.Task{
			Name:         "Waiting until etcds are ready",
			Fn:           b.WaitUntilEtcdsReady,
			Dependencies: flow.NewTaskIDs(deployEtcd),
		})
		migrateBackupEntry = g.Add(flow.Task{
			Name:         "Migrating backup entry",
			Fn:           b.Shoot.Components.BackupEntry.Migrate,
			Dependencies: flow.NewTaskIDs(waitEtcdsReady),
		})
		_ = g.Add(flow.Task{
			Name:         "Waiting until backup entry has been migrated",
			Fn:           b.Shoot.Components.BackupEntry.WaitMigrate,
			Dependencies: flow.NewTaskIDs(migrateBackupEntry),
		})
	)

	return g
}

// TaskGroupDestinationEtcdPeersJoined is a flow.TaskID for a logical flow.TaskGroup.
const TaskGroupDestinationEtcdPeersJoined flow.TaskID = "TaskGroupDestinationEtcdPeersJoined"

// DestinationEtcdPeersJoinedTaskGroup returns the flow.TaskGroup for joining the destination etcd to the source cluster.
func (b *Botanist) DestinationEtcdPeersJoinedTaskGroup() flow.TaskGroup {
	var (
		g = flow.NewTaskGroup(TaskGroupDestinationEtcdPeersJoined)

		// Refresh the in-memory ShootState before any restore step: the source persisted it in the preceding step,
		// but the destination botanist was built before it existed, so its copy is still nil.
		refreshShootState = g.Add(flow.Task{
			Name: "Refreshing shoot state",
			Fn:   b.RefreshShootStateForLiveMigration,
		})
		deployControlPlaneNamespace = g.Add(flow.Task{
			Name:         "Deploying control plane namespace",
			Fn:           b.DeployControlPlaneNamespace,
			Dependencies: flow.NewTaskIDs(refreshShootState),
		})
		deployEtcdPeerExposure = g.Add(flow.Task{
			Name:         "Deploying etcd peer exposure",
			Fn:           b.DeployEtcdMemberExposure,
			Dependencies: flow.NewTaskIDs(deployControlPlaneNamespace),
		})
		initSecretsManagement = g.Add(flow.Task{
			Name:         "Initializing secrets management",
			Fn:           b.InitializeSecretsManagement,
			Dependencies: flow.NewTaskIDs(deployEtcdPeerExposure),
		})
		// The source backup entry is deployed to ensure that the data in the source seed's backup bucket
		// is properly cleaned up at a later stage of the flow.
		deploySourceBackupEntry = g.Add(flow.Task{
			Name:         "Deploying source backup entry",
			Fn:           b.DeploySourceBackupEntry,
			Dependencies: flow.NewTaskIDs(deployControlPlaneNamespace),
		})
		waitSourceBackupEntryReady = g.Add(flow.Task{
			Name:         "Waiting until source backup entry is ready",
			Fn:           b.Shoot.Components.SourceBackupEntry.Wait,
			Dependencies: flow.NewTaskIDs(deploySourceBackupEntry),
		})
		restoreBackupEntry = g.Add(flow.Task{
			Name: "Restoring backup entry",
			Fn: func(ctx context.Context) error {
				return b.Shoot.Components.BackupEntry.Restore(ctx, nil)
			},
			Dependencies: flow.NewTaskIDs(waitSourceBackupEntryReady),
		})
		waitBackupEntryReady = g.Add(flow.Task{
			Name:         "Waiting until backup entry is ready",
			Fn:           b.Shoot.Components.BackupEntry.Wait,
			Dependencies: flow.NewTaskIDs(restoreBackupEntry),
		})
		deployEtcd = g.Add(flow.Task{
			Name:         "Deploying etcd",
			Fn:           b.DeployEtcd,
			Dependencies: flow.NewTaskIDs(initSecretsManagement, deployEtcdPeerExposure, waitBackupEntryReady),
		})
		_ = g.Add(flow.Task{
			Name:         "Waiting until etcds are ready",
			Fn:           b.WaitUntilEtcdsReady,
			Dependencies: flow.NewTaskIDs(deployEtcd),
		})
	)

	return g
}

// TaskGroupMigrateExtensionsBeforeKubeAPIServer is a flow.TaskID for a logical flow.TaskGroup.
const TaskGroupMigrateExtensionsBeforeKubeAPIServer flow.TaskID = "TaskGroupMigrateExtensionsBeforeKubeAPIServer"

// MigrateExtensionsBeforeKubeAPIServerTaskGroup migrates the source extensions needed before the kube-apiserver and
// persists the resulting shoot state so the destination can restore them.
func (b *Botanist) MigrateExtensionsBeforeKubeAPIServerTaskGroup() flow.TaskGroup {
	var (
		g = flow.NewTaskGroup(TaskGroupMigrateExtensionsBeforeKubeAPIServer)

		migrate = g.Add(flow.Task{
			Name: "Migrating extensions before kube-apiserver",
			Fn:   b.Shoot.Components.Extensions.Extension.MigrateBeforeKubeAPIServer,
		})
		waitMigrate = g.Add(flow.Task{
			Name:         "Waiting until extensions before kube-apiserver have been migrated",
			Fn:           b.Shoot.Components.Extensions.Extension.WaitMigrateBeforeKubeAPIServer,
			Dependencies: flow.NewTaskIDs(migrate),
		})
		_ = g.Add(flow.Task{
			Name:         "Persisting shoot state",
			Fn:           b.PersistShootState,
			Dependencies: flow.NewTaskIDs(waitMigrate),
		})
	)

	return g
}

// TaskGroupDestinationKubeAPIServerReady is a flow.TaskID for a logical flow.TaskGroup.
const TaskGroupDestinationKubeAPIServerReady flow.TaskID = "TaskGroupDestinationKubeAPIServerReady"

// DestinationKubeAPIServerReadyTaskGroup brings up the destination control plane and the temporary VPN. The phases run
// sequentially (each gated on all tasks of the previous one); the reused reconcile groups keep their internal parallelism.
func (b *Botanist) DestinationKubeAPIServerReadyTaskGroup() flow.TaskGroup {
	g := flow.NewTaskGroup(TaskGroupDestinationKubeAPIServerReady)

	// The istio ConfigMap gates the pod-kube-apiserver-load-balancing webhook; without it control plane pods resolve
	// api.<internalDomain> to the source apiserver and fail authentication (401).
	refreshShootState := g.Add(flow.Task{
		Name: "Refreshing shoot state",
		Fn:   b.RefreshShootStateForLiveMigration,
	})
	reconcileIstioConfigMap := g.Add(flow.Task{
		Name:         "Reconciling istio internal load balancing configmap",
		Fn:           b.ReconcileIstioInternalLoadBalancingConfigMap,
		Dependencies: flow.NewTaskIDs(refreshShootState),
	})

	reconcileExtensions := b.ReconcileExtensionsBeforeKubeAPIServerTaskGroup(false)
	g = g.AddAll(reconcileExtensions.WithTaskDependencies(reconcileIstioConfigMap)...)

	// The kube-apiserver Service is not part of ReconcileKubeAPIServerTaskGroup; its Wait resolves the Istio load
	// balancer address into b.APIServerAddress, which the live migration VPN DNS record relies on.
	deployService := g.Add(flow.Task{
		Name:         "Deploying kube-apiserver service",
		Fn:           b.Shoot.Components.ControlPlane.KubeAPIServerService.Deploy,
		Dependencies: flow.NewTaskIDs(reconcileExtensions),
	})
	waitService := g.Add(flow.Task{
		Name:         "Waiting until kube-apiserver service is ready",
		Fn:           b.Shoot.Components.ControlPlane.KubeAPIServerService.Wait,
		Dependencies: flow.NewTaskIDs(deployService),
	})

	reconcileKubeAPIServer := b.ReconcileKubeAPIServerTaskGroup(false, defaultTimeout)
	g = g.AddAll(reconcileKubeAPIServer.WithTaskDependencies(waitService)...)

	reconcileGardenerResourceManager := b.ReconcileGardenerResourceManagerTaskGroup(true, false)
	g = g.AddAll(reconcileGardenerResourceManager.WithTaskDependencies(reconcileKubeAPIServer)...)

	deployKubeControllerManager := g.Add(flow.Task{
		Name:         "Deploying kube-controller-manager",
		Fn:           b.DeployKubeControllerManager,
		Dependencies: flow.NewTaskIDs(reconcileGardenerResourceManager),
	})
	deployKubeScheduler := g.Add(flow.Task{
		Name:         "Deploying kube-scheduler",
		Fn:           b.Shoot.Components.ControlPlane.KubeScheduler.Deploy,
		SkipIf:       b.Shoot.IsWorkerless,
		Dependencies: flow.NewTaskIDs(reconcileGardenerResourceManager),
	})
	deployVerticalPodAutoscaler := g.Add(flow.Task{
		Name:         "Deploying vertical pod autoscaler",
		Fn:           b.DeployVerticalPodAutoscaler,
		SkipIf:       b.Shoot.IsWorkerless,
		Dependencies: flow.NewTaskIDs(reconcileGardenerResourceManager),
	})
	deployDependencyWatchdogAccess := g.Add(flow.Task{
		Name:         "Deploying dependency-watchdog access",
		Fn:           b.DeployDependencyWatchdogAccess,
		SkipIf:       b.Shoot.IsWorkerless,
		Dependencies: flow.NewTaskIDs(reconcileGardenerResourceManager),
	})
	controlPlaneDeployed := flow.NewTaskIDs(deployKubeControllerManager, deployKubeScheduler, deployVerticalPodAutoscaler, deployDependencyWatchdogAccess)

	// The temporary VPN lets admission webhooks reach the destination before the DNS cutover. The final wait checks the
	// temporary tunnel, not the permanent vpn-shoot (which would be a false positive while the temporary pod can route).
	deployVPNServer := g.Add(flow.Task{
		Name:         "Deploying destination VPN server",
		Fn:           b.DeployVPNServer,
		Dependencies: controlPlaneDeployed,
	})
	deployVPNDNSRecord := g.Add(flow.Task{
		Name:         "Deploying live migration VPN DNS record",
		Fn:           b.DeployLiveMigrationVPNDNSRecord,
		Dependencies: flow.NewTaskIDs(deployVPNServer),
	})
	deployTemporaryVPNShoot := g.Add(flow.Task{
		Name:         "Deploying temporary VPN shoot client",
		Fn:           b.DeployTemporaryVPNShoot,
		Dependencies: flow.NewTaskIDs(deployVPNDNSRecord),
	})
	// GardenerAccess deploys the "gardener-internal" kubeconfig secret (and the ManagedResource whose token GRM injects)
	// that InitializeDesiredShootClients reads to build the shoot client; without it the shoot client build fails with
	// "Secret gardener-internal not found".
	deployGardenerAccess := g.Add(flow.Task{
		Name:         "Deploying Gardener shoot access resources",
		Fn:           flow.TaskFn(b.Shoot.Components.GardenerAccess.Deploy).RetryUntilTimeout(defaultInterval, defaultTimeout),
		Dependencies: flow.NewTaskIDs(reconcileGardenerResourceManager),
	})
	// WaitUntilTemporaryTunnelConnectionExists lists pods through b.ShootClientSet, which is nil until the shoot client
	// is initialized against the freshly deployed destination kube-apiserver.
	initializeShootClients := g.Add(flow.Task{
		Name:         "Initializing connection to shoot",
		Fn:           flow.TaskFn(b.InitializeDesiredShootClients).RetryUntilTimeout(defaultInterval, 2*time.Minute),
		Dependencies: flow.NewTaskIDs(deployGardenerAccess),
	})
	g.Add(flow.Task{
		Name:         "Waiting until the temporary VPN tunnel connection to the destination is established",
		Fn:           b.WaitUntilTemporaryTunnelConnectionExists,
		Dependencies: flow.NewTaskIDs(initializeShootClients, deployTemporaryVPNShoot),
	})

	return g
}

// TaskGroupMigrateDNSRecords is a flow.TaskID for a logical flow.TaskGroup.
const TaskGroupMigrateDNSRecords flow.TaskID = "TaskGroupMigrateDNSRecords"

// MigrateDNSRecordsTaskGroup releases the source internal and external DNSRecords so the destination can take them over.
func (b *Botanist) MigrateDNSRecordsTaskGroup() flow.TaskGroup {
	var (
		g = flow.NewTaskGroup(TaskGroupMigrateDNSRecords)

		_ = g.Add(flow.Task{
			Name: "Migrating internal DNS record",
			Fn:   b.MigrateInternalDNSRecord,
		})
		_ = g.Add(flow.Task{
			Name: "Migrating external DNS record",
			Fn:   b.MigrateExternalDNSRecord,
		})
	)

	return g
}

// TaskGroupEtcdMigrationComplete is a flow.TaskID for a logical flow.TaskGroup.
const TaskGroupEtcdMigrationComplete flow.TaskID = "TaskGroupEtcdMigrationComplete"

// EtcdMigrationCompleteTaskGroup removes the source cluster's etcd members from the joined cluster, scaling etcd-main
// back to its final member count, and waits until the destination etcd is ready again.
func (b *Botanist) EtcdMigrationCompleteTaskGroup() flow.TaskGroup {
	var (
		g = flow.NewTaskGroup(TaskGroupEtcdMigrationComplete)

		removeSourceMembers = g.Add(flow.Task{
			Name: "Removing source etcd members from the joined cluster",
			Fn:   b.RemoveSourceEtcdMembers,
		})
		_ = g.Add(flow.Task{
			Name:         "Waiting until etcds are ready",
			Fn:           b.WaitUntilEtcdsReady,
			Dependencies: flow.NewTaskIDs(removeSourceMembers),
		})
	)

	return g
}

// TaskGroupSourceSeedCleanup is a flow.TaskID for a logical flow.TaskGroup.
const TaskGroupSourceSeedCleanup flow.TaskID = "TaskGroupSourceSeedCleanup"

// SourceSeedCleanupTaskGroup migrates and tears down the source-side shoot resources (extensions, infrastructure,
// control plane, managed resources, machines) and persists the migrated state for the destination to restore.
func (b *Botanist) SourceSeedCleanupTaskGroup() flow.TaskGroup {
	var (
		g = flow.NewTaskGroup(TaskGroupSourceSeedCleanup)

		migrateExtensions = g.Add(flow.Task{
			Name: "Migrating extension resources",
			Fn:   b.MigrateExtensionResourcesInParallel,
		})
		waitMigrateExtensions = g.Add(flow.Task{
			Name:         "Waiting until extension resources have been migrated",
			Fn:           b.WaitUntilExtensionResourcesMigrated,
			Dependencies: flow.NewTaskIDs(migrateExtensions),
		})
		migrateInfrastructure = g.Add(flow.Task{
			Name:         "Migrating shoot infrastructure",
			Fn:           b.Shoot.Components.Extensions.Infrastructure.Migrate,
			Dependencies: flow.NewTaskIDs(waitMigrateExtensions),
		})
		waitMigrateInfrastructure = g.Add(flow.Task{
			Name:         "Waiting until shoot infrastructure has been migrated",
			Fn:           b.Shoot.Components.Extensions.Infrastructure.WaitMigrate,
			Dependencies: flow.NewTaskIDs(migrateInfrastructure),
		})
		migrateControlPlane = g.Add(flow.Task{
			Name:         "Migrating shoot control plane",
			Fn:           b.Shoot.Components.Extensions.ControlPlane.Migrate,
			Dependencies: flow.NewTaskIDs(waitMigrateInfrastructure),
		})
		waitMigrateControlPlane = g.Add(flow.Task{
			Name:         "Waiting until shoot control plane has been migrated",
			Fn:           b.Shoot.Components.Extensions.ControlPlane.WaitMigrate,
			Dependencies: flow.NewTaskIDs(migrateControlPlane),
		})
		migrateExtensionsAfterKubeAPIServer = g.Add(flow.Task{
			Name:         "Migrating extensions after kube-apiserver",
			Fn:           b.Shoot.Components.Extensions.Extension.MigrateAfterKubeAPIServer,
			Dependencies: flow.NewTaskIDs(waitMigrateControlPlane),
		})
		waitMigrateExtensionsAfterKubeAPIServer = g.Add(flow.Task{
			Name:         "Waiting until extensions after kube-apiserver have been migrated",
			Fn:           b.Shoot.Components.Extensions.Extension.WaitMigrateAfterKubeAPIServer,
			Dependencies: flow.NewTaskIDs(migrateExtensionsAfterKubeAPIServer),
		})
		persistShootState = g.Add(flow.Task{
			Name:         "Persisting shoot state",
			Fn:           b.PersistShootState,
			Dependencies: flow.NewTaskIDs(waitMigrateExtensionsAfterKubeAPIServer),
		})
		keepManagedResources = g.Add(flow.Task{
			Name:         "Configuring managed resources to be kept in the shoot",
			Fn:           b.KeepObjectsForManagedResources,
			Dependencies: flow.NewTaskIDs(persistShootState),
		})
		deleteManagedResources = g.Add(flow.Task{
			Name:         "Deleting managed resources from the source namespace",
			Fn:           b.DeleteManagedResources,
			Dependencies: flow.NewTaskIDs(keepManagedResources),
		})
		waitManagedResourcesDeleted = g.Add(flow.Task{
			Name:         "Waiting until managed resources have been deleted",
			Fn:           b.WaitUntilManagedResourcesDeleted,
			Dependencies: flow.NewTaskIDs(deleteManagedResources),
		})
		// Hand the machines over to the destination: stop the source MCM and shallow-delete the machine CRs (finalizers
		// removed, VMs left running) so the destination's restored worker/MCM can adopt them.
		deleteMachineControllerManager = g.Add(flow.Task{
			Name:         "Deleting machine-controller-manager",
			Fn:           b.Shoot.Components.ControlPlane.MachineControllerManager.Destroy,
			Dependencies: flow.NewTaskIDs(waitManagedResourcesDeleted),
		})
		waitMachineControllerManagerDeleted = g.Add(flow.Task{
			Name:         "Waiting until machine-controller-manager has been deleted",
			Fn:           b.Shoot.Components.ControlPlane.MachineControllerManager.WaitCleanup,
			Dependencies: flow.NewTaskIDs(deleteMachineControllerManager),
		})
		shallowDeleteMachines = g.Add(flow.Task{
			Name:         "Shallow-deleting machine resources from the source namespace",
			Fn:           b.ShallowDeleteMachineResources,
			Dependencies: flow.NewTaskIDs(waitMachineControllerManagerDeleted),
		})
		waitMachinesDeleted = g.Add(flow.Task{
			Name: "Waiting until machine resources have been deleted",
			Fn: func(ctx context.Context) error {
				return gardenerutils.WaitUntilMachineResourcesDeleted(ctx, b.Logger, b.SeedClientSet.Client(), b.Shoot.ControlPlaneNamespace)
			},
			Dependencies: flow.NewTaskIDs(shallowDeleteMachines),
		})
		deleteExtensions = g.Add(flow.Task{
			Name:         "Deleting extension resources from the source namespace",
			Fn:           b.DestroyExtensionResourcesInParallel,
			Dependencies: flow.NewTaskIDs(waitMachinesDeleted),
		})
		waitExtensionsDeleted = g.Add(flow.Task{
			Name:         "Waiting until extension resources have been deleted",
			Fn:           b.WaitUntilExtensionResourcesDeleted,
			Dependencies: flow.NewTaskIDs(deleteExtensions),
		})
		deleteExtensionsBeforeKubeAPIServer = g.Add(flow.Task{
			Name:         "Deleting extensions before kube-apiserver",
			Fn:           b.Shoot.Components.Extensions.Extension.DestroyBeforeKubeAPIServer,
			Dependencies: flow.NewTaskIDs(waitExtensionsDeleted),
		})
		waitExtensionsBeforeKubeAPIServerDeleted = g.Add(flow.Task{
			Name:         "Waiting until extensions before kube-apiserver have been deleted",
			Fn:           b.Shoot.Components.Extensions.Extension.WaitCleanupBeforeKubeAPIServer,
			Dependencies: flow.NewTaskIDs(deleteExtensionsBeforeKubeAPIServer),
		})
		deleteControlPlane = g.Add(flow.Task{
			Name:         "Deleting shoot control plane",
			Fn:           b.Shoot.Components.Extensions.ControlPlane.Destroy,
			Dependencies: flow.NewTaskIDs(waitExtensionsBeforeKubeAPIServerDeleted),
		})
		waitControlPlaneDeleted = g.Add(flow.Task{
			Name:         "Waiting until shoot control plane has been deleted",
			Fn:           b.Shoot.Components.Extensions.ControlPlane.WaitCleanup,
			Dependencies: flow.NewTaskIDs(deleteControlPlane),
		})
		_ = g.Add(flow.Task{
			Name:         "Deleting vpn-seed-server from the source namespace",
			Fn:           b.DestroyVPNServer,
			Dependencies: flow.NewTaskIDs(waitControlPlaneDeleted),
		})
		// The source kube-apiserver is deliberately left running: the DNS cutover happens later, so tearing it down now
		// would break api.<internalDomain> until the destination record propagates. It is removed with the source namespace.
		deleteExtensionsAfterKubeAPIServer = g.Add(flow.Task{
			Name:         "Deleting extensions after kube-apiserver",
			Fn:           b.Shoot.Components.Extensions.Extension.DestroyAfterKubeAPIServer,
			Dependencies: flow.NewTaskIDs(waitControlPlaneDeleted),
		})
		waitExtensionsAfterKubeAPIServerDeleted = g.Add(flow.Task{
			Name:         "Waiting until extensions after kube-apiserver have been deleted",
			Fn:           b.Shoot.Components.Extensions.Extension.WaitCleanupAfterKubeAPIServer,
			Dependencies: flow.NewTaskIDs(deleteExtensionsAfterKubeAPIServer),
		})
		deleteInfrastructure = g.Add(flow.Task{
			Name:         "Deleting shoot infrastructure",
			Fn:           b.Shoot.Components.Extensions.Infrastructure.Destroy,
			Dependencies: flow.NewTaskIDs(waitExtensionsAfterKubeAPIServerDeleted),
		})
		waitInfrastructureDeleted = g.Add(flow.Task{
			Name:         "Waiting until shoot infrastructure has been deleted",
			Fn:           b.Shoot.Components.Extensions.Infrastructure.WaitCleanup,
			Dependencies: flow.NewTaskIDs(deleteInfrastructure),
		})
		_ = g.Add(flow.Task{
			Name:         "Deleting DNSRecords from the source namespace",
			Fn:           b.DestroyDNSRecords,
			Dependencies: flow.NewTaskIDs(waitInfrastructureDeleted),
		})
	)

	return g
}

// TaskGroupDestinationCompletionRestore is a flow.TaskID for a logical flow.TaskGroup.
const TaskGroupDestinationCompletionRestore flow.TaskID = "TaskGroupDestinationCompletionRestore"

// DestinationCompletionRestoreTaskGroup restores, on the destination seed, the resources the source migrated during
// SourceSeedCleanupTaskGroup and then cuts the VPN over from the temporary to the permanent tunnel.
func (b *Botanist) DestinationCompletionRestoreTaskGroup() flow.TaskGroup {
	var (
		g = flow.NewTaskGroup(TaskGroupDestinationCompletionRestore)

		refreshShootState = g.Add(flow.Task{
			Name: "Refreshing shoot state",
			Fn:   b.RefreshShootStateForLiveMigration,
		})
		// Deploy the DNSRecords first so api.<domain> resolves to the destination before the long tail of restores (and
		// before the permanent vpn-shoot, whose endpoint is api.<internalDomain>, is brought up).
		deployInternalDNSRecord = g.Add(flow.Task{
			Name:         "Deploying internal DNS record targeting the destination",
			Fn:           b.DeployOrDestroyInternalDNSRecord,
			Dependencies: flow.NewTaskIDs(refreshShootState),
		})
		deployExternalDNSRecord = g.Add(flow.Task{
			Name:         "Deploying external DNS record targeting the destination",
			Fn:           b.DeployOrDestroyExternalDNSRecord,
			Dependencies: flow.NewTaskIDs(deployInternalDNSRecord),
		})
		// Give upstream DNS caches time to pick up the destination targets before bringing up the permanent vpn-shoot
		// (whose endpoint resolves via api.<internalDomain>) and the other components that resolve these names.
		waitDNSCacheSync = g.Add(flow.Task{
			Name:         "Waiting for DNS caches to sync to the destination",
			Fn:           b.WaitForLiveMigrationDNSCacheSync,
			Dependencies: flow.NewTaskIDs(deployExternalDNSRecord),
		})
		// The destination never ran the regular reconcile, so deploy the cloud provider secret before the extensions
		// that build provider clients from it.
		deployCloudProviderSecret = g.Add(flow.Task{
			Name:         "Deploying cloud provider secret",
			Fn:           b.DeployCloudProviderSecret,
			Dependencies: flow.NewTaskIDs(waitDNSCacheSync),
		})
		deployReferencedResources = g.Add(flow.Task{
			Name:         "Deploying referenced resources",
			Fn:           b.DeployReferencedResources,
			Dependencies: flow.NewTaskIDs(deployCloudProviderSecret),
		})
		restoreInfrastructure = g.Add(flow.Task{
			Name:         "Restoring shoot infrastructure",
			Fn:           b.DeployInfrastructure,
			Dependencies: flow.NewTaskIDs(deployReferencedResources),
		})
		waitInfrastructure = g.Add(flow.Task{
			Name:         "Waiting until shoot infrastructure is restored",
			Fn:           b.WaitForInfrastructure,
			Dependencies: flow.NewTaskIDs(restoreInfrastructure),
		})
		restoreControlPlane = g.Add(flow.Task{
			Name:         "Restoring shoot control plane",
			Fn:           b.DeployControlPlane,
			Dependencies: flow.NewTaskIDs(waitInfrastructure),
		})
		waitControlPlane = g.Add(flow.Task{
			Name:         "Waiting until shoot control plane is restored",
			Fn:           b.Shoot.Components.Extensions.ControlPlane.Wait,
			Dependencies: flow.NewTaskIDs(restoreControlPlane),
		})
		restoreNetwork = g.Add(flow.Task{
			Name:         "Restoring network",
			Fn:           b.DeployNetwork,
			Dependencies: flow.NewTaskIDs(waitControlPlane),
		})
		waitNetwork = g.Add(flow.Task{
			Name:         "Waiting until network is restored",
			Fn:           b.Shoot.Components.Extensions.Network.Wait,
			Dependencies: flow.NewTaskIDs(restoreNetwork),
		})
		restoreOperatingSystemConfig = g.Add(flow.Task{
			Name:         "Restoring operating system config",
			Fn:           b.DeployOperatingSystemConfig,
			Dependencies: flow.NewTaskIDs(waitNetwork),
		})
		waitOperatingSystemConfig = g.Add(flow.Task{
			Name:         "Waiting until operating system config is restored",
			Fn:           b.Shoot.Components.Extensions.OperatingSystemConfig.Wait,
			Dependencies: flow.NewTaskIDs(restoreOperatingSystemConfig),
		})
		// machine-controller-manager must run before the worker is restored so it adopts the migrated MachineDeployments.
		deployMachineControllerManager = g.Add(flow.Task{
			Name:         "Deploying machine-controller-manager",
			Fn:           b.DeployMachineControllerManager,
			Dependencies: flow.NewTaskIDs(waitOperatingSystemConfig),
		})
		restoreWorker = g.Add(flow.Task{
			Name:         "Restoring worker",
			Fn:           b.DeployWorker,
			Dependencies: flow.NewTaskIDs(deployMachineControllerManager),
		})
		waitWorker = g.Add(flow.Task{
			Name:         "Waiting until worker is restored",
			Fn:           b.Shoot.Components.Extensions.Worker.Wait,
			Dependencies: flow.NewTaskIDs(restoreWorker),
		})
		restoreContainerRuntime = g.Add(flow.Task{
			Name:         "Restoring container runtime",
			Fn:           b.DeployContainerRuntime,
			Dependencies: flow.NewTaskIDs(waitWorker),
		})
		waitContainerRuntime = g.Add(flow.Task{
			Name:         "Waiting until container runtime is restored",
			Fn:           b.Shoot.Components.Extensions.ContainerRuntime.Wait,
			Dependencies: flow.NewTaskIDs(restoreContainerRuntime),
		})
		restoreExtensionsAfterKubeAPIServer = g.Add(flow.Task{
			Name:         "Restoring extensions after kube-apiserver",
			Fn:           b.DeployExtensionsAfterKubeAPIServer,
			Dependencies: flow.NewTaskIDs(waitContainerRuntime),
		})
		waitExtensionsAfterKubeAPIServer = g.Add(flow.Task{
			Name:         "Waiting until extensions after kube-apiserver are restored",
			Fn:           b.Shoot.Components.Extensions.Extension.WaitAfterKubeAPIServer,
			Dependencies: flow.NewTaskIDs(restoreExtensionsAfterKubeAPIServer),
		})
		// Deploy the permanent vpn-shoot and wait until it is healthy before tearing down the temporary VPN, so the
		// permanent tunnel to the destination is established first and connectivity is uninterrupted.
		deployVPNShoot = g.Add(flow.Task{
			Name:         "Deploying VPN shoot client to destination",
			Fn:           b.DeployVPNShoot,
			Dependencies: flow.NewTaskIDs(waitExtensionsAfterKubeAPIServer),
		})
		waitVPNShoot = g.Add(flow.Task{
			Name:         "Waiting until VPN shoot client to destination is healthy",
			Fn:           b.Shoot.Components.SystemComponents.VPNShoot.Wait,
			Dependencies: flow.NewTaskIDs(deployVPNShoot),
		})
		deployGardenerAccess = g.Add(flow.Task{
			Name:         "Deploying Gardener access resources",
			Fn:           b.Shoot.Components.GardenerAccess.Deploy,
			Dependencies: flow.NewTaskIDs(waitVPNShoot),
		})
		initializeShootClients = g.Add(flow.Task{
			Name:         "Initializing connection to shoot",
			Fn:           b.InitializeDesiredShootClients,
			Dependencies: flow.NewTaskIDs(deployGardenerAccess),
		})
		// Confirm the permanent tunnel actually carries traffic to the shoot BEFORE tearing down the
		// temporary VPN. Otherwise the temp path is removed while the permanent one may not yet be
		// established end-to-end (VPNShoot.Wait only checks pod/ManagedResource health, not tunnel
		// reachability), briefly black-holing apiserver->shoot traffic - webhooks, logs, exec.
		// ponytail: this port-forward probe may still traverse the temp tunnel if seed-side routing
		// prefers it, so it confirms shoot reachability rather than the permanent tunnel in isolation;
		// a permanent-tunnel-scoped probe would be the full guarantee.
		waitTunnelConnection = g.Add(flow.Task{
			Name:         "Waiting until the permanent VPN tunnel connection to the destination is established",
			Fn:           b.WaitUntilTunnelConnectionExists,
			Dependencies: flow.NewTaskIDs(initializeShootClients),
		})
		destroyTemporaryVPNShoot = g.Add(flow.Task{
			Name:         "Destroying temporary VPN shoot client",
			Fn:           b.DestroyTemporaryVPNShoot,
			Dependencies: flow.NewTaskIDs(waitTunnelConnection),
		})
		_ = g.Add(flow.Task{
			Name:         "Destroying live migration VPN DNS record",
			Fn:           b.DestroyLiveMigrationVPNDNSRecord,
			Dependencies: flow.NewTaskIDs(destroyTemporaryVPNShoot),
		})
	)

	return g
}

// TaskGroupDestinationCompletion is a flow.TaskID for a logical flow.TaskGroup.
const TaskGroupDestinationCompletion flow.TaskID = "TaskGroupDestinationCompletion"

// DestinationCompletionTaskGroup returns the group run by the MigrationCompleted step: the restore chain followed by
// the destination shoot-system layer (system components, resources, addons, observability), run sequentially. The
// live migration flow is self-sufficient, so these must be deployed here rather than by a subsequent reconcile.
func (b *Botanist) DestinationCompletionTaskGroup() flow.TaskGroup {
	kubeProxyEnabled := v1beta1helper.KubeProxyEnabled(b.Shoot.GetInfo().Spec.Kubernetes.KubeProxy)
	nginxDisabled := b.Shoot.IsWorkerless || !v1beta1helper.NginxIngressEnabled(b.Shoot.GetInfo().Spec.Addons)

	// EnsureShootClusterIdentity populates status.ClusterIdentity, read by the system-components group, so it runs first.
	prerequisites := flow.NewTaskGroup("destination-shoot-system-prerequisites")
	deployClusterAutoscaler := prerequisites.Add(flow.Task{
		Name:   "Deploying cluster-autoscaler",
		Fn:     b.DeployClusterAutoscaler,
		SkipIf: b.Shoot.IsWorkerless,
	})
	deployAPIServerProxy := prerequisites.Add(flow.Task{
		Name:         "Deploying apiserver-proxy",
		Fn:           b.DeployAPIServerProxy,
		SkipIf:       b.Shoot.IsWorkerless,
		Dependencies: flow.NewTaskIDs(deployClusterAutoscaler),
	})
	prerequisites.Add(flow.Task{
		Name:         "Ensuring shoot cluster identity",
		Fn:           b.EnsureShootClusterIdentity,
		Dependencies: flow.NewTaskIDs(deployAPIServerProxy),
	})

	nodeAgent := flow.NewTaskGroup("destination-shoot-system-node-agent")
	deployNodeAgent := nodeAgent.Add(flow.Task{
		Name: "Deploying gardener-node-agent's OperatingSystemConfig secrets and RBAC resources",
		Fn: func(ctx context.Context) error {
			return b.DeployManagedResourceForGardenerNodeAgent(ctx, false)
		},
		SkipIf: b.Shoot.IsWorkerless,
	})
	populateStaticManifests := nodeAgent.Add(flow.Task{
		Name:         "Populating static manifests from seed to shoot",
		Fn:           b.PopulateStaticManifestsFromSeedToShoot,
		Dependencies: flow.NewTaskIDs(deployNodeAgent),
	})
	nodeAgent.Add(flow.Task{
		Name:         "Ensuring advertised addresses for the shoot",
		Fn:           b.UpdateAdvertisedAddresses,
		Dependencies: flow.NewTaskIDs(populateStaticManifests),
	})

	observability := flow.NewTaskGroup("destination-shoot-system-observability")
	deployLogging := observability.Add(flow.Task{
		Name: "Deploying shoot logging stack in seed",
		Fn:   b.DeployLogging,
	})
	deployAlertManager := observability.Add(flow.Task{
		Name:         "Reconciling shoot Alertmanager",
		Fn:           b.DeployAlertManager,
		Dependencies: flow.NewTaskIDs(deployLogging),
	})
	waitAlertManager := observability.Add(flow.Task{
		Name:         "Waiting until shoot Alertmanager is reconciled",
		Fn:           b.WaitForAlertManager,
		Dependencies: flow.NewTaskIDs(deployAlertManager),
	})
	deployPrometheus := observability.Add(flow.Task{
		Name:         "Reconciling shoot Prometheus",
		Fn:           b.DeployPrometheus,
		Dependencies: flow.NewTaskIDs(waitAlertManager),
	})
	waitPrometheus := observability.Add(flow.Task{
		Name:         "Waiting until shoot Prometheus is reconciled",
		Fn:           b.WaitForPrometheus,
		Dependencies: flow.NewTaskIDs(deployPrometheus),
	})
	deployBlackboxExporter := observability.Add(flow.Task{
		Name:         "Deploying control plane blackbox-exporter",
		Fn:           b.ReconcileBlackboxExporterControlPlane,
		Dependencies: flow.NewTaskIDs(waitPrometheus),
	})
	deployKubeStateMetrics := observability.Add(flow.Task{
		Name:         "Reconciling kube-state-metrics for shoot in seed",
		Fn:           b.DeployKubeStateMetrics,
		SkipIf:       b.Shoot.IsWorkerless,
		Dependencies: flow.NewTaskIDs(deployBlackboxExporter),
	})
	deployPlutono := observability.Add(flow.Task{
		Name:         "Reconciling Plutono for shoot in seed",
		Fn:           b.DeployPlutono,
		Dependencies: flow.NewTaskIDs(deployKubeStateMetrics),
	})
	waitPlutono := observability.Add(flow.Task{
		Name:         "Waiting until Plutono for shoot in seed is reconciled",
		Fn:           b.WaitForPlutono,
		Dependencies: flow.NewTaskIDs(deployPlutono),
	})
	observability.Add(flow.Task{
		Name:         "Deploying istio-basic-auth-server",
		Fn:           b.Shoot.Components.ControlPlane.IstioBasicAuthServer.Deploy,
		Dependencies: flow.NewTaskIDs(waitPlutono),
	})

	nginxIngress := flow.NewTaskGroup("destination-shoot-system-nginx-ingress")
	waitNginx := nginxIngress.Add(flow.Task{
		Name:   "Waiting until nginx ingress LoadBalancer is ready",
		Fn:     b.WaitUntilNginxIngressServiceIsReady,
		SkipIf: nginxDisabled,
	})
	nginxIngress.Add(flow.Task{
		Name:         "Deploying nginx ingress DNS record",
		Fn:           b.DeployOrDestroyIngressDNSRecord,
		SkipIf:       nginxDisabled,
		Dependencies: flow.NewTaskIDs(waitNginx),
	})

	g := flow.NewTaskGroup(TaskGroupDestinationCompletion)

	restore := b.DestinationCompletionRestoreTaskGroup()
	g = g.AddAll(restore.Tasks()...)
	g = g.AddAll(prerequisites.WithTaskDependencies(restore)...)

	shootNamespaces := b.ReconcileShootNamespacesTaskGroup(false)
	g = g.AddAll(shootNamespaces.WithTaskDependencies(prerequisites)...)

	systemComponents := b.ReconcileSystemComponentsTaskGroup(kubeProxyEnabled, false)
	g = g.AddAll(systemComponents.WithTaskDependencies(shootNamespaces)...)

	systemResources := b.ReconcileSystemResourcesTaskGroup()
	g = g.AddAll(systemResources.WithTaskDependencies(systemComponents)...)

	g = g.AddAll(nodeAgent.WithTaskDependencies(systemResources)...)
	g = g.AddAll(observability.WithTaskDependencies(nodeAgent)...)
	g = g.AddAll(nginxIngress.WithTaskDependencies(observability)...)

	return g
}
