// Copyright 2020 SAP SE or an SAP affiliate company. All rights reserved. This file is licensed under the Apache Software License, v. 2 except as noted otherwise in the LICENSE file
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package shoot

import (
	"context"
	"time"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"sigs.k8s.io/controller-runtime/pkg/client"

	gardencorev1beta1 "github.com/gardener/gardener/pkg/apis/core/v1beta1"
	v1beta1constants "github.com/gardener/gardener/pkg/apis/core/v1beta1/constants"
	v1beta1helper "github.com/gardener/gardener/pkg/apis/core/v1beta1/helper"
	extensionsv1alpha1 "github.com/gardener/gardener/pkg/apis/extensions/v1alpha1"
	"github.com/gardener/gardener/pkg/operation"
	botanistpkg "github.com/gardener/gardener/pkg/operation/botanist"
	errorsutils "github.com/gardener/gardener/pkg/utils/errors"
	"github.com/gardener/gardener/pkg/utils/flow"
	kubernetesutils "github.com/gardener/gardener/pkg/utils/kubernetes"
	retryutils "github.com/gardener/gardener/pkg/utils/retry"
)

func (r *Reconciler) runMigrateShootFlow(ctx context.Context, o *operation.Operation) *v1beta1helper.WrappedLastErrors {
	var (
		botanist                      *botanistpkg.Botanist
		err                           error
		tasksWithErrors               []string
		controlPlaneRestorationNeeded bool
		infrastructure                *extensionsv1alpha1.Infrastructure
		kubeAPIServerDeploymentFound  = true
		etcdSnapshotRequired          bool
		workerless                    = o.Shoot.IsWorkerless
	)

	for _, lastError := range o.Shoot.GetInfo().Status.LastErrors {
		if lastError.TaskID != nil {
			tasksWithErrors = append(tasksWithErrors, *lastError.TaskID)
		}
	}

	errorContext := errorsutils.NewErrorContext("Shoot cluster preparation for migration", tasksWithErrors)

	err = errorsutils.HandleErrors(errorContext,
		func(errorID string) error {
			o.CleanShootTaskError(ctx, errorID)
			return nil
		},
		nil,
		errorsutils.ToExecute("Create botanist", func() error {
			return retryutils.UntilTimeout(ctx, 10*time.Second, 10*time.Minute, func(context.Context) (done bool, err error) {
				botanist, err = botanistpkg.New(ctx, o)
				if err != nil {
					return retryutils.MinorError(err)
				}
				return retryutils.Ok()
			})
		}),
		errorsutils.ToExecute("Retrieve kube-apiserver deployment in the shoot namespace in the seed cluster", func() error {
			deploymentKubeAPIServer := &appsv1.Deployment{}
			if err := botanist.SeedClientSet.APIReader().Get(ctx, kubernetesutils.Key(o.Shoot.SeedNamespace, v1beta1constants.DeploymentNameKubeAPIServer), deploymentKubeAPIServer); err != nil {
				if !apierrors.IsNotFound(err) {
					return err
				}
				kubeAPIServerDeploymentFound = false
			}
			if deploymentKubeAPIServer.DeletionTimestamp != nil {
				kubeAPIServerDeploymentFound = false
			}
			return nil
		}),
		errorsutils.ToExecute("Retrieve the Shoot namespace in the Seed cluster", func() error {
			return checkIfSeedNamespaceExists(ctx, o, botanist)
		}),
		errorsutils.ToExecute("Retrieve the BackupEntry in the garden cluster", func() error {
			backupEntry := &gardencorev1beta1.BackupEntry{}
			err := botanist.GardenClient.Get(ctx, client.ObjectKey{Name: botanist.Shoot.BackupEntryName, Namespace: o.Shoot.GetInfo().Namespace}, backupEntry)
			if err != nil {
				if !apierrors.IsNotFound(err) {
					return err
				}
				return nil
			}
			etcdSnapshotRequired = backupEntry.Spec.SeedName != nil && *backupEntry.Spec.SeedName == *botanist.Shoot.GetInfo().Status.SeedName && botanist.SeedNamespaceObject != nil
			return nil
		}),
		errorsutils.ToExecute("Retrieve the infrastructure resource", func() error {
			if workerless {
				return nil
			}
			obj, err := botanist.Shoot.Components.Extensions.Infrastructure.Get(ctx)
			if err != nil {
				if apierrors.IsNotFound(err) {
					return nil
				}
				return err
			}
			infrastructure = obj
			return nil
		}),
		errorsutils.ToExecute("Check whether control plane restoration is needed", func() error {
			controlPlaneRestorationNeeded, err = needsControlPlaneDeployment(ctx, o, kubeAPIServerDeploymentFound, infrastructure)
			return err
		}),
	)

	if err != nil {
		return v1beta1helper.NewWrappedLastErrors(v1beta1helper.FormatLastErrDescription(err), err)
	}

	var (
		nonTerminatingNamespace = botanist.SeedNamespaceObject != nil && botanist.SeedNamespaceObject.Status.Phase != corev1.NamespaceTerminating
		cleanupShootResources   = nonTerminatingNamespace && kubeAPIServerDeploymentFound
		wakeupRequired          = (o.Shoot.GetInfo().Status.IsHibernated || o.Shoot.HibernationEnabled) && cleanupShootResources
		defaultTimeout          = 10 * time.Minute
		defaultInterval         = 5 * time.Second

		g = flow.NewGraph("Shoot cluster preparation for migration")

		ensureShootStateExists = g.Add(flow.Task{
			Name: "Ensuring that ShootState exists",
			Fn:   flow.TaskFn(botanist.EnsureShootStateExists).RetryUntilTimeout(defaultInterval, defaultTimeout),
		})
		initializeSecretsManagement = g.Add(flow.Task{
			Name:         "Initializing secrets management",
			Fn:           flow.TaskFn(botanist.InitializeSecretsManagement).DoIf(nonTerminatingNamespace).RetryUntilTimeout(defaultInterval, defaultTimeout),
			Dependencies: flow.NewTaskIDs(ensureShootStateExists),
		})
		deployETCD = g.Add(flow.Task{
			Name:         "Deploying main and events etcd",
			Fn:           flow.TaskFn(botanist.DeployEtcd).RetryUntilTimeout(defaultInterval, defaultTimeout).DoIf(cleanupShootResources || etcdSnapshotRequired),
			Dependencies: flow.NewTaskIDs(initializeSecretsManagement),
		})
		scaleUpETCD = g.Add(flow.Task{
			Name:         "Scaling etcd up",
			Fn:           flow.TaskFn(botanist.ScaleUpETCD).RetryUntilTimeout(defaultInterval, defaultTimeout).DoIf(wakeupRequired),
			Dependencies: flow.NewTaskIDs(deployETCD),
		})
		waitUntilEtcdReady = g.Add(flow.Task{
			Name:         "Waiting until main and event etcd report readiness",
			Fn:           flow.TaskFn(botanist.WaitUntilEtcdsReady).DoIf(cleanupShootResources || etcdSnapshotRequired),
			Dependencies: flow.NewTaskIDs(deployETCD, scaleUpETCD),
		})
		// Restore the control plane in case it was already migrated to make sure all components that depend on the cloud provider secret are restarted
		// in case it has changed. Also, it's needed for other control plane components like the kube-apiserver or kube-
		// controller-manager to be updateable due to provider config injection.
		restoreControlPlane = g.Add(flow.Task{
			Name: "Restoring Shoot control plane",
			Fn: flow.TaskFn(func(ctx context.Context) error {
				if workerless {
					return nil
				}
				return botanist.RestoreControlPlane(ctx)
			}).DoIf(cleanupShootResources && controlPlaneRestorationNeeded),
			Dependencies: flow.NewTaskIDs(initializeSecretsManagement),
		})
		waitUntilControlPlaneReady = g.Add(flow.Task{
			Name: "Waiting until Shoot control plane has been restored",
			Fn: flow.TaskFn(func(ctx context.Context) error {
				if workerless {
					return nil
				}
				return botanist.Shoot.Components.Extensions.ControlPlane.Wait(ctx)
			}).DoIf(cleanupShootResources && controlPlaneRestorationNeeded),
			Dependencies: flow.NewTaskIDs(restoreControlPlane),
		})
		wakeUpKubeAPIServer = g.Add(flow.Task{
			Name:         "Scaling Kubernetes API Server up and waiting until ready",
			Fn:           flow.TaskFn(botanist.WakeUpKubeAPIServer).DoIf(wakeupRequired),
			Dependencies: flow.NewTaskIDs(deployETCD, scaleUpETCD, waitUntilControlPlaneReady),
		})
		// Deploy gardener-resource-manager to re-run the bootstrap logic if needed (e.g. when the token is expired because of hibernation).
		// This fixes https://github.com/gardener/gardener/issues/7606
		deployGardenerResourceManager = g.Add(flow.Task{
			Name:         "Deploying gardener-resource-manager",
			Fn:           flow.TaskFn(botanist.DeployGardenerResourceManager).DoIf(cleanupShootResources),
			Dependencies: flow.NewTaskIDs(wakeUpKubeAPIServer),
		})
		ensureResourceManagerScaledUp = g.Add(flow.Task{
			Name:         "Ensuring that the gardener-resource-manager is scaled to 1",
			Fn:           flow.TaskFn(botanist.ScaleGardenerResourceManagerToOne).DoIf(cleanupShootResources),
			Dependencies: flow.NewTaskIDs(deployGardenerResourceManager),
		})
		keepManagedResourcesObjectsInShoot = g.Add(flow.Task{
			Name:         "Configuring Managed Resources objects to be kept in the Shoot",
			Fn:           flow.TaskFn(botanist.KeepObjectsForManagedResources).DoIf(cleanupShootResources),
			Dependencies: flow.NewTaskIDs(ensureResourceManagerScaledUp),
		})
		deleteManagedResources = g.Add(flow.Task{
			Name:         "Deleting all Managed Resources from the Shoot's namespace",
			Fn:           flow.TaskFn(botanist.DeleteManagedResources),
			Dependencies: flow.NewTaskIDs(keepManagedResourcesObjectsInShoot, ensureResourceManagerScaledUp),
		})
		waitForManagedResourcesDeletion = g.Add(flow.Task{
			Name:         "Waiting until ManagedResources are deleted",
			Fn:           flow.TaskFn(botanist.WaitUntilManagedResourcesDeleted).Timeout(10 * time.Minute),
			Dependencies: flow.NewTaskIDs(deleteManagedResources),
		})
		migrateExtensionResources = g.Add(flow.Task{
			Name:         "Migrating extension resources",
			Fn:           botanist.MigrateExtensionResourcesInParallel,
			Dependencies: flow.NewTaskIDs(waitForManagedResourcesDeletion),
		})
		waitUntilExtensionResourcesMigrated = g.Add(flow.Task{
			Name:         "Waiting until extension resources have been migrated",
			Fn:           botanist.WaitUntilExtensionResourcesMigrated,
			Dependencies: flow.NewTaskIDs(migrateExtensionResources),
		})
		migrateExtensionsBeforeKubeAPIServer = g.Add(flow.Task{
			Name:         "Migrating extensions before kube-apiserver",
			Fn:           botanist.Shoot.Components.Extensions.Extension.MigrateBeforeKubeAPIServer,
			Dependencies: flow.NewTaskIDs(waitForManagedResourcesDeletion),
		})
		waitUntilExtensionsBeforeKubeAPIServerMigrated = g.Add(flow.Task{
			Name:         "Waiting until extensions that should be handled before kube-apiserver have been migrated",
			Fn:           botanist.Shoot.Components.Extensions.Extension.WaitMigrateBeforeKubeAPIServer,
			Dependencies: flow.NewTaskIDs(migrateExtensionsBeforeKubeAPIServer),
		})
		deleteExtensionResources = g.Add(flow.Task{
			Name:         "Deleting extension resources from the Shoot namespace",
			Fn:           botanist.DestroyExtensionResourcesInParallel,
			Dependencies: flow.NewTaskIDs(waitUntilExtensionResourcesMigrated),
		})
		waitUntilExtensionResourcesDeleted = g.Add(flow.Task{
			Name:         "Waiting until extension resources have been deleted",
			Fn:           botanist.WaitUntilExtensionResourcesDeleted,
			Dependencies: flow.NewTaskIDs(deleteExtensionResources),
		})
		deleteExtensionsBeforeKubeAPIServer = g.Add(flow.Task{
			Name:         "Deleting extensions before kube-apiserver",
			Fn:           botanist.Shoot.Components.Extensions.Extension.DestroyBeforeKubeAPIServer,
			Dependencies: flow.NewTaskIDs(waitUntilExtensionsBeforeKubeAPIServerMigrated),
		})
		waitUntilExtensionsBeforeKubeAPIServerDeleted = g.Add(flow.Task{
			Name:         "Waiting until extensions that should be handled before kube-apiserver have been deleted",
			Fn:           botanist.Shoot.Components.Extensions.Extension.WaitCleanupBeforeKubeAPIServer,
			Dependencies: flow.NewTaskIDs(deleteExtensionsBeforeKubeAPIServer),
		})
		deleteStaleExtensionResources = g.Add(flow.Task{
			Name:         "Deleting stale extensions",
			Fn:           flow.TaskFn(botanist.Shoot.Components.Extensions.Extension.DeleteStaleResources),
			Dependencies: flow.NewTaskIDs(waitUntilExtensionResourcesMigrated),
		})
		waitUntilStaleExtensionResourcesDeleted = g.Add(flow.Task{
			Name:         "Waiting until all stale extensions have been deleted",
			Fn:           botanist.Shoot.Components.Extensions.Extension.WaitCleanupStaleResources,
			Dependencies: flow.NewTaskIDs(deleteStaleExtensionResources),
		})
		migrateControlPlane = g.Add(flow.Task{
			Name: "Migrating shoot control plane",
			Fn: flow.TaskFn(func(ctx context.Context) error {
				if workerless {
					return nil
				}
				return botanist.Shoot.Components.Extensions.ControlPlane.Migrate(ctx)
			}),
			Dependencies: flow.NewTaskIDs(waitUntilExtensionResourcesDeleted, waitUntilExtensionsBeforeKubeAPIServerDeleted, waitUntilStaleExtensionResourcesDeleted),
		})
		deleteControlPlane = g.Add(flow.Task{
			Name: "Deleting shoot control plane",
			Fn: flow.TaskFn(func(ctx context.Context) error {
				if workerless {
					return nil
				}
				return botanist.Shoot.Components.Extensions.ControlPlane.Destroy(ctx)
			}).RetryUntilTimeout(defaultInterval, defaultTimeout),
			Dependencies: flow.NewTaskIDs(migrateControlPlane),
		})
		waitUntilControlPlaneDeleted = g.Add(flow.Task{
			Name: "Waiting until shoot control plane has been deleted",
			Fn: flow.TaskFn(func(ctx context.Context) error {
				if workerless {
					return nil
				}
				return botanist.Shoot.Components.Extensions.ControlPlane.WaitCleanup(ctx)
			}),
			Dependencies: flow.NewTaskIDs(deleteControlPlane),
		})
		waitUntilShootManagedResourcesDeleted = g.Add(flow.Task{
			Name:         "Waiting until shoot managed resources have been deleted",
			Fn:           flow.TaskFn(botanist.WaitUntilShootManagedResourcesDeleted).DoIf(cleanupShootResources).RetryUntilTimeout(defaultInterval, defaultTimeout),
			Dependencies: flow.NewTaskIDs(waitUntilControlPlaneDeleted),
		})
		deleteKubeAPIServer = g.Add(flow.Task{
			Name:         "Deleting kube-apiserver deployment",
			Fn:           flow.TaskFn(botanist.DeleteKubeAPIServer).RetryUntilTimeout(defaultInterval, defaultTimeout),
			Dependencies: flow.NewTaskIDs(waitForManagedResourcesDeletion, waitUntilEtcdReady, waitUntilControlPlaneDeleted, waitUntilShootManagedResourcesDeleted),
		})
		waitUntilKubeAPIServerDeleted = g.Add(flow.Task{
			Name:         "Waiting until kube-apiserver has been deleted",
			Fn:           botanist.Shoot.Components.ControlPlane.KubeAPIServer.WaitCleanup,
			Dependencies: flow.NewTaskIDs(deleteKubeAPIServer),
		})
		migrateExtensionsAfterKubeAPIServer = g.Add(flow.Task{
			Name:         "Migrating extensions after kube-apiserver",
			Fn:           botanist.Shoot.Components.Extensions.Extension.MigrateAfterKubeAPIServer,
			Dependencies: flow.NewTaskIDs(waitUntilKubeAPIServerDeleted),
		})
		waitUntilExtensionsAfterKubeAPIServerMigrated = g.Add(flow.Task{
			Name:         "Waiting until extensions that should be handled after kube-apiserver have been migrated",
			Fn:           botanist.Shoot.Components.Extensions.Extension.WaitMigrateAfterKubeAPIServer,
			Dependencies: flow.NewTaskIDs(migrateExtensionsAfterKubeAPIServer),
		})
		deleteExtensionsAfterKubeAPIServer = g.Add(flow.Task{
			Name:         "Deleting extensions after kube-apiserver",
			Fn:           flow.TaskFn(botanist.Shoot.Components.Extensions.Extension.DestroyAfterKubeAPIServer),
			Dependencies: flow.NewTaskIDs(waitUntilExtensionsAfterKubeAPIServerMigrated),
		})
		waitUntilExtensionsAfterKubeAPIServerDeleted = g.Add(flow.Task{
			Name:         "Waiting until extensions that should be handled after kube-apiserver have been deleted",
			Fn:           botanist.Shoot.Components.Extensions.Extension.WaitCleanupAfterKubeAPIServer,
			Dependencies: flow.NewTaskIDs(deleteExtensionsAfterKubeAPIServer),
		})
		// Add this step in interest of completeness. All extension deletions should have already been triggered by previous steps.
		waitUntilExtensionsDeleted = g.Add(flow.Task{
			Name:         "Waiting until all extensions have been deleted",
			Fn:           botanist.Shoot.Components.Extensions.Extension.WaitCleanup,
			Dependencies: flow.NewTaskIDs(waitUntilExtensionsAfterKubeAPIServerMigrated),
		})
		migrateInfrastructure = g.Add(flow.Task{
			Name: "Migrating shoot infrastructure",
			Fn: flow.TaskFn(func(ctx context.Context) error {
				if workerless {
					return nil
				}
				return botanist.Shoot.Components.Extensions.Infrastructure.Migrate(ctx)
			}),
			Dependencies: flow.NewTaskIDs(waitUntilKubeAPIServerDeleted),
		})
		waitUntilInfrastructureMigrated = g.Add(flow.Task{
			Name: "Waiting until shoot infrastructure has been migrated",
			Fn: flow.TaskFn(func(ctx context.Context) error {
				if workerless {
					return nil
				}
				return botanist.Shoot.Components.Extensions.Infrastructure.WaitMigrate(ctx)
			}),
			Dependencies: flow.NewTaskIDs(migrateInfrastructure),
		})
		deleteInfrastructure = g.Add(flow.Task{
			Name: "Deleting shoot infrastructure",
			Fn: flow.TaskFn(func(ctx context.Context) error {
				if workerless {
					return nil
				}
				return botanist.Shoot.Components.Extensions.Infrastructure.Destroy(ctx)
			}),
			Dependencies: flow.NewTaskIDs(waitUntilInfrastructureMigrated),
		})
		waitUntilInfrastructureDeleted = g.Add(flow.Task{
			Name: "Waiting until shoot infrastructure has been deleted",
			Fn: flow.TaskFn(func(ctx context.Context) error {
				if workerless {
					return nil
				}
				return botanist.Shoot.Components.Extensions.Infrastructure.WaitCleanup(ctx)
			}),
			Dependencies: flow.NewTaskIDs(deleteInfrastructure),
		})
		migrateIngressDNSRecord = g.Add(flow.Task{
			Name:         "Migrating nginx ingress DNS record",
			Fn:           botanist.MigrateIngressDNSRecord,
			Dependencies: flow.NewTaskIDs(waitUntilKubeAPIServerDeleted),
		})
		migrateExternalDNSRecord = g.Add(flow.Task{
			Name:         "Migrating external domain DNS record",
			Fn:           botanist.MigrateExternalDNSRecord,
			Dependencies: flow.NewTaskIDs(waitUntilKubeAPIServerDeleted),
		})
		migrateInternalDNSRecord = g.Add(flow.Task{
			Name:         "Migrating internal domain DNS record",
			Fn:           botanist.MigrateInternalDNSRecord,
			Dependencies: flow.NewTaskIDs(waitUntilKubeAPIServerDeleted),
		})
		migrateOrDestroyOwnerDNSRecord = g.Add(flow.Task{
			Name:         "Migrating owner domain DNS record",
			Fn:           flow.TaskFn(botanist.MigrateOrDestroyOwnerDNSResources).DoIf(nonTerminatingNamespace),
			Dependencies: flow.NewTaskIDs(waitUntilKubeAPIServerDeleted),
		})
		syncPoint = flow.NewTaskIDs(
			waitUntilExtensionsAfterKubeAPIServerDeleted,
			waitUntilExtensionsDeleted,
			waitUntilInfrastructureDeleted,
		)
		destroyDNSRecords = g.Add(flow.Task{
			Name:         "Deleting DNSRecords from the Shoot namespace",
			Fn:           flow.TaskFn(botanist.DestroyDNSRecords).DoIf(nonTerminatingNamespace),
			Dependencies: flow.NewTaskIDs(syncPoint, migrateIngressDNSRecord, migrateExternalDNSRecord, migrateInternalDNSRecord, migrateOrDestroyOwnerDNSRecord),
		})
		createETCDSnapshot = g.Add(flow.Task{
			Name:         "Creating ETCD Snapshot",
			Fn:           flow.TaskFn(botanist.SnapshotEtcd).DoIf(etcdSnapshotRequired),
			Dependencies: flow.NewTaskIDs(syncPoint, waitUntilKubeAPIServerDeleted),
		})
		migrateBackupEntryInGarden = g.Add(flow.Task{
			Name:         "Migrating BackupEntry to new seed",
			Fn:           botanist.Shoot.Components.BackupEntry.Migrate,
			Dependencies: flow.NewTaskIDs(syncPoint, createETCDSnapshot),
		})
		waitUntilBackupEntryInGardenMigrated = g.Add(flow.Task{
			Name:         "Waiting for BackupEntry to be migrated to new seed",
			Fn:           botanist.Shoot.Components.BackupEntry.WaitMigrate,
			Dependencies: flow.NewTaskIDs(migrateBackupEntryInGarden),
		})
		destroyEtcd = g.Add(flow.Task{
			Name:         "Destroying main and events etcd",
			Fn:           flow.TaskFn(botanist.DestroyEtcd).RetryUntilTimeout(defaultInterval, defaultTimeout),
			Dependencies: flow.NewTaskIDs(syncPoint, createETCDSnapshot, waitUntilBackupEntryInGardenMigrated),
		})
		waitUntilEtcdDeleted = g.Add(flow.Task{
			Name:         "Waiting until main and event etcd have been destroyed",
			Fn:           flow.TaskFn(botanist.WaitUntilEtcdsDeleted).RetryUntilTimeout(defaultInterval, defaultTimeout),
			Dependencies: flow.NewTaskIDs(destroyEtcd),
		})
		deleteNamespace = g.Add(flow.Task{
			Name:         "Deleting shoot namespace in Seed",
			Fn:           flow.TaskFn(botanist.DeleteSeedNamespace).RetryUntilTimeout(defaultInterval, defaultTimeout),
			Dependencies: flow.NewTaskIDs(syncPoint, waitUntilBackupEntryInGardenMigrated, deleteExtensionResources, destroyDNSRecords, waitForManagedResourcesDeletion, waitUntilEtcdDeleted),
		})
		_ = g.Add(flow.Task{
			Name:         "Waiting until shoot namespace in Seed has been deleted",
			Fn:           botanist.WaitUntilSeedNamespaceDeleted,
			Dependencies: flow.NewTaskIDs(deleteNamespace),
		})

		f = g.Compile()
	)

	if err := f.Run(ctx, flow.Opts{
		Log:              o.Logger,
		ProgressReporter: r.newProgressReporter(o.ReportShootProgress),
		ErrorContext:     errorContext,
		ErrorCleaner:     o.CleanShootTaskError,
	}); err != nil {
		return v1beta1helper.NewWrappedLastErrors(v1beta1helper.FormatLastErrDescription(err), flow.Errors(err))
	}

	o.Logger.Info("Successfully prepared Shoot cluster for restoration")
	return nil
}
