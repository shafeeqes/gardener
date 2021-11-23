// Copyright (c) 2018 SAP SE or an SAP affiliate company. All rights reserved. This file is licensed under the Apache Software License, v. 2 except as noted otherwise in the LICENSE file
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
	"fmt"
	"time"

	gardencorev1beta1 "github.com/gardener/gardener/pkg/apis/core/v1beta1"
	v1beta1constants "github.com/gardener/gardener/pkg/apis/core/v1beta1/constants"
	gardencorev1beta1helper "github.com/gardener/gardener/pkg/apis/core/v1beta1/helper"
	"github.com/gardener/gardener/pkg/client/kubernetes/clientmap/keys"
	"github.com/gardener/gardener/pkg/controllerutils"
	"github.com/gardener/gardener/pkg/operation"
	botanistpkg "github.com/gardener/gardener/pkg/operation/botanist"
	"github.com/gardener/gardener/pkg/operation/botanist/component"
	"github.com/gardener/gardener/pkg/utils/errors"
	"github.com/gardener/gardener/pkg/utils/flow"
	kutil "github.com/gardener/gardener/pkg/utils/kubernetes"
	retryutils "github.com/gardener/gardener/pkg/utils/retry"
)

// runReconcileShootFlow reconciles the Shoot cluster's state.
// It receives an Operation object <o> which stores the Shoot object.
func (r *shootReconciler) runReconcileShootFlow(ctx context.Context, o *operation.Operation) *gardencorev1beta1helper.WrappedLastErrors {
	// We create the botanists (which will do the actual work).
	var (
		botanist                *botanistpkg.Botanist
		tasksWithErrors         []string
		isCopyOfBackupsRequired bool
		err                     error
	)

	for _, lastError := range o.Shoot.GetInfo().Status.LastErrors {
		if lastError.TaskID != nil {
			tasksWithErrors = append(tasksWithErrors, *lastError.TaskID)
		}
	}

	errorContext := errors.NewErrorContext("Shoot cluster reconciliation", tasksWithErrors)

	err = errors.HandleErrors(errorContext,
		func(errorID string) error {
			o.CleanShootTaskError(ctx, errorID)
			return nil
		},
		nil,
		errors.ToExecute("Create botanist", func() error {
			return retryutils.UntilTimeout(ctx, 10*time.Second, 10*time.Minute, func(context.Context) (done bool, err error) {
				botanist, err = botanistpkg.New(ctx, o)
				if err != nil {
					return retryutils.MinorError(err)
				}
				return retryutils.Ok()
			})
		}),
		errors.ToExecute("Check required extensions", func() error {
			return botanist.WaitUntilRequiredExtensionsReady(ctx)
		}),
		errors.ToExecute("Check if copy of backups is required", func() error {
			isCopyOfBackupsRequired, err = botanist.IsCopyOfBackupsRequired(ctx)
			return err
		}),
	)

	if err != nil {
		return gardencorev1beta1helper.NewWrappedLastErrors(gardencorev1beta1helper.FormatLastErrDescription(err), err)
	}

	var (
		defaultTimeout                 = 30 * time.Second
		defaultInterval                = 5 * time.Second
		dnsEnabled                     = !o.Shoot.DisableDNS
		allowBackup                    = o.Seed.GetInfo().Spec.Backup != nil
		staticNodesCIDR                = o.Shoot.GetInfo().Spec.Networking.Nodes != nil
		useSNI                         = botanist.APIServerSNIEnabled()
		generation                     = o.Shoot.GetInfo().Generation
		sniPhase                       = botanist.Shoot.Components.ControlPlane.KubeAPIServerSNIPhase
		requestControlPlanePodsRestart = controllerutils.HasTask(o.Shoot.GetInfo().Annotations, v1beta1constants.ShootTaskRestartControlPlanePods)

		g                      = flow.NewGraph("Shoot cluster reconciliation")
		ensureShootStateExists = g.Add(flow.Task{
			Name: "Ensuring that ShootState exists",
			Fn:   flow.TaskFn(botanist.EnsureShootStateExists).RetryUntilTimeout(defaultInterval, defaultTimeout),
		})
		deployNamespace = g.Add(flow.Task{
			Name: "Deploying Shoot namespace in Seed",
			Fn:   flow.TaskFn(botanist.DeploySeedNamespace).RetryUntilTimeout(defaultInterval, defaultTimeout),
		})
		ensureShootClusterIdentity = g.Add(flow.Task{
			Name:         "Ensuring Shoot cluster identity",
			Fn:           flow.TaskFn(botanist.EnsureShootClusterIdentity).RetryUntilTimeout(defaultInterval, defaultTimeout),
			Dependencies: flow.NewTaskIDs(deployNamespace),
		})
		deployCloudProviderSecret = g.Add(flow.Task{
			Name:         "Deploying cloud provider account secret",
			Fn:           flow.TaskFn(botanist.DeployCloudProviderSecret).RetryUntilTimeout(defaultInterval, defaultTimeout),
			Dependencies: flow.NewTaskIDs(deployNamespace),
		})
		deployKubeAPIServerService = g.Add(flow.Task{
			Name: "Deploying Kubernetes API server service in the Seed cluster",
			Fn: flow.TaskFn(func(ctx context.Context) error {
				return botanist.DeployKubeAPIService(ctx, sniPhase)
			}).
				RetryUntilTimeout(defaultInterval, defaultTimeout).
				SkipIf(o.Shoot.HibernationEnabled && !useSNI),
			Dependencies: flow.NewTaskIDs(deployNamespace, ensureShootClusterIdentity),
		})
		_ = g.Add(flow.Task{
			Name:         "Deploying Kubernetes API server service SNI settings in the Seed cluster",
			Fn:           flow.TaskFn(botanist.DeployKubeAPIServerSNI).RetryUntilTimeout(defaultInterval, defaultTimeout),
			Dependencies: flow.NewTaskIDs(deployKubeAPIServerService),
		})
		waitUntilKubeAPIServerServiceIsReady = g.Add(flow.Task{
			Name:         "Waiting until Kubernetes API LoadBalancer in the Seed cluster has reported readiness",
			Fn:           flow.TaskFn(botanist.Shoot.Components.ControlPlane.KubeAPIServerService.Wait).SkipIf(o.Shoot.HibernationEnabled && !useSNI),
			Dependencies: flow.NewTaskIDs(deployKubeAPIServerService),
		})
		_ = g.Add(flow.Task{
			Name:         "Ensuring advertised addresses for the Shoot",
			Fn:           botanist.UpdateAdvertisedAddresses,
			Dependencies: flow.NewTaskIDs(waitUntilKubeAPIServerServiceIsReady),
		})
		generateSecrets = g.Add(flow.Task{
			Name: "Generating secrets and saving them into ShootState",
			Fn:   botanist.GenerateAndSaveSecrets,
			Dependencies: func() flow.TaskIDs {
				taskIDs := flow.NewTaskIDs(deployNamespace, ensureShootStateExists)
				if !dnsEnabled && !o.Shoot.HibernationEnabled {
					taskIDs.Insert(waitUntilKubeAPIServerServiceIsReady)
				}
				return taskIDs
			}(),
		})
		deploySecrets = g.Add(flow.Task{
			Name:         "Deploying Shoot certificates / keys",
			Fn:           botanist.DeploySecrets,
			Dependencies: flow.NewTaskIDs(deployNamespace, generateSecrets, ensureShootStateExists),
		})
		deploySeedLogging = g.Add(flow.Task{
			Name:         "Deploying shoot logging stack in Seed",
			Fn:           flow.TaskFn(botanist.DeploySeedLogging).RetryUntilTimeout(defaultInterval, defaultTimeout),
			Dependencies: flow.NewTaskIDs(deployNamespace, deploySecrets),
		})
		deployReferencedResources = g.Add(flow.Task{
			Name:         "Deploying referenced resources",
			Fn:           flow.TaskFn(botanist.DeployReferencedResources).RetryUntilTimeout(defaultInterval, defaultTimeout),
			Dependencies: flow.NewTaskIDs(deployNamespace),
		})
		deployOwnerDomainDNSRecord = g.Add(flow.Task{
			Name:         "Deploying owner domain DNS record",
			Fn:           botanist.DeployOwnerDNSResources,
			Dependencies: flow.NewTaskIDs(ensureShootStateExists, deployReferencedResources),
		})
		deployInternalDomainDNSRecord = g.Add(flow.Task{
			Name:         "Deploying internal domain DNS record",
			Fn:           flow.TaskFn(botanist.DeployInternalDNSResources).DoIf(!o.Shoot.HibernationEnabled),
			Dependencies: flow.NewTaskIDs(deployReferencedResources, waitUntilKubeAPIServerServiceIsReady, deployOwnerDomainDNSRecord),
		})
		deployExternalDomainDNSRecord = g.Add(flow.Task{
			Name:         "Deploying external domain DNS record",
			Fn:           flow.TaskFn(botanist.DeployExternalDNSResources).DoIf(!o.Shoot.HibernationEnabled),
			Dependencies: flow.NewTaskIDs(deployReferencedResources, waitUntilKubeAPIServerServiceIsReady, deployOwnerDomainDNSRecord),
		})
		deployInfrastructure = g.Add(flow.Task{
			Name:         "Deploying Shoot infrastructure",
			Fn:           flow.TaskFn(botanist.DeployInfrastructure).RetryUntilTimeout(defaultInterval, defaultTimeout),
			Dependencies: flow.NewTaskIDs(deploySecrets, deployCloudProviderSecret, deployReferencedResources, deployOwnerDomainDNSRecord),
		})
		waitUntilInfrastructureReady = g.Add(flow.Task{
			Name: "Waiting until shoot infrastructure has been reconciled",
			Fn: func(ctx context.Context) error {
				if err := botanist.WaitForInfrastructure(ctx); err != nil {
					return err
				}
				return removeTaskAnnotation(ctx, o, generation, v1beta1constants.ShootTaskDeployInfrastructure)
			},
			Dependencies: flow.NewTaskIDs(deployInfrastructure),
		})
		_ = g.Add(flow.Task{
			Name:         "Reconciling network policies",
			Fn:           flow.TaskFn(botanist.Shoot.Components.NetworkPolicies.Deploy).RetryUntilTimeout(defaultInterval, defaultTimeout),
			Dependencies: flow.NewTaskIDs(deployNamespace),
		})
		// If the nodes CIDR is not static then it might be assigned only after the Infrastructure reconciliation. Hence,
		// we might need to reconcile the network policies again after this step (because it might be only known afterwards).
		_ = g.Add(flow.Task{
			Name: "Reconciling network policies now that infrastructure is ready",
			Fn: flow.TaskFn(func(ctx context.Context) error {
				if botanist.Shoot.GetInfo().Spec.Networking.Nodes != nil {
					o.Shoot.Components.NetworkPolicies, err = botanist.DefaultNetworkPolicies(sniPhase)
					if err != nil {
						return err
					}
					return botanist.Shoot.Components.NetworkPolicies.Deploy(ctx)
				}
				return nil
			}).RetryUntilTimeout(defaultInterval, defaultTimeout).DoIf(!staticNodesCIDR),
			Dependencies: flow.NewTaskIDs(waitUntilInfrastructureReady),
		})
		deploySourceBackupEntry = g.Add(flow.Task{
			Name:         "Deploying source backup entry",
			Fn:           flow.TaskFn(botanist.DeploySourceBackupEntry).DoIf(isCopyOfBackupsRequired),
			Dependencies: flow.NewTaskIDs(deployOwnerDomainDNSRecord),
		})
		waitUntilSourceBackupEntryInGardenReconciled = g.Add(flow.Task{
			Name:         "Waiting until the source backup entry has been reconciled",
			Fn:           flow.TaskFn(botanist.Shoot.Components.SourceBackupEntry.Wait).DoIf(isCopyOfBackupsRequired),
			Dependencies: flow.NewTaskIDs(deploySourceBackupEntry),
		})
		deployBackupEntryInGarden = g.Add(flow.Task{
			Name:         "Deploying backup entry",
			Fn:           flow.TaskFn(botanist.DeployBackupEntry).DoIf(allowBackup),
			Dependencies: flow.NewTaskIDs(ensureShootStateExists, deployOwnerDomainDNSRecord, waitUntilSourceBackupEntryInGardenReconciled),
		})
		waitUntilBackupEntryInGardenReconciled = g.Add(flow.Task{
			Name:         "Waiting until the backup entry has been reconciled",
			Fn:           flow.TaskFn(botanist.Shoot.Components.BackupEntry.Wait).DoIf(allowBackup),
			Dependencies: flow.NewTaskIDs(deployBackupEntryInGarden),
		})
		copyEtcdBackups = g.Add(flow.Task{
			Name:         "Copying etcd backups to new seed's backup bucket",
			Fn:           flow.TaskFn(botanist.DeployEtcdCopyBackupsTask).DoIf(isCopyOfBackupsRequired),
			Dependencies: flow.NewTaskIDs(deploySecrets, deployCloudProviderSecret, waitUntilBackupEntryInGardenReconciled, waitUntilSourceBackupEntryInGardenReconciled),
		})
		waitUntilEtcdBackupsCopied = g.Add(flow.Task{
			Name:         "Waiting until etcd backups are copied",
			Fn:           flow.TaskFn(botanist.Shoot.Components.ControlPlane.EtcdCopyBackupsTask.Wait).DoIf(isCopyOfBackupsRequired),
			Dependencies: flow.NewTaskIDs(copyEtcdBackups),
		})
		_ = g.Add(flow.Task{
			Name:         "Destroying copy etcd backups task resource",
			Fn:           flow.TaskFn(botanist.Shoot.Components.ControlPlane.EtcdCopyBackupsTask.Destroy).DoIf(isCopyOfBackupsRequired),
			Dependencies: flow.NewTaskIDs(waitUntilEtcdBackupsCopied),
		})
		deployETCD = g.Add(flow.Task{
			Name:         "Deploying main and events etcd",
			Fn:           flow.TaskFn(botanist.DeployEtcd).RetryUntilTimeout(defaultInterval, defaultTimeout),
			Dependencies: flow.NewTaskIDs(deploySecrets, deployCloudProviderSecret, waitUntilBackupEntryInGardenReconciled, waitUntilEtcdBackupsCopied),
		})
		_ = g.Add(flow.Task{
			Name:         "Destroying source backup entry",
			Fn:           flow.TaskFn(botanist.Shoot.Components.SourceBackupEntry.Destroy).DoIf(allowBackup),
			Dependencies: flow.NewTaskIDs(deployETCD),
		})
		waitUntilEtcdReady = g.Add(flow.Task{
			Name:         "Waiting until main and event etcd report readiness",
			Fn:           flow.TaskFn(botanist.WaitUntilEtcdsReady).SkipIf(o.Shoot.HibernationEnabled),
			Dependencies: flow.NewTaskIDs(deployETCD),
		})
		deployControlPlane = g.Add(flow.Task{
			Name:         "Deploying shoot control plane components",
			Fn:           flow.TaskFn(botanist.DeployControlPlane).RetryUntilTimeout(defaultInterval, defaultTimeout),
			Dependencies: flow.NewTaskIDs(deploySecrets, deployCloudProviderSecret, deployReferencedResources, waitUntilInfrastructureReady),
		})
		waitUntilControlPlaneReady = g.Add(flow.Task{
			Name:         "Waiting until shoot control plane has been reconciled",
			Fn:           botanist.Shoot.Components.Extensions.ControlPlane.Wait,
			Dependencies: flow.NewTaskIDs(deployControlPlane),
		})
		generateEncryptionConfigurationMetaData = g.Add(flow.Task{
			Name:         "Generating etcd encryption configuration",
			Fn:           botanist.GenerateEncryptionConfiguration,
			Dependencies: flow.NewTaskIDs(deployNamespace, ensureShootStateExists),
		})
		persistETCDEncryptionConfiguration = g.Add(flow.Task{
			Name:         "Persisting etcd encryption configuration in ShootState",
			Fn:           botanist.PersistEncryptionConfiguration,
			Dependencies: flow.NewTaskIDs(deployNamespace, ensureShootStateExists, generateEncryptionConfigurationMetaData),
		})
		createOrUpdateETCDEncryptionConfiguration = g.Add(flow.Task{
			Name:         "Applying etcd encryption configuration",
			Fn:           botanist.ApplyEncryptionConfiguration,
			Dependencies: flow.NewTaskIDs(deployNamespace, ensureShootStateExists, generateEncryptionConfigurationMetaData, persistETCDEncryptionConfiguration),
		})
		deployKubeAPIServer = g.Add(flow.Task{
			Name: "Deploying Kubernetes API server",
			Fn:   flow.TaskFn(botanist.DeployKubeAPIServer).RetryUntilTimeout(defaultInterval, defaultTimeout),
			Dependencies: flow.NewTaskIDs(
				deploySecrets,
				deployETCD,
				waitUntilEtcdReady,
				waitUntilKubeAPIServerServiceIsReady,
				waitUntilControlPlaneReady,
				createOrUpdateETCDEncryptionConfiguration,
			).InsertIf(!staticNodesCIDR, waitUntilInfrastructureReady),
		})
		waitUntilKubeAPIServerIsReady = g.Add(flow.Task{
			Name:         "Waiting until Kubernetes API server reports readiness",
			Fn:           flow.TaskFn(botanist.Shoot.Components.ControlPlane.KubeAPIServer.Wait).SkipIf(o.Shoot.HibernationEnabled),
			Dependencies: flow.NewTaskIDs(deployKubeAPIServer),
		})
		deployGardenerResourceManager = g.Add(flow.Task{
			Name:         "Deploying gardener-resource-manager",
			Fn:           flow.TaskFn(botanist.DeployGardenerResourceManager).RetryUntilTimeout(defaultInterval, defaultTimeout),
			Dependencies: flow.NewTaskIDs(waitUntilKubeAPIServerIsReady),
		})
		waitUntilGardenerResourceManagerReady = g.Add(flow.Task{
			Name:         "Waiting until gardener-resource-manager reports readiness",
			Fn:           flow.TaskFn(botanist.Shoot.Components.ControlPlane.ResourceManager.Wait).SkipIf(o.Shoot.HibernationEnabled),
			Dependencies: flow.NewTaskIDs(deployGardenerResourceManager),
		})
		_ = g.Add(flow.Task{
			Name:         "Deploying vpn-seed-server",
			Fn:           flow.TaskFn(botanist.DeployVPNServer).RetryUntilTimeout(defaultInterval, defaultTimeout),
			Dependencies: flow.NewTaskIDs(deploySecrets, deployNamespace),
		})
		deployControlPlaneExposure = g.Add(flow.Task{
			Name:         "Deploying shoot control plane exposure components",
			Fn:           flow.TaskFn(botanist.DeployControlPlaneExposure).RetryUntilTimeout(defaultInterval, defaultTimeout).SkipIf(useSNI),
			Dependencies: flow.NewTaskIDs(deployReferencedResources, waitUntilKubeAPIServerIsReady),
		})
		waitUntilControlPlaneExposureReady = g.Add(flow.Task{
			Name:         "Waiting until Shoot control plane exposure has been reconciled",
			Fn:           flow.TaskFn(botanist.Shoot.Components.Extensions.ControlPlaneExposure.Wait).SkipIf(useSNI),
			Dependencies: flow.NewTaskIDs(deployControlPlaneExposure),
		})
		destroyControlPlaneExposure = g.Add(flow.Task{
			Name:         "Destroying shoot control plane exposure",
			Fn:           flow.TaskFn(botanist.Shoot.Components.Extensions.ControlPlaneExposure.Destroy).DoIf(useSNI),
			Dependencies: flow.NewTaskIDs(waitUntilKubeAPIServerIsReady),
		})
		waitUntilControlPlaneExposureDeleted = g.Add(flow.Task{
			Name:         "Waiting until shoot control plane exposure has been destroyed",
			Fn:           flow.TaskFn(botanist.Shoot.Components.Extensions.ControlPlaneExposure.WaitCleanup).DoIf(useSNI),
			Dependencies: flow.NewTaskIDs(destroyControlPlaneExposure),
		})
		initializeShootClients = g.Add(flow.Task{
			Name:         "Initializing connection to Shoot",
			Fn:           flow.TaskFn(botanist.InitializeDesiredShootClients).RetryUntilTimeout(defaultInterval, 2*time.Minute),
			Dependencies: flow.NewTaskIDs(waitUntilKubeAPIServerIsReady, waitUntilControlPlaneExposureReady, waitUntilControlPlaneExposureDeleted, deployInternalDomainDNSRecord),
		})
		_ = g.Add(flow.Task{
			Name:         "Rewriting Shoot secrets if EncryptionConfiguration has changed",
			Fn:           flow.TaskFn(botanist.RewriteShootSecretsIfEncryptionConfigurationChanged).DoIf(!o.Shoot.HibernationEnabled).RetryUntilTimeout(defaultInterval, 15*time.Minute),
			Dependencies: flow.NewTaskIDs(initializeShootClients, ensureShootStateExists, createOrUpdateETCDEncryptionConfiguration),
		})
		deployKubeScheduler = g.Add(flow.Task{
			Name:         "Deploying Kubernetes scheduler",
			Fn:           flow.TaskFn(botanist.DeployKubeScheduler).RetryUntilTimeout(defaultInterval, defaultTimeout),
			Dependencies: flow.NewTaskIDs(deploySecrets, waitUntilGardenerResourceManagerReady),
		})
		deployKubeControllerManager = g.Add(flow.Task{
			Name:         "Deploying Kubernetes controller manager",
			Fn:           flow.TaskFn(botanist.DeployKubeControllerManager).RetryUntilTimeout(defaultInterval, defaultTimeout),
			Dependencies: flow.NewTaskIDs(deploySecrets, deployCloudProviderSecret, waitUntilKubeAPIServerIsReady),
		})
		_ = g.Add(flow.Task{
			Name:         "Syncing shoot access credentials to project namespace in Garden",
			Fn:           flow.TaskFn(botanist.SyncShootCredentialsToGarden).RetryUntilTimeout(defaultInterval, defaultTimeout),
			Dependencies: flow.NewTaskIDs(deploySecrets, initializeShootClients, deployKubeControllerManager),
		})
		deployOperatingSystemConfig = g.Add(flow.Task{
			Name:         "Deploying operating system specific configuration for shoot workers",
			Fn:           flow.TaskFn(botanist.DeployOperatingSystemConfig).RetryUntilTimeout(defaultInterval, defaultTimeout),
			Dependencies: flow.NewTaskIDs(deployReferencedResources, waitUntilInfrastructureReady, waitUntilControlPlaneReady),
		})
		waitUntilOperatingSystemConfigReady = g.Add(flow.Task{
			Name:         "Waiting until operating system configurations for worker nodes have been reconciled",
			Fn:           botanist.Shoot.Components.Extensions.OperatingSystemConfig.Wait,
			Dependencies: flow.NewTaskIDs(deployOperatingSystemConfig),
		})
		deleteStaleOperatingSystemConfigResources = g.Add(flow.Task{
			Name:         "Delete stale operating system config resources",
			Fn:           flow.TaskFn(botanist.Shoot.Components.Extensions.OperatingSystemConfig.DeleteStaleResources).RetryUntilTimeout(defaultInterval, defaultTimeout),
			Dependencies: flow.NewTaskIDs(deployOperatingSystemConfig),
		})
		_ = g.Add(flow.Task{
			Name:         "Waiting until stale operating system config resources are deleted",
			Fn:           flow.TaskFn(botanist.Shoot.Components.Extensions.OperatingSystemConfig.WaitCleanupStaleResources).SkipIf(o.Shoot.HibernationEnabled),
			Dependencies: flow.NewTaskIDs(deleteStaleOperatingSystemConfigResources),
		})
		deployNetwork = g.Add(flow.Task{
			Name:         "Deploying shoot network plugin",
			Fn:           flow.TaskFn(botanist.DeployNetwork).RetryUntilTimeout(defaultInterval, defaultTimeout),
			Dependencies: flow.NewTaskIDs(deployReferencedResources, deployGardenerResourceManager, waitUntilOperatingSystemConfigReady, deployKubeScheduler),
		})
		waitUntilNetworkIsReady = g.Add(flow.Task{
			Name:         "Waiting until shoot network plugin has been reconciled",
			Fn:           botanist.Shoot.Components.Extensions.Network.Wait,
			Dependencies: flow.NewTaskIDs(deployNetwork),
		})
		_ = g.Add(flow.Task{
			Name:         "Deploying shoot cluster-identity",
			Fn:           flow.TaskFn(botanist.DeployClusterIdentity).RetryUntilTimeout(defaultInterval, defaultTimeout).SkipIf(o.Shoot.HibernationEnabled),
			Dependencies: flow.NewTaskIDs(deployGardenerResourceManager, ensureShootClusterIdentity, waitUntilOperatingSystemConfigReady),
		})
		_ = g.Add(flow.Task{
			Name:         "Deploying shoot namespaces system component",
			Fn:           flow.TaskFn(botanist.Shoot.Components.SystemComponents.Namespaces.Deploy).RetryUntilTimeout(defaultInterval, defaultTimeout).SkipIf(o.Shoot.HibernationEnabled),
			Dependencies: flow.NewTaskIDs(deployGardenerResourceManager, waitUntilOperatingSystemConfigReady),
		})
		_ = g.Add(flow.Task{
			Name: "Deploying CoreDNS system component",
			Fn: flow.TaskFn(func(ctx context.Context) error {
				if err := botanist.DeployCoreDNS(ctx); err != nil {
					return err
				}
				if controllerutils.HasTask(o.Shoot.GetInfo().Annotations, v1beta1constants.ShootTaskRestartCoreAddons) {
					return removeTaskAnnotation(ctx, o, generation, v1beta1constants.ShootTaskRestartCoreAddons)
				}
				return nil
			}).RetryUntilTimeout(defaultInterval, defaultTimeout).SkipIf(o.Shoot.HibernationEnabled),
			Dependencies: flow.NewTaskIDs(deployGardenerResourceManager, initializeShootClients, waitUntilOperatingSystemConfigReady, deployKubeScheduler),
		})
		_ = g.Add(flow.Task{
			Name:         "Deploying metrics-server system component",
			Fn:           flow.TaskFn(botanist.DeployMetricsServer).RetryUntilTimeout(defaultInterval, defaultTimeout).SkipIf(o.Shoot.HibernationEnabled),
			Dependencies: flow.NewTaskIDs(deployGardenerResourceManager, waitUntilOperatingSystemConfigReady, deployKubeScheduler),
		})
		_ = g.Add(flow.Task{
			Name:         "Deploying VPNShoot system component",
			Fn:           flow.TaskFn(botanist.DeployVPNShoot).RetryUntilTimeout(defaultInterval, defaultTimeout).SkipIf(o.Shoot.HibernationEnabled),
			Dependencies: flow.NewTaskIDs(deployGardenerResourceManager, waitUntilOperatingSystemConfigReady, deployKubeScheduler),
		})
		deployManagedResourcesForAddons = g.Add(flow.Task{
			Name:         "Deploying managed resources for system components and optional addons",
			Fn:           flow.TaskFn(botanist.DeployManagedResourceForAddons).RetryUntilTimeout(defaultInterval, defaultTimeout).SkipIf(o.Shoot.HibernationEnabled),
			Dependencies: flow.NewTaskIDs(deployGardenerResourceManager, initializeShootClients, ensureShootClusterIdentity, deployKubeScheduler),
		})
		deployManagedResourceForCloudConfigExecutor = g.Add(flow.Task{
			Name:         "Deploying managed resources for the cloud config executors",
			Fn:           flow.TaskFn(botanist.DeployManagedResourceForCloudConfigExecutor).RetryUntilTimeout(defaultInterval, defaultTimeout).SkipIf(o.Shoot.HibernationEnabled),
			Dependencies: flow.NewTaskIDs(deployGardenerResourceManager, ensureShootClusterIdentity, waitUntilOperatingSystemConfigReady),
		})
		deployWorker = g.Add(flow.Task{
			Name:         "Configuring shoot worker pools",
			Fn:           flow.TaskFn(botanist.DeployWorker).RetryUntilTimeout(defaultInterval, defaultTimeout),
			Dependencies: flow.NewTaskIDs(deployCloudProviderSecret, deployReferencedResources, waitUntilInfrastructureReady, initializeShootClients, waitUntilOperatingSystemConfigReady, waitUntilNetworkIsReady),
		})
		_ = g.Add(flow.Task{
			Name:         "Reconciling Grafana for Shoot in Seed for the logging stack",
			Fn:           flow.TaskFn(botanist.DeploySeedGrafana).RetryUntilTimeout(defaultInterval, 2*time.Minute),
			Dependencies: flow.NewTaskIDs(deploySeedLogging),
		})
		waitUntilWorkerReady = g.Add(flow.Task{
			Name:         "Waiting until shoot worker nodes have been reconciled",
			Fn:           botanist.Shoot.Components.Extensions.Worker.Wait,
			Dependencies: flow.NewTaskIDs(deployWorker, deployManagedResourceForCloudConfigExecutor),
		})
		nginxLBReady = g.Add(flow.Task{
			Name:         "Waiting until nginx ingress LoadBalancer is ready",
			Fn:           flow.TaskFn(botanist.WaitUntilNginxIngressServiceIsReady).DoIf(gardencorev1beta1helper.NginxIngressEnabled(botanist.Shoot.GetInfo().Spec.Addons)).SkipIf(o.Shoot.HibernationEnabled),
			Dependencies: flow.NewTaskIDs(deployManagedResourcesForAddons, initializeShootClients, waitUntilWorkerReady, ensureShootClusterIdentity),
		})
		deployIngressDomainDNSRecord = g.Add(flow.Task{
			Name:         "Deploying nginx ingress DNS record",
			Fn:           flow.TaskFn(botanist.DeployIngressDNSResources).DoIf(!o.Shoot.HibernationEnabled),
			Dependencies: flow.NewTaskIDs(nginxLBReady),
		})
		_ = g.Add(flow.Task{
			Name:         "Deploying additional DNS providers",
			Fn:           flow.TaskFn(botanist.DeployAdditionalDNSProviders).DoIf(!o.Shoot.HibernationEnabled),
			Dependencies: flow.NewTaskIDs(deployInternalDomainDNSRecord, deployExternalDomainDNSRecord, deployIngressDomainDNSRecord, deployOwnerDomainDNSRecord),
		})
		vpnLBReady = g.Add(flow.Task{
			Name:         "Waiting until vpn-shoot LoadBalancer is ready",
			Fn:           flow.TaskFn(botanist.WaitUntilVpnShootServiceIsReady).SkipIf(o.Shoot.HibernationEnabled || o.Shoot.ReversedVPNEnabled),
			Dependencies: flow.NewTaskIDs(deployManagedResourcesForAddons, waitUntilNetworkIsReady, waitUntilWorkerReady),
		})
		waitUntilTunnelConnectionExists = g.Add(flow.Task{
			Name:         "Waiting until the Kubernetes API server can connect to the Shoot workers",
			Fn:           flow.TaskFn(botanist.WaitUntilTunnelConnectionExists).SkipIf(o.Shoot.HibernationEnabled),
			Dependencies: flow.NewTaskIDs(deployManagedResourcesForAddons, waitUntilNetworkIsReady, waitUntilWorkerReady, vpnLBReady),
		})
		_ = g.Add(flow.Task{
			Name:         "Waiting until all shoot worker nodes have updated the cloud config user data",
			Fn:           flow.TaskFn(botanist.WaitUntilCloudConfigUpdatedForAllWorkerPools).SkipIf(o.Shoot.HibernationEnabled),
			Dependencies: flow.NewTaskIDs(waitUntilWorkerReady, waitUntilTunnelConnectionExists),
		})
		_ = g.Add(flow.Task{
			Name: "Finishing Kubernetes API server service SNI transition",
			Fn: flow.TaskFn(func(ctx context.Context) error {
				return botanist.DeployKubeAPIService(ctx, sniPhase.Done())
			}).
				RetryUntilTimeout(defaultInterval, defaultTimeout).
				SkipIf(o.Shoot.HibernationEnabled).
				DoIf(sniPhase == component.PhaseEnabling || sniPhase == component.PhaseDisabling),
			Dependencies: flow.NewTaskIDs(waitUntilTunnelConnectionExists),
		})
		_ = g.Add(flow.Task{
			Name: "Deleting SNI resources if SNI is disabled",
			Fn: flow.TaskFn(botanist.Shoot.Components.ControlPlane.KubeAPIServerSNI.Destroy).
				RetryUntilTimeout(defaultInterval, defaultTimeout).
				DoIf(sniPhase.Done() == component.PhaseDisabled),
			Dependencies: flow.NewTaskIDs(waitUntilTunnelConnectionExists),
		})
		deploySeedMonitoring = g.Add(flow.Task{
			Name:         "Deploying Shoot monitoring stack in Seed",
			Fn:           flow.TaskFn(botanist.DeploySeedMonitoring).RetryUntilTimeout(defaultInterval, 2*time.Minute),
			Dependencies: flow.NewTaskIDs(initializeShootClients, waitUntilTunnelConnectionExists, waitUntilWorkerReady).InsertIf(!staticNodesCIDR, waitUntilInfrastructureReady),
		})
		_ = g.Add(flow.Task{
			Name:         "Reconciling Grafana for Shoot in Seed for the monitoring stack",
			Fn:           flow.TaskFn(botanist.DeploySeedGrafana).RetryUntilTimeout(defaultInterval, 2*time.Minute),
			Dependencies: flow.NewTaskIDs(deploySeedMonitoring),
		})
		deployClusterAutoscaler = g.Add(flow.Task{
			Name:         "Deploying cluster autoscaler",
			Fn:           flow.TaskFn(botanist.DeployClusterAutoscaler).RetryUntilTimeout(defaultInterval, defaultTimeout),
			Dependencies: flow.NewTaskIDs(waitUntilWorkerReady, deployManagedResourcesForAddons, deployManagedResourceForCloudConfigExecutor),
		})

		hibernateControlPlane = g.Add(flow.Task{
			Name:         "Hibernating control plane",
			Fn:           flow.TaskFn(botanist.HibernateControlPlane).RetryUntilTimeout(defaultInterval, 2*time.Minute).DoIf(o.Shoot.HibernationEnabled),
			Dependencies: flow.NewTaskIDs(initializeShootClients, deploySeedMonitoring, deploySeedLogging, deployClusterAutoscaler),
		})
		_ = g.Add(flow.Task{
			Name:         "Destroying ingress domain DNS record if hibernated",
			Fn:           flow.TaskFn(botanist.DestroyIngressDNSResources).DoIf(o.Shoot.HibernationEnabled),
			Dependencies: flow.NewTaskIDs(hibernateControlPlane),
		})
		_ = g.Add(flow.Task{
			Name:         "Destroying external domain DNS record if hibernated",
			Fn:           flow.TaskFn(botanist.DestroyExternalDNSResources).DoIf(o.Shoot.HibernationEnabled),
			Dependencies: flow.NewTaskIDs(hibernateControlPlane),
		})
		_ = g.Add(flow.Task{
			Name:         "Destroying internal domain DNS record if hibernated",
			Fn:           flow.TaskFn(botanist.DestroyInternalDNSResources).DoIf(o.Shoot.HibernationEnabled),
			Dependencies: flow.NewTaskIDs(hibernateControlPlane),
		})
		deployExtensionResources = g.Add(flow.Task{
			Name:         "Deploying extension resources",
			Fn:           flow.TaskFn(botanist.DeployExtensions).RetryUntilTimeout(defaultInterval, defaultTimeout),
			Dependencies: flow.NewTaskIDs(deployReferencedResources, initializeShootClients),
		})
		_ = g.Add(flow.Task{
			Name:         "Waiting until extension resources are ready",
			Fn:           botanist.Shoot.Components.Extensions.Extension.Wait,
			Dependencies: flow.NewTaskIDs(deployExtensionResources),
		})
		deleteStaleExtensionResources = g.Add(flow.Task{
			Name:         "Delete stale extension resources",
			Fn:           flow.TaskFn(botanist.Shoot.Components.Extensions.Extension.DeleteStaleResources).RetryUntilTimeout(defaultInterval, defaultTimeout),
			Dependencies: flow.NewTaskIDs(initializeShootClients),
		})
		_ = g.Add(flow.Task{
			Name:         "Waiting until stale extension resources are deleted",
			Fn:           flow.TaskFn(botanist.Shoot.Components.Extensions.Extension.WaitCleanupStaleResources).SkipIf(o.Shoot.HibernationEnabled),
			Dependencies: flow.NewTaskIDs(deleteStaleExtensionResources),
		})
		deployContainerRuntimeResources = g.Add(flow.Task{
			Name:         "Deploying container runtime resources",
			Fn:           flow.TaskFn(botanist.DeployContainerRuntime).RetryUntilTimeout(defaultInterval, defaultTimeout),
			Dependencies: flow.NewTaskIDs(deployReferencedResources, initializeShootClients),
		})
		_ = g.Add(flow.Task{
			Name:         "Waiting until container runtime resources are ready",
			Fn:           botanist.Shoot.Components.Extensions.ContainerRuntime.Wait,
			Dependencies: flow.NewTaskIDs(deployContainerRuntimeResources),
		})
		deleteStaleContainerRuntimeResources = g.Add(flow.Task{
			Name:         "Delete stale container runtime resources",
			Fn:           flow.TaskFn(botanist.Shoot.Components.Extensions.ContainerRuntime.DeleteStaleResources).RetryUntilTimeout(defaultInterval, defaultTimeout),
			Dependencies: flow.NewTaskIDs(initializeShootClients),
		})
		_ = g.Add(flow.Task{
			Name:         "Waiting until stale container runtime resources are deleted",
			Fn:           flow.TaskFn(botanist.Shoot.Components.Extensions.ContainerRuntime.WaitCleanupStaleResources).SkipIf(o.Shoot.HibernationEnabled),
			Dependencies: flow.NewTaskIDs(deleteStaleContainerRuntimeResources),
		})
		_ = g.Add(flow.Task{
			Name: "Restart control plane pods",
			Fn: flow.TaskFn(func(ctx context.Context) error {
				if err := botanist.RestartControlPlanePods(ctx); err != nil {
					return err
				}
				return removeTaskAnnotation(ctx, o, generation, v1beta1constants.ShootTaskRestartControlPlanePods)
			}).DoIf(requestControlPlanePodsRestart),
			Dependencies: flow.NewTaskIDs(deployKubeControllerManager, deployControlPlane, deployControlPlaneExposure),
		})
		_ = g.Add(flow.Task{
			Name:         "Deploying Kubernetes vertical pod autoscaler",
			Fn:           flow.TaskFn(botanist.DeployVerticalPodAutoscaler).RetryUntilTimeout(defaultInterval, defaultTimeout),
			Dependencies: flow.NewTaskIDs(deploySecrets, waitUntilKubeAPIServerIsReady, deployManagedResourcesForAddons, deployManagedResourceForCloudConfigExecutor, hibernateControlPlane),
		})
	)

	f := g.Compile()

	if err := f.Run(ctx, flow.Opts{
		Logger:           o.Logger,
		ProgressReporter: r.newProgressReporter(o.ReportShootProgress),
		ErrorContext:     errorContext,
		ErrorCleaner:     o.CleanShootTaskError,
	}); err != nil {
		o.Logger.Errorf("Failed to reconcile Shoot %q: %+v", o.Shoot.GetInfo().Name, err)
		return gardencorev1beta1helper.NewWrappedLastErrors(gardencorev1beta1helper.FormatLastErrDescription(err), flow.Errors(err))
	}

	// ensure that shoot client is invalidated after it has been hibernated
	if o.Shoot.HibernationEnabled {
		if err := o.ClientMap.InvalidateClient(keys.ForShoot(o.Shoot.GetInfo())); err != nil {
			err = fmt.Errorf("failed to invalidate shoot client: %w", err)
			return gardencorev1beta1helper.NewWrappedLastErrors(gardencorev1beta1helper.FormatLastErrDescription(err), err)
		}
	}

	o.Logger.Infof("Successfully reconciled Shoot %q", o.Shoot.GetInfo().Name)
	return nil
}

func removeTaskAnnotation(ctx context.Context, o *operation.Operation, generation int64, tasksToRemove ...string) error {
	// Check if shoot generation was changed mid-air, i.e., whether we need to wait for the next reconciliation until we
	// can safely remove the task annotations to ensure all required tasks are executed.
	shoot := &gardencorev1beta1.Shoot{}
	if err := o.K8sGardenClient.APIReader().Get(ctx, kutil.Key(o.Shoot.GetInfo().Namespace, o.Shoot.GetInfo().Name), shoot); err != nil {
		return err
	}

	if shoot.Generation != generation {
		return nil
	}

	return o.Shoot.UpdateInfo(ctx, o.K8sGardenClient.Client(), false, func(shoot *gardencorev1beta1.Shoot) error {
		controllerutils.RemoveTasks(shoot.Annotations, tasksToRemove...)
		return nil
	})
}
