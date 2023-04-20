// Copyright 2018 SAP SE or an SAP affiliate company. All rights reserved. This file is licensed under the Apache Software License, v. 2 except as noted otherwise in the LICENSE file
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

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	gardencorev1beta1 "github.com/gardener/gardener/pkg/apis/core/v1beta1"
	v1beta1constants "github.com/gardener/gardener/pkg/apis/core/v1beta1/constants"
	v1beta1helper "github.com/gardener/gardener/pkg/apis/core/v1beta1/helper"
	"github.com/gardener/gardener/pkg/client/kubernetes/clientmap/keys"
	"github.com/gardener/gardener/pkg/controllerutils"
	"github.com/gardener/gardener/pkg/gardenlet/controller/shoot/shoot/helper"
	"github.com/gardener/gardener/pkg/operation"
	botanistpkg "github.com/gardener/gardener/pkg/operation/botanist"
	"github.com/gardener/gardener/pkg/operation/botanist/component"
	"github.com/gardener/gardener/pkg/operation/botanist/component/kubeapiserver"
	"github.com/gardener/gardener/pkg/utils"
	"github.com/gardener/gardener/pkg/utils/errors"
	"github.com/gardener/gardener/pkg/utils/flow"
	"github.com/gardener/gardener/pkg/utils/gardener/secretsrotation"
	kubernetesutils "github.com/gardener/gardener/pkg/utils/kubernetes"
	retryutils "github.com/gardener/gardener/pkg/utils/retry"
)

// runReconcileShootFlow reconciles the Shoot cluster.
// It receives an Operation object <o> which stores the Shoot object.
func (r *Reconciler) runReconcileShootFlow(ctx context.Context, o *operation.Operation, operationType gardencorev1beta1.LastOperationType) *v1beta1helper.WrappedLastErrors {
	// We create the botanists (which will do the actual work).
	var (
		botanist                *botanistpkg.Botanist
		err                     error
		isCopyOfBackupsRequired bool
		tasksWithErrors         []string

		isRestoring   = operationType == gardencorev1beta1.LastOperationTypeRestore
		skipReadiness = metav1.HasAnnotation(o.Shoot.GetInfo().ObjectMeta, v1beta1constants.AnnotationShootSkipReadiness)
	)

	for _, lastError := range o.Shoot.GetInfo().Status.LastErrors {
		if lastError.TaskID != nil {
			tasksWithErrors = append(tasksWithErrors, *lastError.TaskID)
		}
	}

	errorContext := errors.NewErrorContext(fmt.Sprintf("Shoot cluster %s", utils.IifString(isRestoring, "restoration", "reconciliation")), tasksWithErrors)

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
		return v1beta1helper.NewWrappedLastErrors(v1beta1helper.FormatLastErrDescription(err), err)
	}

	const (
		defaultTimeout  = 30 * time.Second
		defaultInterval = 5 * time.Second
	)

	var (
		allowBackup                     = o.Seed.GetInfo().Spec.Backup != nil
		staticNodesCIDR                 = o.Shoot.GetInfo().Spec.Networking != nil && o.Shoot.GetInfo().Spec.Networking.Nodes != nil
		workerless                      = botanist.Shoot.IsWorkerless
		useSNI                          = botanist.APIServerSNIEnabled()
		generation                      = o.Shoot.GetInfo().Generation
		sniPhase                        = botanist.Shoot.Components.ControlPlane.KubeAPIServerSNIPhase
		requestControlPlanePodsRestart  = controllerutils.HasTask(o.Shoot.GetInfo().Annotations, v1beta1constants.ShootTaskRestartControlPlanePods)
		kubeProxyEnabled                = v1beta1helper.KubeProxyEnabled(o.Shoot.GetInfo().Spec.Kubernetes.KubeProxy)
		shootControlPlaneLoggingEnabled = botanist.Shoot.IsShootControlPlaneLoggingEnabled(botanist.Config)
		deployKubeAPIServerTaskTimeout  = defaultTimeout
		shootSSHAccessEnabled           = v1beta1helper.ShootEnablesSSHAccess(o.Shoot.GetInfo())
	)

	// During the 'Preparing' phase of different rotation operations, components are deployed twice. Also, the
	// different deployment functions call the `Wait` method after the first deployment. Hence, we should use
	// the respective timeout in this case instead of the (too short) default timeout to prevent undesired and confusing
	// errors in the reconciliation flow.
	if v1beta1helper.GetShootETCDEncryptionKeyRotationPhase(o.Shoot.GetInfo().Status.Credentials) == gardencorev1beta1.RotationPreparing {
		deployKubeAPIServerTaskTimeout = kubeapiserver.TimeoutWaitForDeployment
	}

	var (
		deployExtensionAfterKAPIMsg = "Deploying extension resources after kube-apiserver"
		waitExtensionAfterKAPIMsg   = "Waiting until extension resources handled after kube-apiserver are ready"
	)
	if o.Shoot.HibernationEnabled {
		deployExtensionAfterKAPIMsg = "Hibernating extension resources before kube-apiserver hibernation"
		waitExtensionAfterKAPIMsg = "Waiting until extension resources hibernated before kube-apiserver hibernation are ready"
	}

	var (
		g                      = flow.NewGraph(fmt.Sprintf("Shoot cluster %s", utils.IifString(isRestoring, "restoration", "reconciliation")))
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
			Name: "Deploying cloud provider account secret",
			Fn: flow.TaskFn(func(ctx context.Context) error {
				if workerless {
					return nil
				}
				return botanist.DeployCloudProviderSecret(ctx)
			}).RetryUntilTimeout(defaultInterval, defaultTimeout),
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
		initializeSecretsManagement = g.Add(flow.Task{
			Name:         "Initializing secrets management",
			Fn:           flow.TaskFn(botanist.InitializeSecretsManagement).RetryUntilTimeout(defaultInterval, defaultTimeout),
			Dependencies: flow.NewTaskIDs(deployNamespace, ensureShootStateExists),
		})
		_ = g.Add(flow.Task{
			Name:         "Deploying Kubernetes API server ingress with trusted certificate in the Seed cluster",
			Fn:           flow.TaskFn(botanist.DeployKubeAPIServerIngress),
			Dependencies: flow.NewTaskIDs(initializeSecretsManagement),
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
			Name: "Deploying internal domain DNS record",
			Fn: flow.TaskFn(func(ctx context.Context) error {
				if err := botanist.DeployOrDestroyInternalDNSRecord(ctx); err != nil {
					return err
				}
				return removeTaskAnnotation(ctx, o, generation, v1beta1constants.ShootTaskDeployDNSRecordInternal)
			}).DoIf(!o.Shoot.HibernationEnabled),
			Dependencies: flow.NewTaskIDs(deployReferencedResources, waitUntilKubeAPIServerServiceIsReady, deployOwnerDomainDNSRecord),
		})
		deployExternalDomainDNSRecord = g.Add(flow.Task{
			Name: "Deploying external domain DNS record",
			Fn: flow.TaskFn(func(ctx context.Context) error {
				if err := botanist.DeployOrDestroyExternalDNSRecord(ctx); err != nil {
					return err
				}
				return removeTaskAnnotation(ctx, o, generation, v1beta1constants.ShootTaskDeployDNSRecordExternal)
			}).DoIf(!o.Shoot.HibernationEnabled),
			Dependencies: flow.NewTaskIDs(deployReferencedResources, waitUntilKubeAPIServerServiceIsReady, deployOwnerDomainDNSRecord),
		})
		deployInfrastructure = g.Add(flow.Task{
			Name: "Deploying Shoot infrastructure",
			Fn: flow.TaskFn(func(ctx context.Context) error {
				if workerless {
					return nil
				}
				return botanist.DeployInfrastructure(ctx)
			}).RetryUntilTimeout(defaultInterval, defaultTimeout),
			Dependencies: flow.NewTaskIDs(initializeSecretsManagement, deployCloudProviderSecret, deployReferencedResources, deployOwnerDomainDNSRecord),
		})
		waitUntilInfrastructureReady = g.Add(flow.Task{
			Name: "Waiting until shoot infrastructure has been reconciled",
			Fn: flow.TaskFn(func(ctx context.Context) error {
				if workerless {
					return nil
				}
				if !skipReadiness {
					if err := botanist.WaitForInfrastructure(ctx); err != nil {
						return err
					}
				}
				return removeTaskAnnotation(ctx, o, generation, v1beta1constants.ShootTaskDeployInfrastructure)
			}),
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
					o.Shoot.Components.NetworkPolicies = botanist.DefaultNetworkPolicies()
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
			Fn:           flow.TaskFn(botanist.Shoot.Components.SourceBackupEntry.Wait).DoIf(isCopyOfBackupsRequired).SkipIf(skipReadiness),
			Dependencies: flow.NewTaskIDs(deploySourceBackupEntry),
		})
		deployBackupEntryInGarden = g.Add(flow.Task{
			Name:         "Deploying backup entry",
			Fn:           flow.TaskFn(botanist.DeployBackupEntry).DoIf(allowBackup),
			Dependencies: flow.NewTaskIDs(ensureShootStateExists, deployOwnerDomainDNSRecord, waitUntilSourceBackupEntryInGardenReconciled),
		})
		waitUntilBackupEntryInGardenReconciled = g.Add(flow.Task{
			Name:         "Waiting until the backup entry has been reconciled",
			Fn:           flow.TaskFn(botanist.Shoot.Components.BackupEntry.Wait).DoIf(allowBackup).SkipIf(skipReadiness),
			Dependencies: flow.NewTaskIDs(deployBackupEntryInGarden),
		})
		copyEtcdBackups = g.Add(flow.Task{
			Name:         "Copying etcd backups to new seed's backup bucket",
			Fn:           flow.TaskFn(botanist.DeployEtcdCopyBackupsTask).DoIf(isCopyOfBackupsRequired),
			Dependencies: flow.NewTaskIDs(initializeSecretsManagement, deployCloudProviderSecret, waitUntilBackupEntryInGardenReconciled, waitUntilSourceBackupEntryInGardenReconciled),
		})
		waitUntilEtcdBackupsCopied = g.Add(flow.Task{
			Name:         "Waiting until etcd backups are copied",
			Fn:           flow.TaskFn(botanist.Shoot.Components.ControlPlane.EtcdCopyBackupsTask.Wait).DoIf(isCopyOfBackupsRequired).SkipIf(skipReadiness),
			Dependencies: flow.NewTaskIDs(copyEtcdBackups),
		})
		_ = g.Add(flow.Task{
			Name:         "Destroying copy etcd backups task resource",
			Fn:           flow.TaskFn(botanist.Shoot.Components.ControlPlane.EtcdCopyBackupsTask.Destroy).DoIf(isCopyOfBackupsRequired),
			Dependencies: flow.NewTaskIDs(waitUntilEtcdBackupsCopied),
		})
		deployETCD = g.Add(flow.Task{
			Name:         "Deploying main and events etcd",
			Fn:           flow.TaskFn(botanist.DeployEtcd).RetryUntilTimeout(defaultInterval, helper.GetEtcdDeployTimeout(o.Shoot, defaultTimeout)),
			Dependencies: flow.NewTaskIDs(initializeSecretsManagement, deployCloudProviderSecret, waitUntilBackupEntryInGardenReconciled, waitUntilEtcdBackupsCopied),
		})
		_ = g.Add(flow.Task{
			Name:         "Destroying source backup entry",
			Fn:           flow.TaskFn(botanist.DestroySourceBackupEntry).DoIf(allowBackup),
			Dependencies: flow.NewTaskIDs(deployETCD),
		})
		waitUntilEtcdReady = g.Add(flow.Task{
			Name:         "Waiting until main and event etcd report readiness",
			Fn:           flow.TaskFn(botanist.WaitUntilEtcdsReady).SkipIf(o.Shoot.HibernationEnabled || skipReadiness),
			Dependencies: flow.NewTaskIDs(deployETCD),
		})
		deployControlPlane = g.Add(flow.Task{
			Name: "Deploying shoot control plane components",
			Fn: flow.TaskFn(func(ctx context.Context) error {
				if workerless {
					return nil
				}
				return botanist.DeployControlPlane(ctx)
			}).RetryUntilTimeout(defaultInterval, defaultTimeout),
			Dependencies: flow.NewTaskIDs(initializeSecretsManagement, deployCloudProviderSecret, deployReferencedResources, waitUntilInfrastructureReady),
		})
		waitUntilControlPlaneReady = g.Add(flow.Task{
			Name: "Waiting until shoot control plane has been reconciled",
			Fn: flow.TaskFn(func(ctx context.Context) error {
				if workerless || skipReadiness {
					return nil
				}
				return botanist.Shoot.Components.Extensions.ControlPlane.Wait(ctx)
			}).RetryUntilTimeout(defaultInterval, defaultTimeout),
			Dependencies: flow.NewTaskIDs(deployControlPlane),
		})
		deployExtensionResourcesBeforeKAPI = g.Add(flow.Task{
			Name:         "Deploying extension resources before kube-apiserver",
			Fn:           flow.TaskFn(botanist.DeployExtensionsBeforeKubeAPIServer).RetryUntilTimeout(defaultInterval, defaultTimeout).SkipIf(o.Shoot.HibernationEnabled),
			Dependencies: flow.NewTaskIDs(waitUntilControlPlaneReady),
		})
		waitUntilExtensionResourcesBeforeKAPIReady = g.Add(flow.Task{
			Name:         "Waiting until extension resources handled before kube-apiserver are ready",
			Fn:           flow.TaskFn(botanist.Shoot.Components.Extensions.Extension.WaitBeforeKubeAPIServer).SkipIf(o.Shoot.HibernationEnabled || skipReadiness),
			Dependencies: flow.NewTaskIDs(deployExtensionResourcesBeforeKAPI),
		})
		deployKubeAPIServer = g.Add(flow.Task{
			Name: "Deploying Kubernetes API server",
			Fn:   flow.TaskFn(botanist.DeployKubeAPIServer).RetryUntilTimeout(defaultInterval, deployKubeAPIServerTaskTimeout),
			Dependencies: flow.NewTaskIDs(
				initializeSecretsManagement,
				deployETCD,
				waitUntilEtcdReady,
				waitUntilKubeAPIServerServiceIsReady,
				waitUntilControlPlaneReady,
				waitUntilExtensionResourcesBeforeKAPIReady,
			).InsertIf(!staticNodesCIDR, waitUntilInfrastructureReady),
		})
		waitUntilKubeAPIServerIsReady = g.Add(flow.Task{
			Name:         "Waiting until Kubernetes API server rolled out",
			Fn:           flow.TaskFn(botanist.Shoot.Components.ControlPlane.KubeAPIServer.Wait).SkipIf(o.Shoot.HibernationEnabled || skipReadiness),
			Dependencies: flow.NewTaskIDs(deployKubeAPIServer),
		})
		deployGardenerResourceManager = g.Add(flow.Task{
			Name:         "Deploying gardener-resource-manager",
			Fn:           flow.TaskFn(botanist.DeployGardenerResourceManager).RetryUntilTimeout(defaultInterval, defaultTimeout),
			Dependencies: flow.NewTaskIDs(waitUntilKubeAPIServerIsReady),
		})
		waitUntilGardenerResourceManagerReady = g.Add(flow.Task{
			Name:         "Waiting until gardener-resource-manager reports readiness",
			Fn:           flow.TaskFn(botanist.Shoot.Components.ControlPlane.ResourceManager.Wait).SkipIf(o.Shoot.HibernationEnabled || skipReadiness),
			Dependencies: flow.NewTaskIDs(deployGardenerResourceManager),
		})
		_ = g.Add(flow.Task{
			Name: "Renewing shoot access secrets after creation of new ServiceAccount signing key",
			Fn: flow.TaskFn(botanist.RenewShootAccessSecrets).
				RetryUntilTimeout(defaultInterval, defaultTimeout).
				DoIf(v1beta1helper.GetShootServiceAccountKeyRotationPhase(o.Shoot.GetInfo().Status.Credentials) == gardencorev1beta1.RotationPreparing),
			Dependencies: flow.NewTaskIDs(waitUntilKubeAPIServerIsReady, waitUntilGardenerResourceManagerReady),
		})
		deploySeedLogging = g.Add(flow.Task{
			Name:         "Deploying shoot logging stack in Seed",
			Fn:           flow.TaskFn(botanist.DeploySeedLogging).RetryUntilTimeout(defaultInterval, defaultTimeout),
			Dependencies: flow.NewTaskIDs(deployNamespace, initializeSecretsManagement).InsertIf(shootControlPlaneLoggingEnabled, waitUntilGardenerResourceManagerReady),
		})
		deployShootNamespaces = g.Add(flow.Task{
			Name:         "Deploying shoot namespaces system component",
			Fn:           flow.TaskFn(botanist.Shoot.Components.SystemComponents.Namespaces.Deploy).RetryUntilTimeout(defaultInterval, defaultTimeout),
			Dependencies: flow.NewTaskIDs(deployGardenerResourceManager),
		})
		waitUntilShootNamespacesReady = g.Add(flow.Task{
			Name:         "Waiting until shoot namespaces have been reconciled",
			Fn:           flow.TaskFn(botanist.Shoot.Components.SystemComponents.Namespaces.Wait).SkipIf(o.Shoot.HibernationEnabled || skipReadiness),
			Dependencies: flow.NewTaskIDs(waitUntilGardenerResourceManagerReady, deployShootNamespaces),
		})
		deployVPNSeedServer = g.Add(flow.Task{
			Name: "Deploying vpn-seed-server",
			Fn: flow.TaskFn(func(ctx context.Context) error {
				if workerless {
					return nil
				}
				return botanist.DeployVPNServer(ctx)
			}).RetryUntilTimeout(defaultInterval, defaultTimeout),
			Dependencies: flow.NewTaskIDs(initializeSecretsManagement, deployNamespace, waitUntilKubeAPIServerIsReady),
		})
		deployControlPlaneExposure = g.Add(flow.Task{
			Name: "Deploying shoot control plane exposure components",
			Fn: flow.TaskFn(func(ctx context.Context) error {
				if workerless {
					return nil
				}
				return botanist.DeployControlPlaneExposure(ctx)
			}).RetryUntilTimeout(defaultInterval, defaultTimeout).SkipIf(useSNI),
			Dependencies: flow.NewTaskIDs(deployReferencedResources, waitUntilKubeAPIServerIsReady),
		})
		waitUntilControlPlaneExposureReady = g.Add(flow.Task{
			Name: "Waiting until Shoot control plane exposure has been reconciled",
			Fn: flow.TaskFn(func(ctx context.Context) error {
				if workerless {
					return nil
				}
				return botanist.Shoot.Components.Extensions.ControlPlaneExposure.Wait(ctx)
			}).SkipIf(useSNI || skipReadiness),
			Dependencies: flow.NewTaskIDs(deployControlPlaneExposure),
		})
		destroyControlPlaneExposure = g.Add(flow.Task{
			Name: "Destroying shoot control plane exposure",
			Fn: flow.TaskFn(func(ctx context.Context) error {
				if workerless {
					return nil
				}
				return botanist.Shoot.Components.Extensions.ControlPlaneExposure.Destroy(ctx)
			}).DoIf(useSNI),
			Dependencies: flow.NewTaskIDs(waitUntilKubeAPIServerIsReady),
		})
		waitUntilControlPlaneExposureDeleted = g.Add(flow.Task{
			Name: "Waiting until shoot control plane exposure has been destroyed",
			Fn: flow.TaskFn(func(ctx context.Context) error {
				if workerless {
					return nil
				}
				return botanist.Shoot.Components.Extensions.ControlPlaneExposure.WaitCleanup(ctx)
			}).DoIf(useSNI),
			Dependencies: flow.NewTaskIDs(destroyControlPlaneExposure),
		})
		deployGardenerAccess = g.Add(flow.Task{
			Name:         "Deploying Gardener shoot access resources",
			Fn:           flow.TaskFn(botanist.Shoot.Components.GardenerAccess.Deploy).RetryUntilTimeout(defaultInterval, defaultTimeout),
			Dependencies: flow.NewTaskIDs(initializeSecretsManagement, waitUntilGardenerResourceManagerReady),
		})
		initializeShootClients = g.Add(flow.Task{
			Name:         "Initializing connection to Shoot",
			Fn:           flow.TaskFn(botanist.InitializeDesiredShootClients).RetryUntilTimeout(defaultInterval, 2*time.Minute),
			Dependencies: flow.NewTaskIDs(waitUntilKubeAPIServerIsReady, waitUntilControlPlaneExposureReady, waitUntilControlPlaneExposureDeleted, deployInternalDomainDNSRecord, deployGardenerAccess),
		})
		rewriteSecretsAddLabel = g.Add(flow.Task{
			Name: "Labeling secrets to encrypt them with new ETCD encryption key",
			Fn: flow.TaskFn(func(ctx context.Context) error {
				return secretsrotation.RewriteSecretsAddLabel(ctx, o.Logger, o.ShootClientSet.Client(), o.SecretsManager)
			}).
				RetryUntilTimeout(30*time.Second, 10*time.Minute).
				DoIf(v1beta1helper.GetShootETCDEncryptionKeyRotationPhase(o.Shoot.GetInfo().Status.Credentials) == gardencorev1beta1.RotationPreparing),
			Dependencies: flow.NewTaskIDs(initializeShootClients),
		})
		_ = g.Add(flow.Task{
			Name: "Snapshotting ETCD after secrets were re-encrypted with new ETCD encryption key",
			Fn: flow.TaskFn(func(ctx context.Context) error {
				return secretsrotation.SnapshotETCDAfterRewritingSecrets(ctx, o.SeedClientSet.Client(), botanist.SnapshotEtcd, o.Shoot.SeedNamespace, "")
			}).
				DoIf(allowBackup && v1beta1helper.GetShootETCDEncryptionKeyRotationPhase(o.Shoot.GetInfo().Status.Credentials) == gardencorev1beta1.RotationPreparing),
			Dependencies: flow.NewTaskIDs(rewriteSecretsAddLabel),
		})
		_ = g.Add(flow.Task{
			Name: "Removing label from secrets after rotation of ETCD encryption key",
			Fn: flow.TaskFn(func(ctx context.Context) error {
				return secretsrotation.RewriteSecretsRemoveLabel(ctx, o.Logger, o.SeedClientSet.Client(), o.ShootClientSet.Client(), o.Shoot.SeedNamespace, "")
			}).
				RetryUntilTimeout(30*time.Second, 10*time.Minute).
				DoIf(v1beta1helper.GetShootETCDEncryptionKeyRotationPhase(o.Shoot.GetInfo().Status.Credentials) == gardencorev1beta1.RotationCompleting),
			Dependencies: flow.NewTaskIDs(initializeShootClients),
		})
		deployKubeScheduler = g.Add(flow.Task{
			Name: "Deploying Kubernetes scheduler",
			Fn: flow.TaskFn(func(ctx context.Context) error {
				if workerless {
					return nil
				}
				return botanist.Shoot.Components.ControlPlane.KubeScheduler.Deploy(ctx)
			}).RetryUntilTimeout(defaultInterval, defaultTimeout),
			Dependencies: flow.NewTaskIDs(initializeSecretsManagement, waitUntilGardenerResourceManagerReady),
		})
		_ = g.Add(flow.Task{
			Name: "Deploying Kubernetes vertical pod autoscaler",
			Fn: flow.TaskFn(func(ctx context.Context) error {
				if workerless {
					return nil
				}
				return botanist.DeployVerticalPodAutoscaler(ctx)
			}).RetryUntilTimeout(defaultInterval, defaultTimeout),
			Dependencies: flow.NewTaskIDs(initializeSecretsManagement, waitUntilGardenerResourceManagerReady),
		})
		_ = g.Add(flow.Task{
			Name:         "Deploying dependency-watchdog shoot access resources",
			Fn:           flow.TaskFn(botanist.DeployDependencyWatchdogAccess).RetryUntilTimeout(defaultInterval, defaultTimeout),
			Dependencies: flow.NewTaskIDs(initializeSecretsManagement, waitUntilGardenerResourceManagerReady),
		})
		deployKubeControllerManager = g.Add(flow.Task{
			Name:         "Deploying Kubernetes controller manager",
			Fn:           flow.TaskFn(botanist.DeployKubeControllerManager).RetryUntilTimeout(defaultInterval, defaultTimeout),
			Dependencies: flow.NewTaskIDs(initializeSecretsManagement, deployCloudProviderSecret, waitUntilKubeAPIServerIsReady),
		})
		waitUntilKubeControllerManagerReady = g.Add(flow.Task{
			Name: "Waiting until kube-controller-manager reports readiness",
			Fn: flow.TaskFn(botanist.Shoot.Components.ControlPlane.KubeControllerManager.Wait).DoIf(v1beta1helper.GetShootServiceAccountKeyRotationPhase(o.Shoot.GetInfo().Status.Credentials) == gardencorev1beta1.RotationPreparing).
				SkipIf(skipReadiness),
			Dependencies: flow.NewTaskIDs(deployKubeControllerManager),
		})
		createNewServiceAccountSecrets = g.Add(flow.Task{
			Name: "Creating new ServiceAccount secrets after creation of new signing key",
			Fn: flow.TaskFn(func(ctx context.Context) error {
				return secretsrotation.CreateNewServiceAccountSecrets(ctx, o.Logger, o.ShootClientSet.Client(), o.SecretsManager)
			}).
				RetryUntilTimeout(30*time.Second, 10*time.Minute).
				DoIf(v1beta1helper.GetShootServiceAccountKeyRotationPhase(o.Shoot.GetInfo().Status.Credentials) == gardencorev1beta1.RotationPreparing),
			Dependencies: flow.NewTaskIDs(initializeShootClients, waitUntilKubeControllerManagerReady),
		})
		_ = g.Add(flow.Task{
			Name: "Deleting old ServiceAccount secrets after rotation of signing key",
			Fn: flow.TaskFn(func(ctx context.Context) error {
				return secretsrotation.DeleteOldServiceAccountSecrets(ctx, o.Logger, o.ShootClientSet.Client(), o.Shoot.GetInfo().Status.Credentials.Rotation.ServiceAccountKey.LastInitiationFinishedTime.Time)
			}).
				RetryUntilTimeout(30*time.Second, 10*time.Minute).
				DoIf(v1beta1helper.GetShootServiceAccountKeyRotationPhase(o.Shoot.GetInfo().Status.Credentials) == gardencorev1beta1.RotationCompleting),
			Dependencies: flow.NewTaskIDs(initializeShootClients, waitUntilKubeControllerManagerReady),
		})
		deleteBastions = g.Add(flow.Task{
			Name:         "Deleting Bastions",
			Fn:           flow.TaskFn(botanist.DeleteBastions).SkipIf(shootSSHAccessEnabled),
			Dependencies: flow.NewTaskIDs(deployReferencedResources, waitUntilInfrastructureReady, waitUntilControlPlaneReady),
		})
		deployOperatingSystemConfig = g.Add(flow.Task{
			Name: "Deploying operating system specific configuration for shoot workers",
			Fn: flow.TaskFn(func(ctx context.Context) error {
				if workerless {
					return nil
				}
				return botanist.DeployOperatingSystemConfig(ctx)
			}).RetryUntilTimeout(defaultInterval, defaultTimeout),
			Dependencies: flow.NewTaskIDs(deployReferencedResources, waitUntilInfrastructureReady, waitUntilControlPlaneReady, deleteBastions),
		})
		waitUntilOperatingSystemConfigReady = g.Add(flow.Task{
			Name: "Waiting until operating system configurations for worker nodes have been reconciled",
			Fn: flow.TaskFn(func(ctx context.Context) error {
				if workerless {
					return nil
				}
				return botanist.Shoot.Components.Extensions.OperatingSystemConfig.Wait(ctx)
			}),
			Dependencies: flow.NewTaskIDs(deployOperatingSystemConfig),
		})
		deleteStaleOperatingSystemConfigResources = g.Add(flow.Task{
			Name: "Delete stale operating system config resources",
			Fn: flow.TaskFn(func(ctx context.Context) error {
				if workerless {
					return nil
				}
				return botanist.Shoot.Components.Extensions.OperatingSystemConfig.DeleteStaleResources(ctx)
			}).RetryUntilTimeout(defaultInterval, defaultTimeout),
			Dependencies: flow.NewTaskIDs(deployOperatingSystemConfig),
		})
		_ = g.Add(flow.Task{
			Name: "Waiting until stale operating system config resources are deleted",
			Fn: flow.TaskFn(func(ctx context.Context) error {
				if workerless || skipReadiness {
					return nil
				}
				return botanist.Shoot.Components.Extensions.OperatingSystemConfig.WaitCleanupStaleResources(ctx)
			}).SkipIf(o.Shoot.HibernationEnabled),
			Dependencies: flow.NewTaskIDs(deleteStaleOperatingSystemConfigResources),
		})
		deployNetwork = g.Add(flow.Task{
			Name: "Deploying shoot network plugin",
			Fn: flow.TaskFn(func(ctx context.Context) error {
				if workerless {
					return nil
				}
				return botanist.DeployNetwork(ctx)
			}).RetryUntilTimeout(defaultInterval, defaultTimeout),
			Dependencies: flow.NewTaskIDs(deployReferencedResources, waitUntilGardenerResourceManagerReady, waitUntilOperatingSystemConfigReady, deployKubeScheduler, waitUntilShootNamespacesReady),
		})
		waitUntilNetworkIsReady = g.Add(flow.Task{
			Name: "Waiting until shoot network plugin has been reconciled",
			Fn: flow.TaskFn(func(ctx context.Context) error {
				if workerless || skipReadiness {
					return nil
				}
				return botanist.Shoot.Components.Extensions.Network.Wait(ctx)
			}).RetryUntilTimeout(defaultInterval, defaultTimeout),
			Dependencies: flow.NewTaskIDs(deployNetwork),
		})
		_ = g.Add(flow.Task{
			Name: "Deploying shoot cluster identity",
			Fn: flow.TaskFn(func(ctx context.Context) error {
				return botanist.DeployClusterIdentity(ctx)
			}).RetryUntilTimeout(defaultInterval, defaultTimeout).SkipIf(o.Shoot.HibernationEnabled),
			Dependencies: flow.NewTaskIDs(deployGardenerResourceManager, ensureShootClusterIdentity, waitUntilOperatingSystemConfigReady),
		})
		deployShootSystemResources = g.Add(flow.Task{
			Name: "Deploying shoot system resources",
			Fn: flow.TaskFn(func(ctx context.Context) error {
				if workerless {
					return nil
				}
				return botanist.Shoot.Components.SystemComponents.Resources.Deploy(ctx)
			}).RetryUntilTimeout(defaultInterval, defaultTimeout).SkipIf(o.Shoot.HibernationEnabled),
			Dependencies: flow.NewTaskIDs(waitUntilGardenerResourceManagerReady, waitUntilOperatingSystemConfigReady, waitUntilShootNamespacesReady),
		})
		deployCoreDNS = g.Add(flow.Task{
			Name: "Deploying CoreDNS system component",
			Fn: flow.TaskFn(func(ctx context.Context) error {
				if workerless {
					return nil
				}
				if err := botanist.DeployCoreDNS(ctx); err != nil {
					return err
				}
				if controllerutils.HasTask(o.Shoot.GetInfo().Annotations, v1beta1constants.ShootTaskRestartCoreAddons) {
					return removeTaskAnnotation(ctx, o, generation, v1beta1constants.ShootTaskRestartCoreAddons)
				}
				return nil
			}).RetryUntilTimeout(defaultInterval, defaultTimeout).SkipIf(o.Shoot.HibernationEnabled),
			Dependencies: flow.NewTaskIDs(waitUntilGardenerResourceManagerReady, initializeShootClients, waitUntilOperatingSystemConfigReady, deployKubeScheduler, waitUntilShootNamespacesReady),
		})
		deployNodeLocalDNS = g.Add(flow.Task{
			Name: "Reconcile node-local-dns system component",
			Fn: flow.TaskFn(func(ctx context.Context) error {
				if workerless {
					return nil
				}
				return botanist.ReconcileNodeLocalDNS(ctx)
			}).SkipIf(o.Shoot.HibernationEnabled),
			Dependencies: flow.NewTaskIDs(deployGardenerResourceManager, initializeShootClients, waitUntilOperatingSystemConfigReady, deployKubeScheduler, waitUntilShootNamespacesReady, waitUntilNetworkIsReady),
		})
		deployMetricsServer = g.Add(flow.Task{
			Name: "Deploying metrics-server system component",
			Fn: flow.TaskFn(func(ctx context.Context) error {
				if workerless {
					return nil
				}
				return botanist.Shoot.Components.SystemComponents.MetricsServer.Deploy(ctx)
			}).RetryUntilTimeout(defaultInterval, defaultTimeout).SkipIf(o.Shoot.HibernationEnabled),
			Dependencies: flow.NewTaskIDs(waitUntilGardenerResourceManagerReady, waitUntilOperatingSystemConfigReady, deployKubeScheduler, waitUntilShootNamespacesReady),
		})
		deployVPNShoot = g.Add(flow.Task{
			Name: "Deploying vpn-shoot system component",
			Fn: flow.TaskFn(func(ctx context.Context) error {
				if workerless {
					return nil
				}
				return botanist.Shoot.Components.SystemComponents.VPNShoot.Deploy(ctx)
			}).RetryUntilTimeout(defaultInterval, defaultTimeout).SkipIf(o.Shoot.HibernationEnabled),
			Dependencies: flow.NewTaskIDs(waitUntilGardenerResourceManagerReady, deployGardenerResourceManager, deployKubeScheduler, deployVPNSeedServer, waitUntilShootNamespacesReady),
		})
		deployNodeProblemDetector = g.Add(flow.Task{
			Name: "Deploying node-problem-detector system component",
			Fn: flow.TaskFn(func(ctx context.Context) error {
				if workerless {
					return nil
				}
				return botanist.Shoot.Components.SystemComponents.NodeProblemDetector.Deploy(ctx)
			}).RetryUntilTimeout(defaultInterval, defaultTimeout).SkipIf(o.Shoot.HibernationEnabled),
			Dependencies: flow.NewTaskIDs(deployGardenerResourceManager, waitUntilOperatingSystemConfigReady, waitUntilShootNamespacesReady),
		})
		deployKubeProxy = g.Add(flow.Task{
			Name: "Deploying kube-proxy system component",
			Fn: flow.TaskFn(func(ctx context.Context) error {
				if workerless {
					return nil
				}
				return botanist.DeployKubeProxy(ctx)
			}).RetryUntilTimeout(defaultInterval, defaultTimeout).SkipIf(o.Shoot.HibernationEnabled).DoIf(kubeProxyEnabled),
			Dependencies: flow.NewTaskIDs(deployGardenerResourceManager, initializeShootClients, ensureShootClusterIdentity, deployKubeScheduler, waitUntilShootNamespacesReady),
		})
		_ = g.Add(flow.Task{
			Name: "Deleting stale kube-proxy DaemonSets",
			Fn: flow.TaskFn(func(ctx context.Context) error {
				if workerless {
					return nil
				}
				return botanist.Shoot.Components.SystemComponents.KubeProxy.DeleteStaleResources(ctx)
			}).RetryUntilTimeout(defaultInterval, defaultTimeout).DoIf(kubeProxyEnabled),
			Dependencies: flow.NewTaskIDs(deployKubeProxy),
		})
		_ = g.Add(flow.Task{
			Name: "Deleting kube-proxy system component",
			Fn: flow.TaskFn(func(ctx context.Context) error {
				if workerless {
					return nil
				}
				return botanist.Shoot.Components.SystemComponents.KubeProxy.Destroy(ctx)
			}).RetryUntilTimeout(defaultInterval, defaultTimeout).SkipIf(o.Shoot.HibernationEnabled).DoIf(!kubeProxyEnabled),
			Dependencies: flow.NewTaskIDs(deployGardenerResourceManager, initializeShootClients, ensureShootClusterIdentity, deployKubeScheduler),
		})
		deployAPIServerProxy = g.Add(flow.Task{
			Name: "Deploying apiserver-proxy",
			Fn: flow.TaskFn(func(ctx context.Context) error {
				if workerless {
					return nil
				}
				return botanist.DeployAPIServerProxy(ctx)
			}).RetryUntilTimeout(defaultInterval, defaultTimeout),
			Dependencies: flow.NewTaskIDs(waitUntilGardenerResourceManagerReady, initializeShootClients, ensureShootClusterIdentity, deployKubeScheduler, waitUntilShootNamespacesReady),
		})
		deployManagedResourcesForAddons = g.Add(flow.Task{
			Name:         "Deploying managed resources for system components and optional addons",
			Fn:           flow.TaskFn(botanist.DeployManagedResourceForAddons).RetryUntilTimeout(defaultInterval, defaultTimeout).SkipIf(o.Shoot.HibernationEnabled),
			Dependencies: flow.NewTaskIDs(waitUntilGardenerResourceManagerReady, initializeShootClients, ensureShootClusterIdentity, deployKubeScheduler, waitUntilShootNamespacesReady),
		})
		deployKubernetesDashboard = g.Add(flow.Task{
			Name: "Deploying addon Kubernetes Dashboard",
			Fn: flow.TaskFn(func(ctx context.Context) error {
				if workerless {
					return nil
				}
				return botanist.DeployKubernetesDashboard(ctx)
			}).RetryUntilTimeout(defaultInterval, defaultTimeout).SkipIf(o.Shoot.HibernationEnabled),
			Dependencies: flow.NewTaskIDs(waitUntilGardenerResourceManagerReady, initializeShootClients, ensureShootClusterIdentity, deployKubeScheduler, waitUntilShootNamespacesReady),
		})
		deployNginxIngressAddon = g.Add(flow.Task{
			Name: "Deploying addon Nginx Ingress Controller",
			Fn: flow.TaskFn(func(ctx context.Context) error {
				if workerless {
					return nil
				}
				return botanist.DeployNginxIngressAddon(ctx)
			}).RetryUntilTimeout(defaultInterval, defaultTimeout).SkipIf(o.Shoot.HibernationEnabled),
			Dependencies: flow.NewTaskIDs(waitUntilGardenerResourceManagerReady, initializeShootClients, ensureShootClusterIdentity, deployKubeScheduler, waitUntilShootNamespacesReady),
		})
		deployManagedResourceForCloudConfigExecutor = g.Add(flow.Task{
			Name: "Deploying managed resources for the cloud config executors",
			Fn: flow.TaskFn(func(ctx context.Context) error {
				if workerless {
					return nil
				}
				return botanist.DeployManagedResourceForCloudConfigExecutor(ctx)
			}).RetryUntilTimeout(defaultInterval, defaultTimeout).SkipIf(o.Shoot.HibernationEnabled),
			Dependencies: flow.NewTaskIDs(deployGardenerResourceManager, ensureShootClusterIdentity, waitUntilOperatingSystemConfigReady),
		})

		syncPointAllSystemComponentsDeployed = flow.NewTaskIDs(
			waitUntilNetworkIsReady,
			deployAPIServerProxy,
			deployShootSystemResources,
			deployCoreDNS,
			deployNodeLocalDNS,
			deployMetricsServer,
			deployVPNShoot,
			deployNodeProblemDetector,
			deployKubeProxy,
			deployManagedResourcesForAddons,
			deployKubernetesDashboard,
			deployNginxIngressAddon,
		)

		deployWorker = g.Add(flow.Task{
			Name: "Configuring shoot worker pools",
			Fn: flow.TaskFn(func(ctx context.Context) error {
				if workerless {
					return nil
				}
				return botanist.DeployWorker(ctx)
			}).RetryUntilTimeout(defaultInterval, defaultTimeout),
			Dependencies: flow.NewTaskIDs(deployCloudProviderSecret, deployReferencedResources, waitUntilInfrastructureReady, initializeShootClients, waitUntilOperatingSystemConfigReady, waitUntilNetworkIsReady, createNewServiceAccountSecrets),
		})
		_ = g.Add(flow.Task{
			Name:         "Reconciling Grafana for Shoot in Seed for the logging stack",
			Fn:           flow.TaskFn(botanist.DeploySeedGrafana).RetryUntilTimeout(defaultInterval, 2*time.Minute),
			Dependencies: flow.NewTaskIDs(deploySeedLogging),
		})
		waitUntilWorkerReady = g.Add(flow.Task{
			Name: "Waiting until shoot worker nodes have been reconciled",
			Fn: flow.TaskFn(func(ctx context.Context) error {
				if workerless || skipReadiness {
					return nil
				}
				return botanist.Shoot.Components.Extensions.Worker.Wait(ctx)
			}).RetryUntilTimeout(defaultInterval, defaultTimeout),
			Dependencies: flow.NewTaskIDs(deployWorker, deployManagedResourceForCloudConfigExecutor),
		})
		nginxLBReady = g.Add(flow.Task{
			Name: "Waiting until nginx ingress LoadBalancer is ready",
			Fn: flow.TaskFn(func(ctx context.Context) error {
				if workerless {
					return nil
				}
				return botanist.WaitUntilNginxIngressServiceIsReady(ctx)
			}).DoIf(v1beta1helper.NginxIngressEnabled(botanist.Shoot.GetInfo().Spec.Addons)).SkipIf(o.Shoot.HibernationEnabled),
			Dependencies: flow.NewTaskIDs(deployManagedResourcesForAddons, initializeShootClients, waitUntilWorkerReady, ensureShootClusterIdentity),
		})
		deployIngressDomainDNSRecord = g.Add(flow.Task{
			Name: "Deploying nginx ingress DNS record",
			Fn: flow.TaskFn(func(ctx context.Context) error {
				if err := botanist.DeployOrDestroyIngressDNSRecord(ctx); err != nil {
					return err
				}
				return removeTaskAnnotation(ctx, o, generation, v1beta1constants.ShootTaskDeployDNSRecordIngress)
			}).DoIf(!o.Shoot.HibernationEnabled),
			Dependencies: flow.NewTaskIDs(nginxLBReady),
		})
		_ = g.Add(flow.Task{
			Name:         "Cleaning up orphaned DNSRecord secrets",
			Fn:           flow.TaskFn(botanist.CleanupOrphanedDNSRecordSecrets).DoIf(!o.Shoot.HibernationEnabled),
			Dependencies: flow.NewTaskIDs(deployInternalDomainDNSRecord, deployExternalDomainDNSRecord, deployOwnerDomainDNSRecord, deployIngressDomainDNSRecord),
		})
		waitUntilTunnelConnectionExists = g.Add(flow.Task{
			Name: "Waiting until the Kubernetes API server can connect to the Shoot workers",
			Fn: flow.TaskFn(func(ctx context.Context) error {
				if workerless || skipReadiness {
					return nil
				}
				return botanist.WaitUntilTunnelConnectionExists(ctx)
			}).RetryUntilTimeout(defaultInterval, defaultTimeout).SkipIf(o.Shoot.HibernationEnabled),
			Dependencies: flow.NewTaskIDs(syncPointAllSystemComponentsDeployed, waitUntilNetworkIsReady, waitUntilWorkerReady),
		})
		_ = g.Add(flow.Task{
			Name: "Waiting until all shoot worker nodes have updated the cloud config user data",
			Fn: flow.TaskFn(func(ctx context.Context) error {
				if workerless {
					return nil
				}
				return botanist.WaitUntilCloudConfigUpdatedForAllWorkerPools(ctx)
			}).RetryUntilTimeout(defaultInterval, defaultTimeout).SkipIf(o.Shoot.HibernationEnabled),
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
			Name:         "Reconciling kube-state-metrics for Shoot in Seed for the monitoring stack",
			Fn:           flow.TaskFn(botanist.DeployKubeStateMetrics).RetryUntilTimeout(defaultInterval, 2*time.Minute).SkipIf(botanist.Shoot.IsWorkerless),
			Dependencies: flow.NewTaskIDs(deploySeedMonitoring),
		})
		_ = g.Add(flow.Task{
			Name:         "Reconciling Grafana for Shoot in Seed for the monitoring stack",
			Fn:           flow.TaskFn(botanist.DeploySeedGrafana).RetryUntilTimeout(defaultInterval, 2*time.Minute),
			Dependencies: flow.NewTaskIDs(deploySeedMonitoring),
		})
		deployClusterAutoscaler = g.Add(flow.Task{
			Name: "Deploying cluster autoscaler",
			Fn: flow.TaskFn(func(ctx context.Context) error {
				if workerless {
					return nil
				}
				return botanist.DeployClusterAutoscaler(ctx)
			}).RetryUntilTimeout(defaultInterval, defaultTimeout),
			Dependencies: flow.NewTaskIDs(waitUntilWorkerReady, deployManagedResourcesForAddons, deployManagedResourceForCloudConfigExecutor),
		})

		deployExtensionResourcesAfterKAPI = g.Add(flow.Task{
			Name:         deployExtensionAfterKAPIMsg,
			Fn:           flow.TaskFn(botanist.DeployExtensionsAfterKubeAPIServer).RetryUntilTimeout(defaultInterval, defaultTimeout),
			Dependencies: flow.NewTaskIDs(deployReferencedResources, initializeShootClients),
		})
		waitUntilExtensionResourcesAfterKAPIReady = g.Add(flow.Task{
			Name:         waitExtensionAfterKAPIMsg,
			Fn:           flow.TaskFn(botanist.Shoot.Components.Extensions.Extension.WaitAfterKubeAPIServer).SkipIf(skipReadiness),
			Dependencies: flow.NewTaskIDs(deployExtensionResourcesAfterKAPI),
		})

		hibernateControlPlane = g.Add(flow.Task{
			Name:         "Hibernating control plane",
			Fn:           flow.TaskFn(botanist.HibernateControlPlane).RetryUntilTimeout(defaultInterval, 2*time.Minute).DoIf(o.Shoot.HibernationEnabled),
			Dependencies: flow.NewTaskIDs(initializeShootClients, deploySeedMonitoring, deploySeedLogging, deployClusterAutoscaler, waitUntilExtensionResourcesAfterKAPIReady),
		})

		// logic is inverted here
		// extensions that are deployed before the kube-apiserver are hibernated after it
		hibernateExtensionResourcesAfterKAPIHibernation = g.Add(flow.Task{
			Name:         "Hibernating extension resources after kube-apiserver hibernation",
			Fn:           flow.TaskFn(botanist.DeployExtensionsBeforeKubeAPIServer).RetryUntilTimeout(defaultInterval, defaultTimeout).DoIf(o.Shoot.HibernationEnabled),
			Dependencies: flow.NewTaskIDs(hibernateControlPlane),
		})
		_ = g.Add(flow.Task{
			Name:         "Waiting until extension resources hibernated after kube-apiserver hibernation are ready",
			Fn:           flow.TaskFn(botanist.Shoot.Components.Extensions.Extension.WaitBeforeKubeAPIServer).DoIf(o.Shoot.HibernationEnabled).SkipIf(skipReadiness),
			Dependencies: flow.NewTaskIDs(hibernateExtensionResourcesAfterKAPIHibernation),
		})
		_ = g.Add(flow.Task{
			Name:         "Destroying ingress domain DNS record if hibernated",
			Fn:           flow.TaskFn(botanist.DestroyIngressDNSRecord).DoIf(o.Shoot.HibernationEnabled),
			Dependencies: flow.NewTaskIDs(hibernateControlPlane),
		})
		_ = g.Add(flow.Task{
			Name:         "Destroying external domain DNS record if hibernated",
			Fn:           flow.TaskFn(botanist.DestroyExternalDNSRecord).DoIf(o.Shoot.HibernationEnabled),
			Dependencies: flow.NewTaskIDs(hibernateControlPlane),
		})
		_ = g.Add(flow.Task{
			Name:         "Destroying internal domain DNS record if hibernated",
			Fn:           flow.TaskFn(botanist.DestroyInternalDNSRecord).DoIf(o.Shoot.HibernationEnabled),
			Dependencies: flow.NewTaskIDs(hibernateControlPlane),
		})
		deleteStaleExtensionResources = g.Add(flow.Task{
			Name:         "Deleting stale extension resources",
			Fn:           flow.TaskFn(botanist.Shoot.Components.Extensions.Extension.DeleteStaleResources).RetryUntilTimeout(defaultInterval, defaultTimeout),
			Dependencies: flow.NewTaskIDs(initializeShootClients),
		})
		_ = g.Add(flow.Task{
			Name:         "Waiting until stale extension resources are deleted",
			Fn:           flow.TaskFn(botanist.Shoot.Components.Extensions.Extension.WaitCleanupStaleResources).SkipIf(o.Shoot.HibernationEnabled || skipReadiness),
			Dependencies: flow.NewTaskIDs(deleteStaleExtensionResources),
		})
		deployContainerRuntimeResources = g.Add(flow.Task{
			Name: "Deploying container runtime resources",
			Fn: flow.TaskFn(func(ctx context.Context) error {
				if workerless {
					return nil
				}
				return botanist.DeployContainerRuntime(ctx)
			}).RetryUntilTimeout(defaultInterval, defaultTimeout),
			Dependencies: flow.NewTaskIDs(deployReferencedResources, initializeShootClients),
		})
		_ = g.Add(flow.Task{
			Name: "Waiting until container runtime resources are ready",
			Fn: flow.TaskFn(func(ctx context.Context) error {
				if workerless || skipReadiness {
					return nil
				}
				return botanist.Shoot.Components.Extensions.ContainerRuntime.Wait(ctx)
			}).RetryUntilTimeout(defaultInterval, defaultTimeout),
			Dependencies: flow.NewTaskIDs(deployContainerRuntimeResources),
		})
		deleteStaleContainerRuntimeResources = g.Add(flow.Task{
			Name: "Deleting stale container runtime resources",
			Fn: flow.TaskFn(func(ctx context.Context) error {
				if workerless {
					return nil
				}
				return botanist.Shoot.Components.Extensions.ContainerRuntime.DeleteStaleResources(ctx)
			}).RetryUntilTimeout(defaultInterval, defaultTimeout),
			Dependencies: flow.NewTaskIDs(initializeShootClients),
		})
		_ = g.Add(flow.Task{
			Name: "Waiting until stale container runtime resources are deleted",
			Fn: flow.TaskFn(func(ctx context.Context) error {
				if workerless {
					return nil
				}
				return botanist.Shoot.Components.Extensions.ContainerRuntime.WaitCleanupStaleResources(ctx)
			}).SkipIf(o.Shoot.HibernationEnabled || skipReadiness),
			Dependencies: flow.NewTaskIDs(deleteStaleContainerRuntimeResources),
		})
		_ = g.Add(flow.Task{
			Name: "Restarting control plane pods",
			Fn: flow.TaskFn(func(ctx context.Context) error {
				if err := botanist.RestartControlPlanePods(ctx); err != nil {
					return err
				}
				return removeTaskAnnotation(ctx, o, generation, v1beta1constants.ShootTaskRestartControlPlanePods)
			}).DoIf(requestControlPlanePodsRestart),
			Dependencies: flow.NewTaskIDs(deployKubeControllerManager, deployControlPlane, deployControlPlaneExposure),
		})
	)

	f := g.Compile()

	if err := f.Run(ctx, flow.Opts{
		Log:              o.Logger,
		ProgressReporter: r.newProgressReporter(o.ReportShootProgress),
		ErrorContext:     errorContext,
		ErrorCleaner:     o.CleanShootTaskError,
	}); err != nil {
		return v1beta1helper.NewWrappedLastErrors(v1beta1helper.FormatLastErrDescription(err), flow.Errors(err))
	}

	o.Logger.Info("Cleaning no longer required secrets")
	if err := botanist.SecretsManager.Cleanup(ctx); err != nil {
		err = fmt.Errorf("failed to clean no longer required secrets: %w", err)
		return v1beta1helper.NewWrappedLastErrors(v1beta1helper.FormatLastErrDescription(err), err)
	}

	// ensure that shoot client is invalidated after it has been hibernated
	if o.Shoot.HibernationEnabled {
		if err := o.ShootClientMap.InvalidateClient(keys.ForShoot(o.Shoot.GetInfo())); err != nil {
			err = fmt.Errorf("failed to invalidate shoot client: %w", err)
			return v1beta1helper.NewWrappedLastErrors(v1beta1helper.FormatLastErrDescription(err), err)
		}
	}

	if _, ok := o.Shoot.GetInfo().Annotations[v1beta1constants.AnnotationShootSkipReadiness]; ok {
		o.Logger.Info("Removing skip-readiness annotation")

		if err := o.Shoot.UpdateInfo(ctx, o.GardenClient, false, func(shoot *gardencorev1beta1.Shoot) error {
			delete(shoot.ObjectMeta.Annotations, v1beta1constants.AnnotationShootSkipReadiness)
			return nil
		}); err != nil {
			return nil
		}
	}

	o.Logger.Info("Successfully reconciled Shoot cluster", "operation", utils.IifString(isRestoring, "restored", "reconciled"))
	return nil
}

func removeTaskAnnotation(ctx context.Context, o *operation.Operation, generation int64, tasksToRemove ...string) error {
	// Check if shoot generation was changed mid-air, i.e., whether we need to wait for the next reconciliation until we
	// can safely remove the task annotations to ensure all required tasks are executed.
	shoot := &gardencorev1beta1.Shoot{}
	if err := o.GardenClient.Get(ctx, kubernetesutils.Key(o.Shoot.GetInfo().Namespace, o.Shoot.GetInfo().Name), shoot); err != nil {
		return err
	}

	if shoot.Generation != generation {
		return nil
	}

	return o.Shoot.UpdateInfo(ctx, o.GardenClient, false, func(shoot *gardencorev1beta1.Shoot) error {
		controllerutils.RemoveTasks(shoot.Annotations, tasksToRemove...)
		return nil
	})
}
