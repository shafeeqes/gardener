// SPDX-FileCopyrightText: Contributors to the Gardener project
//
// SPDX-License-Identifier: Apache-2.0

package botanist

import (
	"context"
	"fmt"
	"strings"
	"time"

	"k8s.io/apimachinery/pkg/util/sets"

	v1beta1helper "github.com/gardener/gardener/pkg/api/core/v1beta1/helper"
	gardencorev1beta1 "github.com/gardener/gardener/pkg/apis/core/v1beta1"
	v1beta1constants "github.com/gardener/gardener/pkg/apis/core/v1beta1/constants"
	"github.com/gardener/gardener/pkg/component"
	"github.com/gardener/gardener/pkg/component/autoscaling/vpa"
	"github.com/gardener/gardener/pkg/component/etcd/etcd"
	extensioncrds "github.com/gardener/gardener/pkg/component/extensions/crds"
	"github.com/gardener/gardener/pkg/component/networking/istio"
	"github.com/gardener/gardener/pkg/component/nodemanagement/machinecontrollermanager"
	"github.com/gardener/gardener/pkg/component/observability/logging/fluentoperator"
	"github.com/gardener/gardener/pkg/component/observability/monitoring/prometheusoperator"
	seedsystem "github.com/gardener/gardener/pkg/component/seed/system"
	"github.com/gardener/gardener/pkg/component/shared"
	"github.com/gardener/gardener/pkg/controllerutils"
	gardenerextensions "github.com/gardener/gardener/pkg/extensions"
	"github.com/gardener/gardener/pkg/gardenlet/controller/shoot/shoot/helper"
	"github.com/gardener/gardener/pkg/utils/flow"
	gardenerutils "github.com/gardener/gardener/pkg/utils/gardener"
	kubernetesutils "github.com/gardener/gardener/pkg/utils/kubernetes"
)

const (
	defaultTimeout  = 30 * time.Second
	defaultInterval = 5 * time.Second
)

// TaskGroupDeployNamespaces is a flow.TaskID for a logical flow.TaskGroup.
const TaskGroupDeployNamespaces flow.TaskID = "TaskGroupDeployNamespaces"

// DeployNamespacesTaskGroup returns the flow.TaskGroup for deploying the control plane namespace and the garden
// namespace. The garden namespace is only deployed on machines that run the shoot's control plane, i.e., not during
// `gardenadm bootstrap`.
func (b *Botanist) DeployNamespacesTaskGroup() flow.TaskGroup {
	return flow.NewTaskGroup(TaskGroupDeployNamespaces,
		flow.Task{
			Name: "Deploying control plane namespace",
			Fn:   b.DeployControlPlaneNamespace,
		},
		flow.Task{
			Name: "Deploying garden namespace",
			Fn: func(ctx context.Context) error {
				return gardenerutils.ReconcileGardenNamespace(ctx, b.SeedClientSet.Client(), v1beta1constants.GardenNamespace, v1beta1helper.ControlPlaneWorkerPoolForShoot(b.Shoot.GetInfo().Spec.Provider.Workers).Zones, true, nil)
			},
			SkipIf: !b.Shoot.RunsControlPlane(),
		},
	)
}

// TaskGroupDeployCloudProviderSecret is a flow.TaskID for a logical flow.TaskGroup.
const TaskGroupDeployCloudProviderSecret flow.TaskID = "TaskGroupDeployCloudProviderSecret"

// DeployCloudProviderSecretTaskGroup returns the flow.TaskGroup for deploying the cloud provider secret. This task is
// skipped when no shoot credentials are configured.
func (b *Botanist) DeployCloudProviderSecretTaskGroup() flow.TaskGroup {
	return flow.NewTaskGroup(TaskGroupDeployCloudProviderSecret, flow.Task{
		Name:   "Deploying cloud provider account secret",
		Fn:     b.DeployCloudProviderSecret,
		SkipIf: b.Shoot.Credentials == nil || b.Shoot.IsWorkerless,
	}).WithDependencies(TaskGroupDeployNamespaces)
}

// TaskGroupReconcileCustomResourceDefinitions is a flow.TaskID for a logical flow.TaskGroup.
const TaskGroupReconcileCustomResourceDefinitions flow.TaskID = "TaskGroupReconcileCustomResourceDefinitions"

// ReconcileCustomResourceDefinitionsTaskGroup returns the flow.TaskGroup for reconciling the CRDs used by Gardener.
// Each CRD is deployed in an individual task, and it is waited until the CRDs are marked as ready/available.
func (b *Botanist) ReconcileCustomResourceDefinitionsTaskGroup() flow.TaskGroup {
	deployers := map[string]func() (component.DeployWaiter, error){
		"VPA": func() (component.DeployWaiter, error) {
			return vpa.NewCRD(b.SeedClientSet.Client(), nil)
		},
		"Prometheus": func() (component.DeployWaiter, error) {
			return prometheusoperator.NewCRDs(b.SeedClientSet.Client())
		},
		"Fluent": func() (component.DeployWaiter, error) {
			return fluentoperator.NewCRDs(b.SeedClientSet.Client())
		},
		"Extension": func() (component.DeployWaiter, error) {
			return extensioncrds.NewCRD(b.SeedClientSet.Client(), true, true)
		},
		"ETCD": func() (component.DeployWaiter, error) {
			return etcd.NewCRD(b.SeedClientSet.Client(), b.Shoot.KubernetesVersion)
		},
		"Istio": func() (component.DeployWaiter, error) {
			return istio.NewCRD(b.SeedClientSet.Client())
		},
	}

	if b.Shoot.HasManagedInfrastructure() {
		deployers["Machine"] = func() (component.DeployWaiter, error) {
			return machinecontrollermanager.NewCRD(b.SeedClientSet.Client())
		}
	}

	tasks := make([]flow.Task, 0, len(deployers))

	for description, newDeployer := range deployers {
		tasks = append(tasks, flow.Task{
			Name: fmt.Sprintf("Deploying %s CRDs", description),
			Fn: func(ctx context.Context) error {
				d, err := newDeployer()
				if err != nil {
					return fmt.Errorf("failed creating %s deployer: %w", description, err)
				}

				return component.OpWait(d).Deploy(ctx)
			},
		})
	}

	return flow.NewTaskGroup(TaskGroupReconcileCustomResourceDefinitions, tasks...).SkipIf(!b.Shoot.IsSelfHosted())
}

// TaskGroupReconcileClusterResource is a flow.TaskID for a logical flow.TaskGroup.
const TaskGroupReconcileClusterResource flow.TaskID = "TaskGroupReconcileClusterResource"

// ReconcileClusterResourceTaskGroup returns the flow.TaskGroup for reconciling the Cluster resource.
func (b *Botanist) ReconcileClusterResourceTaskGroup() flow.TaskGroup {
	return flow.NewTaskGroup(TaskGroupReconcileClusterResource, flow.Task{
		Name: "Reconciling extensions.gardener.cloud/v1alpha1.Cluster resource",
		Fn: func(ctx context.Context) error {
			return gardenerextensions.SyncClusterResourceToSeed(ctx, b.SeedClientSet.Client(), b.Shoot.ControlPlaneNamespace, b.Shoot.GetInfo(), b.Shoot.CloudProfile, nil)
		},
	}).WithDependencies(TaskGroupReconcileCustomResourceDefinitions).SkipIf(!b.Shoot.IsSelfHosted())
}

// TaskGroupReconcileReferencedResources is a flow.TaskID for a logical flow.TaskGroup.
const TaskGroupReconcileReferencedResources flow.TaskID = "TaskGroupReconcileReferencedResources"

// ReconcileReferencedResourcesTaskGroup returns the flow.TaskGroup for reconciling the resources referenced in the
// Shoot specification.
func (b *Botanist) ReconcileReferencedResourcesTaskGroup() flow.TaskGroup {
	return flow.NewTaskGroup(TaskGroupReconcileReferencedResources, flow.Task{
		Name: "Reconciling referenced resources",
		Fn:   flow.TaskFn(b.DeployReferencedResources).RetryUntilTimeout(defaultInterval, defaultTimeout),
	}).WithDependencies(TaskGroupDeployNamespaces, TaskGroupReconcileRuntimeGardenerResourceManager)
}

// TaskGroupInitializeSecretsManagement is a flow.TaskID for a logical flow.TaskGroup.
const TaskGroupInitializeSecretsManagement flow.TaskID = "TaskGroupInitializeSecretsManagement"

// InitializeSecretsManagementTaskGroup returns the flow.TaskGroup for initializing the secret management.
func (b *Botanist) InitializeSecretsManagementTaskGroup() flow.TaskGroup {
	return flow.NewTaskGroup(TaskGroupInitializeSecretsManagement, flow.Task{
		Name: "Initializing secrets management",
		Fn:   b.InitializeSecretsManagement,
	}).WithDependencies(TaskGroupReconcileClusterResource)
}

// TaskGroupReconcileRuntimeGardenerResourceManager is a flow.TaskID for a logical flow.TaskGroup.
const TaskGroupReconcileRuntimeGardenerResourceManager flow.TaskID = "TaskGroupReconcileRuntimeGardenerResourceManager"

// ReconcileRuntimeGardenerResourceManagerTaskGroup returns the flow.TaskGroup for deploying the runtime
// gardener-resource-manager instances.
func (b *Botanist) ReconcileRuntimeGardenerResourceManagerTaskGroup(podNetworkAvailable, shootIsGarden, skipReadiness bool) flow.TaskGroup {
	var (
		g = flow.NewTaskGroup(TaskGroupReconcileRuntimeGardenerResourceManager).
			SkipIf(!b.Shoot.IsSelfHosted() || shootIsGarden || b.isGardenadmBootstrap()).
			WithDependencies(
				TaskGroupDeployNamespaces,
				TaskGroupInitializeSecretsManagement,
				TaskGroupReconcileCustomResourceDefinitions,
			)

		deployGardenerResourceManager = g.Add(flow.Task{
			Name: "Deploying runtime gardener-resource-manager",
			Fn: func(ctx context.Context) error {
				if b.Shoot.IsSelfHosted() {
					b.Shoot.Components.ControlPlane.RuntimeResourceManager.SetBootstrapControlPlaneNode(!podNetworkAvailable)
				}
				return b.DeployRuntimeGardenerResourceManager(ctx)
			},
		})
		_ = g.Add(flow.Task{
			Name: "Waiting until runtime gardener-resource-manager reports readiness",
			Fn: func(ctx context.Context) error {
				return b.Shoot.Components.ControlPlane.RuntimeResourceManager.Wait(ctx)
			},
			SkipIf:       b.Shoot.HibernationEnabled || skipReadiness,
			Dependencies: flow.NewTaskIDs(deployGardenerResourceManager),
		})
	)

	return g
}

// TaskGroupReconcileIstio is a flow.TaskID for a logical flow.TaskGroup.
const TaskGroupReconcileIstio flow.TaskID = "TaskGroupReconcileIstio"

// ReconcileIstioTaskGroup returns the flow.TaskGroup for deploying the Istio installation (istiod + ingress gateway)
// inside a self-hosted shoot.
func (b *Botanist) ReconcileIstioTaskGroup(skipReadiness bool) flow.TaskGroup {
	var (
		g = flow.NewTaskGroup(TaskGroupReconcileIstio).
			SkipIf(!b.Shoot.IsSelfHosted() || (!b.IsShootMonitoringEnabled() && !b.IsShootLoggingEnabled())).
			WithDependencies(
				TaskGroupReconcileCustomResourceDefinitions,
				TaskGroupReconcileRuntimeGardenerResourceManager,
			)

		deployIstio = g.Add(flow.Task{
			Name: "Deploying Istio",
			Fn:   b.DeployIstio,
		})
		_ = g.Add(flow.Task{
			Name: "Waiting until Istio is ready",
			Fn: func(ctx context.Context) error {
				return b.Shoot.Components.ControlPlane.Istio.Wait(ctx)
			},
			SkipIf:       skipReadiness,
			Dependencies: flow.NewTaskIDs(deployIstio),
		})
	)

	return g
}

// TaskGroupReconcileGardenerResourceManager is a flow.TaskID for a logical flow.TaskGroup.
const TaskGroupReconcileGardenerResourceManager flow.TaskID = "TaskGroupReconcileGardenerResourceManager"

// ReconcileGardenerResourceManagerTaskGroup returns the flow.TaskGroup for deploying the gardener-resource-manager
// instances.
func (b *Botanist) ReconcileGardenerResourceManagerTaskGroup(podNetworkAvailable, skipReadiness bool) flow.TaskGroup {
	var (
		g = flow.NewTaskGroup(TaskGroupReconcileGardenerResourceManager).
			WithDependencies(
				TaskGroupDeployNamespaces,
				TaskGroupInitializeSecretsManagement,
				TaskGroupReconcileCustomResourceDefinitions,
				TaskGroupReconcileRuntimeGardenerResourceManager,
			)

		deployGardenerResourceManager = g.Add(flow.Task{
			Name: "Deploying gardener-resource-manager",
			Fn: func(ctx context.Context) error {
				if b.Shoot.IsSelfHosted() {
					b.Shoot.Components.ControlPlane.ResourceManager.SetBootstrapControlPlaneNode(!podNetworkAvailable)
				}
				return b.DeployGardenerResourceManager(ctx)
			},
		})
		_ = g.Add(flow.Task{
			Name: "Waiting until gardener-resource-manager reports readiness",
			Fn: func(ctx context.Context) error {
				return b.Shoot.Components.ControlPlane.ResourceManager.Wait(ctx)
			},
			SkipIf:       b.Shoot.HibernationEnabled || skipReadiness,
			Dependencies: flow.NewTaskIDs(deployGardenerResourceManager),
		})
	)

	return g
}

// TaskGroupReconcileSystemResources is a flow.TaskID for a logical flow.TaskGroup.
const TaskGroupReconcileSystemResources flow.TaskID = "TaskGroupReconcileSystemResources"

// ReconcileSystemResourcesTaskGroup returns the flow.TaskGroup for deploying the system resources.
func (b *Botanist) ReconcileSystemResourcesTaskGroup() flow.TaskGroup {
	var (
		g = flow.NewTaskGroup(TaskGroupReconcileSystemResources).
			WithDependencies(
				TaskGroupReconcileGardenerResourceManager,
				TaskGroupReconcileReferencedResources,
			)

		_ = g.Add(flow.Task{
			Name: "Deploying seed system resources",
			Fn: func(ctx context.Context) error {
				return seedsystem.New(b.SeedClientSet.Client(), b.Shoot.ControlPlaneNamespace, seedsystem.Values{ManagePriorityClasses: true}).Deploy(ctx)
			},
			SkipIf: !b.Shoot.IsSelfHosted(),
		})
		_ = g.Add(flow.Task{
			Name:   "Deploying shoot system resources",
			Fn:     b.DeployShootSystem,
			SkipIf: b.isGardenadmBootstrap() || b.Shoot.HibernationEnabled,
		})
	)

	return g
}

// TaskGroupReconcileMachineControllerManager is a flow.TaskID for a logical flow.TaskGroup.
const TaskGroupReconcileMachineControllerManager flow.TaskID = "TaskGroupReconcileMachineControllerManager"

// ReconcileMachineControllerManagerTaskGroup returns the flow.TaskGroup for deploying the machine-controller-manager.
func (b *Botanist) ReconcileMachineControllerManagerTaskGroup() flow.TaskGroup {
	return flow.
		NewTaskGroup(TaskGroupReconcileMachineControllerManager, flow.Task{
			Name:   "Deploying machine-controller-manager",
			Fn:     flow.TaskFn(b.DeployMachineControllerManager).RetryUntilTimeout(time.Second, time.Minute),
			SkipIf: !b.Shoot.HasManagedInfrastructure() || b.Shoot.IsWorkerless,
		}).
		WithDependencies(
			TaskGroupInitializeSecretsManagement,
			TaskGroupDeployCloudProviderSecret,
			TaskGroupReconcileGardenerResourceManager,
		).
		WithDependenciesIf(b.isGardenlet(),
			TaskGroupReconcileInfrastructure,
			TaskGroupReconcileOperatingSystemConfig,
			TaskGroupReconcileStaticPods,
		)
}

// TaskGroupReconcileBackupResources is a flow.TaskID for a logical flow.TaskGroup.
const TaskGroupReconcileBackupResources flow.TaskID = "TaskGroupReconcileBackupResources"

// ReconcileBackupResourcesTaskGroup returns the flow.TaskGroup for deploying the BackupBucket or BackupEntry extension
// resources and waiting for their readiness.
func (b *Botanist) ReconcileBackupResourcesTaskGroup(allowBackup, isCopyOfBackupsRequired, skipReadiness bool) flow.TaskGroup {
	var (
		g = flow.NewTaskGroup(TaskGroupReconcileBackupResources).
			WithDependencies(
				TaskGroupDeployNamespaces,
				TaskGroupReconcileReferencedResources,
			)

		deploySourceBackupEntry = g.Add(flow.Task{
			Name:   "Deploying source backup entry",
			Fn:     b.DeploySourceBackupEntry,
			SkipIf: !isCopyOfBackupsRequired || b.Shoot.IsSelfHosted(),
		})
		waitUntilSourceBackupEntryInGardenReconciled = g.Add(flow.Task{
			Name:         "Waiting until the source backup entry has been reconciled",
			Fn:           b.Shoot.Components.SourceBackupEntry.Wait,
			SkipIf:       skipReadiness || !isCopyOfBackupsRequired || b.Shoot.IsSelfHosted(),
			Dependencies: flow.NewTaskIDs(deploySourceBackupEntry),
		})

		deployBackupBucketInGarden = g.Add(flow.Task{
			Name: "Deploying BackupBucket for ETCD data",
			Fn: func(ctx context.Context) error {
				return b.Shoot.Components.BackupBucket.Deploy(ctx)
			},
			SkipIf: !allowBackup || !b.Shoot.IsSelfHosted(),
		})
		waitUntilBackupBucketInGardenReconciled = g.Add(flow.Task{
			Name: "Waiting until the BackupBucket for ETCD data has been reconciled",
			Fn: func(ctx context.Context) error {
				return b.Shoot.Components.BackupBucket.Wait(ctx)
			},
			SkipIf:       skipReadiness || !allowBackup || !b.Shoot.IsSelfHosted(),
			Dependencies: flow.NewTaskIDs(deployBackupBucketInGarden),
		})

		deployBackupEntryInGarden = g.Add(flow.Task{
			Name:         "Deploying BackupEntry for ETCD data",
			Fn:           b.DeployBackupEntry,
			SkipIf:       !allowBackup,
			Dependencies: flow.NewTaskIDs(waitUntilSourceBackupEntryInGardenReconciled, waitUntilBackupBucketInGardenReconciled),
		})
		waitUntilBackupEntryInGardenReconciled = g.Add(flow.Task{
			Name:         "Waiting until the BackupEntry for ETCD data has been reconciled",
			Fn:           b.Shoot.Components.BackupEntry.Wait,
			SkipIf:       skipReadiness || !allowBackup,
			Dependencies: flow.NewTaskIDs(deployBackupEntryInGarden),
		})

		copyEtcdBackups = g.Add(flow.Task{
			Name:         "Copying etcd backups to new seed's backup bucket",
			Fn:           b.DeployEtcdCopyBackupsTask,
			SkipIf:       !isCopyOfBackupsRequired,
			Dependencies: flow.NewTaskIDs(waitUntilBackupEntryInGardenReconciled, waitUntilSourceBackupEntryInGardenReconciled),
		})
		waitUntilEtcdBackupsCopied = g.Add(flow.Task{
			Name:         "Waiting until etcd backups are copied",
			Fn:           b.Shoot.Components.ControlPlane.EtcdCopyBackupsTask.Wait,
			SkipIf:       skipReadiness || !isCopyOfBackupsRequired,
			Dependencies: flow.NewTaskIDs(copyEtcdBackups),
		})
		_ = g.Add(flow.Task{
			Name:         "Destroying copy etcd backups task resource",
			Fn:           b.Shoot.Components.ControlPlane.EtcdCopyBackupsTask.Destroy,
			SkipIf:       !isCopyOfBackupsRequired,
			Dependencies: flow.NewTaskIDs(waitUntilEtcdBackupsCopied),
		})
	)

	return g
}

// TaskGroupReconcileInfrastructure is a flow.TaskID for a logical flow.TaskGroup.
const TaskGroupReconcileInfrastructure flow.TaskID = "TaskGroupReconcileInfrastructure"

// ReconcileInfrastructureTaskGroup returns the flow.TaskGroup for deploying the Infrastructure extension resource and
// waiting for its readiness.
func (b *Botanist) ReconcileInfrastructureTaskGroup(skipReadiness bool) flow.TaskGroup {
	var (
		g = flow.NewTaskGroup(TaskGroupReconcileInfrastructure).
			WithDependencies(
				TaskGroupInitializeSecretsManagement,
				TaskGroupDeployCloudProviderSecret,
				TaskGroupReconcileReferencedResources,
			)

		deployInfrastructure = g.Add(flow.Task{
			Name:   "Deploying Shoot infrastructure",
			Fn:     b.DeployInfrastructure,
			SkipIf: !b.Shoot.HasManagedInfrastructure() || b.Shoot.IsWorkerless,
		})
		_ = g.Add(flow.Task{
			Name: "Waiting until Shoot infrastructure has been reconciled",
			Fn: func(ctx context.Context) error {
				if !skipReadiness {
					if err := b.WaitForInfrastructure(ctx); err != nil {
						return err
					}
				}
				return b.RemoveTaskAnnotation(ctx, v1beta1constants.ShootTaskDeployInfrastructure)
			},
			SkipIf:       !b.Shoot.HasManagedInfrastructure() || b.Shoot.IsWorkerless,
			Dependencies: flow.NewTaskIDs(deployInfrastructure),
		})
	)

	return g
}

// TaskGroupReconcileControlPlane is a flow.TaskID for a logical flow.TaskGroup.
const TaskGroupReconcileControlPlane flow.TaskID = "TaskGroupReconcileControlPlane"

// ReconcileControlPlaneTaskGroup returns the flow.TaskGroup for deploying the ControlPlane extension resource and
// waiting for its readiness.
func (b *Botanist) ReconcileControlPlaneTaskGroup(skipReadiness bool) flow.TaskGroup {
	var (
		g = flow.NewTaskGroup(TaskGroupReconcileControlPlane).
			WithDependencies(
				TaskGroupInitializeSecretsManagement,
				TaskGroupDeployCloudProviderSecret,
				TaskGroupReconcileGardenerResourceManager,
				TaskGroupReconcileInfrastructure,
				TaskGroupReconcileReferencedResources,
			).
			WithDependenciesIf(b.isGardenlet(),
				TaskGroupReconcileStaticPods,
			)

		deployControlPlane = g.Add(flow.Task{
			Name:   "Deploying shoot control plane components",
			Fn:     b.DeployControlPlane,
			SkipIf: b.Shoot.IsWorkerless,
		})
		_ = g.Add(flow.Task{
			Name: "Waiting until shoot control plane has been reconciled",
			Fn: func(ctx context.Context) error {
				return b.Shoot.Components.Extensions.ControlPlane.Wait(ctx)
			},
			SkipIf:       b.Shoot.IsWorkerless || skipReadiness,
			Dependencies: flow.NewTaskIDs(deployControlPlane),
		})
	)

	return g
}

// TaskGroupReconcileDNSRecords is a flow.TaskID for a logical flow.TaskGroup.
const TaskGroupReconcileDNSRecords flow.TaskID = "TaskGroupReconcileDNSRecords"

// ReconcileDNSRecordsTaskGroup returns the flow.TaskGroup for deploying the DNSRecords extension resources
// and waiting for their readiness.
func (b *Botanist) ReconcileDNSRecordsTaskGroup() flow.TaskGroup {
	var (
		g = flow.NewTaskGroup(TaskGroupReconcileDNSRecords).
			SkipIf(b.Shoot.HibernationEnabled || b.Shoot.IsSelfHosted()).
			WithDependencies(
				TaskGroupReconcileReferencedResources,
			)

		_ = g.Add(flow.Task{
			Name: "Deploying internal domain DNS record",
			Fn: func(ctx context.Context) error {
				if err := b.DeployOrDestroyInternalDNSRecord(ctx); err != nil {
					return err
				}
				return b.RemoveTaskAnnotation(ctx, v1beta1constants.ShootTaskDeployDNSRecordInternal)
			},
		})
		_ = g.Add(flow.Task{
			Name: "Deploying external domain DNS record",
			Fn: func(ctx context.Context) error {
				if err := b.DeployOrDestroyExternalDNSRecord(ctx); err != nil {
					return err
				}
				return b.RemoveTaskAnnotation(ctx, v1beta1constants.ShootTaskDeployDNSRecordExternal)
			},
		})
	)

	return g
}

// TaskGroupReconcileExtensionsBeforeKubeAPIServer is a flow.TaskID for a logical flow.TaskGroup.
const TaskGroupReconcileExtensionsBeforeKubeAPIServer flow.TaskID = "TaskGroupReconcileExtensionsBeforeKubeAPIServer"

// ReconcileExtensionsBeforeKubeAPIServerTaskGroup returns the flow.TaskGroup for deploying the Extensions resources
// before kube-apiserver and waiting for their readiness.
func (b *Botanist) ReconcileExtensionsBeforeKubeAPIServerTaskGroup(skipReadiness bool) flow.TaskGroup {
	var (
		g = flow.NewTaskGroup(TaskGroupReconcileExtensionsBeforeKubeAPIServer).
			SkipIf(b.Shoot.HibernationEnabled).
			WithDependencies(
				TaskGroupDeployCloudProviderSecret,
				TaskGroupInitializeSecretsManagement,
				TaskGroupReconcileReferencedResources,
				TaskGroupReconcileInfrastructure,
			)

		deployExtensionResources = g.Add(flow.Task{
			Name: "Deploying extension resources before kube-apiserver",
			Fn:   flow.TaskFn(b.DeployExtensionsBeforeKubeAPIServer).RetryUntilTimeout(defaultInterval, defaultTimeout),
		})
		_ = g.Add(flow.Task{
			Name:         "Waiting until extension resources handled before kube-apiserver are ready",
			Fn:           b.Shoot.Components.Extensions.Extension.WaitBeforeKubeAPIServer,
			SkipIf:       skipReadiness,
			Dependencies: flow.NewTaskIDs(deployExtensionResources),
		})
	)

	return g
}

// TaskGroupReconcileKubeAPIServer is a flow.TaskID for a logical flow.TaskGroup.
const TaskGroupReconcileKubeAPIServer flow.TaskID = "TaskGroupReconcileKubeAPIServer"

// ReconcileKubeAPIServerTaskGroup returns the flow.TaskGroup that deploys the kube-apiserver and waits for its
// readiness, then deploys the SNI resources and cleans up stale load balancing services. The kube-apiserver Service
// is intentionally not part of this group: its readiness is a dependency of other interleaved tasks (advertised
// addresses, DNS records), so callers deploy it separately and wire it in via WithDependencies. deployTimeout is the
// timeout for the kube-apiserver deployment (callers may raise it, e.g. kubeapiserver.TimeoutWaitForDeployment).
//
// The SNI resources must be deployed before any component that uses the generic token kubeconfig (e.g.
// gardener-resource-manager, kube-controller-manager): with Istio TLS termination the generic kubeconfig targets the
// external api.<domain> address and the pod-kube-apiserver-load-balancing webhook only injects the host alias
// redirecting it to the local istio-ingressgateway if the SNI ConfigMap exists. Downstream groups therefore depend
// on this whole group, not just on the kube-apiserver readiness.
func (b *Botanist) ReconcileKubeAPIServerTaskGroup(skipReadiness bool, deployTimeout time.Duration) flow.TaskGroup {
	var (
		g = flow.NewTaskGroup(TaskGroupReconcileKubeAPIServer)

		deployKubeAPIServer = g.Add(flow.Task{
			Name: "Deploying Kubernetes API server",
			Fn: flow.TaskFn(func(ctx context.Context) error {
				return b.DeployKubeAPIServer(ctx)
			}).RetryUntilTimeout(defaultInterval, deployTimeout),
			SkipIf: b.Shoot.IsSelfHosted(),
		})
		waitUntilKubeAPIServerIsReady = g.Add(flow.Task{
			Name:         "Waiting until Kubernetes API server rolled out",
			Fn:           b.Shoot.Components.ControlPlane.KubeAPIServer.Wait,
			SkipIf:       b.Shoot.HibernationEnabled || skipReadiness || b.Shoot.IsSelfHosted(),
			Dependencies: flow.NewTaskIDs(deployKubeAPIServer),
		})
		deployKubeAPIServerServiceSNISettings = g.Add(flow.Task{
			Name:         "Deploying and waiting for Kubernetes API server service SNI settings in the Seed cluster",
			Fn:           flow.TaskFn(b.DeployKubeAPIServerSNI).RetryUntilTimeout(defaultInterval, defaultTimeout),
			SkipIf:       b.Shoot.IsSelfHosted(),
			Dependencies: flow.NewTaskIDs(waitUntilKubeAPIServerIsReady),
		})
		_ = g.Add(flow.Task{
			Name:         "Cleaning up stale Kubernetes API server services in the Seed cluster",
			Fn:           flow.TaskFn(b.CleanupKubeAPIServerLoadBalancingServices).RetryUntilTimeout(defaultInterval, defaultTimeout),
			SkipIf:       b.ShootUsesIstioTLSTermination(),
			Dependencies: flow.NewTaskIDs(deployKubeAPIServerServiceSNISettings),
		})
	)

	return g
}

// TaskGroupReconcileExtensionsAfterKubeAPIServer is a flow.TaskID for a logical flow.TaskGroup.
const TaskGroupReconcileExtensionsAfterKubeAPIServer flow.TaskID = "TaskGroupReconcileExtensionsAfterKubeAPIServer"

// ReconcileExtensionsAfterKubeAPIServerTaskGroup returns the flow.TaskGroup for deploying the Extensions resources
// after kube-apiserver and waiting for their readiness.
func (b *Botanist) ReconcileExtensionsAfterKubeAPIServerTaskGroup(skipReadiness bool) flow.TaskGroup {
	var (
		deployExtensionAfterKAPIMsg = "Deploying extension resources after kube-apiserver"
		waitExtensionAfterKAPIMsg   = "Waiting until extension resources handled after kube-apiserver are ready"
	)
	if b.Shoot.HibernationEnabled {
		deployExtensionAfterKAPIMsg = "Hibernating extension resources before kube-apiserver hibernation"
		waitExtensionAfterKAPIMsg = "Waiting until extension resources hibernated before kube-apiserver hibernation are ready"
	}

	var (
		g = flow.NewTaskGroup(TaskGroupReconcileExtensionsAfterKubeAPIServer).
			WithDependencies(
				TaskGroupDeployCloudProviderSecret,
				TaskGroupInitializeSecretsManagement,
				TaskGroupReconcileReferencedResources,
				TaskGroupReconcileInfrastructure,
			).
			WithDependenciesIf(b.Shoot.IsSelfHosted(),
				TaskGroupReconcileStaticPods,
			)

		deployExtensionResources = g.Add(flow.Task{
			Name: deployExtensionAfterKAPIMsg,
			Fn:   flow.TaskFn(b.DeployExtensionsAfterKubeAPIServer).RetryUntilTimeout(defaultInterval, defaultTimeout),
		})
		_ = g.Add(flow.Task{
			Name:         waitExtensionAfterKAPIMsg,
			Fn:           b.Shoot.Components.Extensions.Extension.WaitAfterKubeAPIServer,
			SkipIf:       skipReadiness,
			Dependencies: flow.NewTaskIDs(deployExtensionResources),
		})
		deleteStaleExtensionResources = g.Add(flow.Task{
			Name: "Deleting stale extension resources",
			Fn:   flow.TaskFn(b.Shoot.Components.Extensions.Extension.DeleteStaleResources).RetryUntilTimeout(defaultInterval, defaultTimeout),
		})
		_ = g.Add(flow.Task{
			Name:         "Waiting until stale extension resources are deleted",
			Fn:           b.Shoot.Components.Extensions.Extension.WaitCleanupStaleResources,
			SkipIf:       b.Shoot.HibernationEnabled || skipReadiness,
			Dependencies: flow.NewTaskIDs(deleteStaleExtensionResources),
		})
	)

	return g
}

// TaskGroupReconcileExtensionsAfterWorker is a flow.TaskID for a logical flow.TaskGroup.
const TaskGroupReconcileExtensionsAfterWorker flow.TaskID = "TaskGroupReconcileExtensionsAfterWorker"

// ReconcileExtensionsAfterWorkerTaskGroup returns the flow.TaskGroup for deploying the Extensions resources
// after the Worker resource and waiting for their readiness.
func (b *Botanist) ReconcileExtensionsAfterWorkerTaskGroup(skipReadiness bool) flow.TaskGroup {
	var (
		g = flow.NewTaskGroup(TaskGroupReconcileExtensionsAfterWorker).
			SkipIf(b.Shoot.IsWorkerless).
			WithDependencies(
				TaskGroupDeployCloudProviderSecret,
				TaskGroupInitializeSecretsManagement,
				TaskGroupReconcileReferencedResources,
				TaskGroupReconcileWorker,
			)

		deployExtensionResources = g.Add(flow.Task{
			Name: "Deploying extension resources after workers",
			Fn:   b.DeployExtensionsAfterWorker,
		})
		_ = g.Add(flow.Task{
			Name:         "Waiting until extension resources handled after workers are ready",
			Fn:           b.Shoot.Components.Extensions.Extension.WaitAfterWorker,
			SkipIf:       skipReadiness,
			Dependencies: flow.NewTaskIDs(deployExtensionResources),
		})
	)

	return g
}

// TaskGroupReconcileContainerRuntime is a flow.TaskID for a logical flow.TaskGroup.
const TaskGroupReconcileContainerRuntime flow.TaskID = "TaskGroupReconcileContainerRuntime"

// ReconcileContainerRuntimeTaskGroup returns the flow.TaskGroup for deploying the ContainerRuntime extension resource
// and waiting for its readiness.
func (b *Botanist) ReconcileContainerRuntimeTaskGroup(skipReadiness bool) flow.TaskGroup {
	var (
		g = flow.NewTaskGroup(TaskGroupReconcileContainerRuntime).
			SkipIf(b.Shoot.IsWorkerless).
			WithDependencies(
				TaskGroupInitializeSecretsManagement,
				TaskGroupReconcileReferencedResources,
				TaskGroupReconcileGardenerResourceManager,
			)

		deployContainerRuntimeResources = g.Add(flow.Task{
			Name: "Deploying container runtime resources",
			Fn:   flow.TaskFn(b.DeployContainerRuntime).RetryUntilTimeout(defaultInterval, defaultTimeout),
		})
		_ = g.Add(flow.Task{
			Name: "Waiting until container runtime resources are ready",
			Fn: func(ctx context.Context) error {
				return b.Shoot.Components.Extensions.ContainerRuntime.Wait(ctx)
			},
			SkipIf:       skipReadiness,
			Dependencies: flow.NewTaskIDs(deployContainerRuntimeResources),
		})
		deleteStaleContainerRuntimeResources = g.Add(flow.Task{
			Name: "Deleting stale container runtime resources",
			Fn: flow.TaskFn(func(ctx context.Context) error {
				return b.Shoot.Components.Extensions.ContainerRuntime.DeleteStaleResources(ctx)
			}).RetryUntilTimeout(defaultInterval, defaultTimeout),
		})
		_ = g.Add(flow.Task{
			Name: "Waiting until stale container runtime resources are deleted",
			Fn: func(ctx context.Context) error {
				return b.Shoot.Components.Extensions.ContainerRuntime.WaitCleanupStaleResources(ctx)
			},
			SkipIf:       b.Shoot.HibernationEnabled || skipReadiness,
			Dependencies: flow.NewTaskIDs(deleteStaleContainerRuntimeResources),
		})
	)

	return g
}

// TaskGroupReconcileOperatingSystemConfig is a flow.TaskID for a logical flow.TaskGroup.
const TaskGroupReconcileOperatingSystemConfig flow.TaskID = "TaskGroupReconcileOperatingSystemConfig"

// ReconcileOperatingSystemConfigTaskGroup returns the flow.TaskGroup for deploying the OperatingSystemConfig extension
// resource and waiting for its readiness.
func (b *Botanist) ReconcileOperatingSystemConfigTaskGroup(skipReadiness bool) flow.TaskGroup {
	var (
		g = flow.
			NewTaskGroup(TaskGroupReconcileOperatingSystemConfig).
			SkipIf(b.Shoot.IsSelfHosted() && !b.isGardenadmBootstrap()).
			WithDependencies(
				TaskGroupInitializeSecretsManagement,
				TaskGroupDeployCloudProviderSecret,
				TaskGroupReconcileGardenerResourceManager,
				TaskGroupReconcileReferencedResources,
			).
			WithDependenciesIf(b.isGardenlet(),
				TaskGroupReconcileInfrastructure,
				TaskGroupReconcileControlPlane,
				TaskGroupReconcileExtensionsAfterKubeAPIServer,
			)

		deployOperatingSystemConfig = g.Add(flow.Task{
			Name: "Deploying OperatingSystemConfig resources for worker pools",
			Fn: func(ctx context.Context) error {
				if b.isGardenadmBootstrap() {
					return b.Shoot.Components.Extensions.OperatingSystemConfig.Deploy(ctx)
				}
				return b.DeployOperatingSystemConfig(ctx)
			},
			SkipIf: b.Shoot.IsWorkerless,
		})
		_ = g.Add(flow.Task{
			Name: "Waiting until OperatingSystemConfig for worker pools have been reconciled",
			Fn: func(ctx context.Context) error {
				return b.Shoot.Components.Extensions.OperatingSystemConfig.Wait(ctx)
			},
			SkipIf:       b.Shoot.IsWorkerless,
			Dependencies: flow.NewTaskIDs(deployOperatingSystemConfig),
		})
		deleteStaleOperatingSystemConfigResources = g.Add(flow.Task{
			Name: "Delete stale OperatingSystemConfig resources",
			Fn: func(ctx context.Context) error {
				return b.Shoot.Components.Extensions.OperatingSystemConfig.DeleteStaleResources(ctx)
			},
			SkipIf:       b.Shoot.IsWorkerless || b.isGardenadmBootstrap(),
			Dependencies: flow.NewTaskIDs(deployOperatingSystemConfig),
		})
		_ = g.Add(flow.Task{
			Name: "Waiting until stale OperatingSystemConfig resources are deleted",
			Fn: func(ctx context.Context) error {
				return b.Shoot.Components.Extensions.OperatingSystemConfig.WaitCleanupStaleResources(ctx)
			},
			SkipIf:       b.Shoot.IsWorkerless || b.Shoot.HibernationEnabled || skipReadiness || b.isGardenadmBootstrap(),
			Dependencies: flow.NewTaskIDs(deleteStaleOperatingSystemConfigResources),
		})
	)

	return g
}

// TaskGroupReconcileWorker is a flow.TaskID for a logical flow.TaskGroup.
const TaskGroupReconcileWorker flow.TaskID = "TaskGroupReconcileWorker"

// ReconcileWorkerTaskGroup returns the flow.TaskGroup for deploying the Worker extension resource. It waits until its
// status was updated with the latest machine deployments, deploys cluster-autoscaler and finally waits for the pools
// to get reconciled.
func (b *Botanist) ReconcileWorkerTaskGroup(skipReadiness bool) flow.TaskGroup {
	var (
		g = flow.NewTaskGroup(TaskGroupReconcileWorker).
			SkipIf(b.Shoot.IsWorkerless || !b.Shoot.HasManagedInfrastructure()).
			WithDependencies(
				TaskGroupInitializeSecretsManagement,
				TaskGroupDeployCloudProviderSecret,
				TaskGroupReconcileGardenerResourceManager,
				TaskGroupReconcileInfrastructure,
				TaskGroupReconcileMachineControllerManager,
				TaskGroupReconcileSystemResources,
			).
			WithDependenciesIf(b.isGardenlet(),
				TaskGroupReconcileOperatingSystemConfig,
			)

		shootHasPendingInPlaceUpdateWorkers = func(shoot *gardencorev1beta1.Shoot) bool {
			return shoot.Status.InPlaceUpdates != nil && shoot.Status.InPlaceUpdates.PendingWorkerUpdates != nil &&
				(len(shoot.Status.InPlaceUpdates.PendingWorkerUpdates.AutoInPlaceUpdate) > 0 || len(shoot.Status.InPlaceUpdates.PendingWorkerUpdates.ManualInPlaceUpdate) > 0)
		}

		deployWorker = g.Add(flow.Task{
			Name: "Configuring worker pools",
			Fn:   b.DeployWorker,
		})
		waitUntilWorkerStatusUpdate = g.Add(flow.Task{
			Name: "Waiting until worker resource status is updated with latest machine deployments",
			Fn: func(ctx context.Context) error {
				return b.Shoot.Components.Extensions.Worker.WaitUntilWorkerStatusMachineDeploymentsUpdated(ctx)
			},
			SkipIf:       b.Shoot.HibernationEnabled,
			Dependencies: flow.NewTaskIDs(deployWorker),
		})
		_ = g.Add(flow.Task{
			Name:         "Deploying cluster-autoscaler",
			Fn:           b.DeployClusterAutoscaler,
			SkipIf:       b.isGardenadmBootstrap() || b.Shoot.HibernationEnabled,
			Dependencies: flow.NewTaskIDs(waitUntilWorkerStatusUpdate),
		})
		_ = g.Add(flow.Task{
			Name: "Waiting until worker pools have been reconciled",
			Fn: func(ctx context.Context) error {
				if err := b.Shoot.Components.Extensions.Worker.Wait(ctx); err != nil {
					return err
				}

				// If the worker is ready, all the AutoInPlaceUpdate worker pools should be updated already, so we can remove them from the status.
				if shootHasPendingInPlaceUpdateWorkers(b.Shoot.GetInfo()) {
					// gardenlet's shoot status reconciler might concurrently update the status, so we need to use optimistic locking.
					if err := b.Shoot.UpdateInfoStatus(ctx, b.GardenClient, false, true, func(shoot *gardencorev1beta1.Shoot) error {
						shoot.Status.InPlaceUpdates.PendingWorkerUpdates.AutoInPlaceUpdate = nil

						if len(shoot.Status.InPlaceUpdates.PendingWorkerUpdates.ManualInPlaceUpdate) == 0 {
							shoot.Status.InPlaceUpdates.PendingWorkerUpdates = nil
						}

						if shoot.Status.InPlaceUpdates.PendingWorkerUpdates == nil {
							shoot.Status.InPlaceUpdates = nil
						}

						return nil
					}); err != nil {
						return fmt.Errorf("failed to remove pending AutoInPlaceUpdate worker pools from status: %w", err)
					}
				}

				// If there are no pending workers rollouts for in-place updates, we can remove the force in-place update annotation.
				if (b.Shoot.GetInfo().Status.InPlaceUpdates == nil || b.Shoot.GetInfo().Status.InPlaceUpdates.PendingWorkerUpdates == nil) &&
					kubernetesutils.HasMetaDataAnnotation(b.Shoot.GetInfo(), v1beta1constants.GardenerOperation, v1beta1constants.ShootOperationForceInPlaceUpdate) {
					return b.Shoot.UpdateInfo(ctx, b.GardenClient, false, func(shoot *gardencorev1beta1.Shoot) error {
						delete(shoot.Annotations, v1beta1constants.GardenerOperation)
						return nil
					})
				}

				return nil
			},
			SkipIf:       skipReadiness,
			Dependencies: flow.NewTaskIDs(waitUntilWorkerStatusUpdate),
		})
	)

	return g
}

// TaskGroupReconcileShootNamespaces is a flow.TaskID for a logical flow.TaskGroup.
const TaskGroupReconcileShootNamespaces flow.TaskID = "TaskGroupReconcileShootNamespaces"

// ReconcileShootNamespacesTaskGroup returns the flow.TaskGroup for deploying the shoot namespaces and waiting for their
// readiness.
func (b *Botanist) ReconcileShootNamespacesTaskGroup(skipReadiness bool) flow.TaskGroup {
	var (
		g = flow.NewTaskGroup(TaskGroupReconcileShootNamespaces).
			SkipIf(b.Shoot.IsSelfHosted()).
			WithDependencies(
				TaskGroupReconcileGardenerResourceManager,
			)

		deployShootNamespaces = g.Add(flow.Task{
			Name: "Deploying shoot namespaces system component",
			Fn:   b.Shoot.Components.SystemComponents.Namespaces.Deploy,
		})
		_ = g.Add(flow.Task{
			Name:         "Waiting until shoot namespaces have been reconciled",
			Fn:           b.Shoot.Components.SystemComponents.Namespaces.Wait,
			SkipIf:       b.Shoot.HibernationEnabled || skipReadiness,
			Dependencies: flow.NewTaskIDs(deployShootNamespaces),
		})
	)

	return g
}

// TaskGroupReconcileSystemComponents is a flow.TaskID for a logical flow.TaskGroup.
const TaskGroupReconcileSystemComponents flow.TaskID = "TaskGroupReconcileSystemComponents"

// ReconcileSystemComponentsTaskGroup returns the flow.TaskGroup for reconciling shoot system components.
func (b *Botanist) ReconcileSystemComponentsTaskGroup(kubeProxyEnabled, skipReadiness bool) flow.TaskGroup {
	var (
		g = flow.NewTaskGroup(TaskGroupReconcileSystemComponents).
			WithDependencies(
				TaskGroupReconcileInfrastructure,
				TaskGroupReconcileGardenerResourceManager,
				TaskGroupReconcileShootNamespaces,
			).
			WithDependenciesIf(b.isGardenlet(),
				TaskGroupReconcileControlPlane,
				TaskGroupReconcileExtensionsAfterKubeAPIServer, // Extensions might deploy webhooks for system components
			)

		deployNetwork = g.Add(flow.Task{
			Name:   "Deploying shoot network plugin",
			Fn:     b.DeployNetwork,
			SkipIf: b.Shoot.IsWorkerless,
		})
		waitUntilNetworkReady = g.Add(flow.Task{
			Name: "Waiting until shoot network plugin has been reconciled",
			Fn: func(ctx context.Context) error {
				return b.Shoot.Components.Extensions.Network.Wait(ctx)
			},
			SkipIf:       b.Shoot.IsWorkerless || skipReadiness,
			Dependencies: flow.NewTaskIDs(deployNetwork),
		})

		deployKubeProxy = g.Add(flow.Task{
			Name:   "Deploying kube-proxy system component",
			Fn:     b.DeployKubeProxy,
			SkipIf: b.Shoot.IsWorkerless || b.Shoot.HibernationEnabled || !kubeProxyEnabled,
		})
		_ = g.Add(flow.Task{
			Name: "Deleting stale kube-proxy DaemonSets",
			Fn: func(ctx context.Context) error {
				return b.Shoot.Components.SystemComponents.KubeProxy.DeleteStaleResources(ctx)
			},
			SkipIf:       b.Shoot.IsWorkerless || b.Shoot.HibernationEnabled || !kubeProxyEnabled,
			Dependencies: flow.NewTaskIDs(deployKubeProxy),
		})
		_ = g.Add(flow.Task{
			Name: "Deleting kube-proxy system component",
			Fn: func(ctx context.Context) error {
				return b.Shoot.Components.SystemComponents.KubeProxy.Destroy(ctx)
			},
			SkipIf: b.Shoot.IsWorkerless || b.Shoot.HibernationEnabled || kubeProxyEnabled,
		})

		_ = g.Add(flow.Task{
			Name:         "Check CoreDNS migration status",
			Fn:           b.CheckDNSServiceMigration,
			SkipIf:       b.Shoot.IsWorkerless || b.Shoot.HibernationEnabled,
			Dependencies: flow.NewTaskIDs(waitUntilNetworkReady),
		})
		deployCoreDNS = g.Add(flow.Task{
			Name: "Deploying CoreDNS system component",
			Fn: func(ctx context.Context) error {
				if err := b.DeployCoreDNS(ctx); err != nil {
					return err
				}
				if controllerutils.HasTask(b.Shoot.GetInfo().Annotations, v1beta1constants.ShootTaskRestartCoreAddons) {
					return b.RemoveTaskAnnotation(ctx, v1beta1constants.ShootTaskRestartCoreAddons)
				}
				return nil
			},
			SkipIf:       b.Shoot.IsWorkerless || b.Shoot.HibernationEnabled,
			Dependencies: flow.NewTaskIDs(waitUntilNetworkReady),
		})
		_ = g.Add(flow.Task{
			Name: "Waiting until CoreDNS system component is ready",
			Fn: func(ctx context.Context) error {
				return b.Shoot.Components.SystemComponents.CoreDNS.Wait(ctx)
			},
			Dependencies: flow.NewTaskIDs(deployCoreDNS),
			SkipIf:       !b.Shoot.IsSelfHosted(),
		})

		_ = g.Add(flow.Task{
			Name:         "Reconcile node-local-dns system component",
			Fn:           b.ReconcileNodeLocalDNS,
			SkipIf:       b.Shoot.IsWorkerless || b.Shoot.HibernationEnabled,
			Dependencies: flow.NewTaskIDs(waitUntilNetworkReady),
		})
		_ = g.Add(flow.Task{
			Name: "Deploying shoot cluster identity",
			Fn: flow.TaskFn(func(ctx context.Context) error {
				return b.DeployClusterIdentity(ctx)
			}).RetryUntilTimeout(defaultInterval, defaultTimeout),
			SkipIf: b.Shoot.HibernationEnabled,
		})
		_ = g.Add(flow.Task{
			Name: "Deploying metrics-server system component",
			Fn: flow.TaskFn(func(ctx context.Context) error {
				return b.Shoot.Components.SystemComponents.MetricsServer.Deploy(ctx)
			}).RetryUntilTimeout(defaultInterval, defaultTimeout),
			SkipIf: b.Shoot.IsWorkerless || b.Shoot.HibernationEnabled,
		})
		_ = g.Add(flow.Task{
			Name: "Deploying node-problem-detector system component",
			Fn: flow.TaskFn(func(ctx context.Context) error {
				return b.Shoot.Components.SystemComponents.NodeProblemDetector.Deploy(ctx)
			}).RetryUntilTimeout(defaultInterval, defaultTimeout),
			SkipIf: b.Shoot.IsWorkerless || b.Shoot.HibernationEnabled,
		})
		_ = g.Add(flow.Task{
			Name:   "Deploying blackbox-exporter",
			Fn:     flow.TaskFn(b.ReconcileBlackboxExporterCluster).RetryUntilTimeout(defaultInterval, defaultTimeout),
			SkipIf: b.Shoot.IsWorkerless || b.Shoot.HibernationEnabled || b.Shoot.IsSelfHosted(),
		})
		_ = g.Add(flow.Task{
			Name:   "Deploying node-exporter",
			Fn:     flow.TaskFn(b.ReconcileNodeExporter).RetryUntilTimeout(defaultInterval, defaultTimeout),
			SkipIf: b.Shoot.IsWorkerless || b.Shoot.HibernationEnabled,
		})
		_ = g.Add(flow.Task{
			Name:   "Deploying addon Kubernetes Dashboard",
			Fn:     flow.TaskFn(b.DeployKubernetesDashboard).RetryUntilTimeout(defaultInterval, defaultTimeout),
			SkipIf: b.Shoot.IsWorkerless || b.Shoot.HibernationEnabled || b.Shoot.IsSelfHosted(),
		})
		_ = g.Add(flow.Task{
			Name:   "Deploying addon Nginx Ingress Controller",
			Fn:     flow.TaskFn(b.DeployNginxIngressAddon).RetryUntilTimeout(defaultInterval, defaultTimeout),
			SkipIf: b.Shoot.IsWorkerless || b.Shoot.HibernationEnabled || b.Shoot.IsSelfHosted(),
		})
	)

	return g
}

// TaskGroupReconcileVPNComponents is a flow.TaskID for a logical flow.TaskGroup.
const TaskGroupReconcileVPNComponents flow.TaskID = "TaskGroupReconcileVPNComponents"

// ReconcileVPNComponentsTaskGroup returns the flow.TaskGroup for reconciling VPN components.
func (b *Botanist) ReconcileVPNComponentsTaskGroup(skipReadiness bool) flow.TaskGroup {
	var (
		g = flow.NewTaskGroup(TaskGroupReconcileVPNComponents).
			SkipIf(b.Shoot.IsWorkerless || b.Shoot.IsSelfHosted()).
			WithDependencies(
				TaskGroupDeployNamespaces,
				TaskGroupInitializeSecretsManagement,
				TaskGroupReconcileGardenerResourceManager,
			)

		deployVPNSeedServer = g.Add(flow.Task{
			Name: "Deploying vpn-seed-server",
			Fn:   flow.TaskFn(b.DeployVPNServer).RetryUntilTimeout(defaultInterval, defaultTimeout),
		})
		_ = g.Add(flow.Task{
			Name: "Deploying apiserver-proxy",
			Fn:   flow.TaskFn(b.DeployAPIServerProxy).RetryUntilTimeout(defaultInterval, defaultTimeout),
		})
		deployVPNShoot = g.Add(flow.Task{
			Name:         "Deploying vpn-shoot system component",
			Fn:           flow.TaskFn(b.DeployVPNShoot).RetryUntilTimeout(defaultInterval, defaultTimeout),
			SkipIf:       b.Shoot.HibernationEnabled,
			Dependencies: flow.NewTaskIDs(deployVPNSeedServer),
		})
		_ = g.Add(flow.Task{
			Name: "Waiting until vpn-shoot system component is ready",
			Fn: func(ctx context.Context) error {
				return b.Shoot.Components.SystemComponents.VPNShoot.Wait(ctx)
			},
			SkipIf:       b.Shoot.HibernationEnabled || skipReadiness,
			Dependencies: flow.NewTaskIDs(deployVPNShoot),
		})
	)

	return g
}

// TaskGroupReconcileETCDs is a flow.TaskID for a logical flow.TaskGroup.
const TaskGroupReconcileETCDs flow.TaskID = "TaskGroupReconcileETCDs"

// ReconcileETCDsTaskGroup returns the flow.TaskGroup for deploying etcd-druid, the ETCDs resources, and waiting for
// their readiness.
func (b *Botanist) ReconcileETCDsTaskGroup(shootIsGarden, isRestoringHAControlPlane, skipReadiness bool) flow.TaskGroup {
	var (
		g = flow.NewTaskGroup(TaskGroupReconcileETCDs).
			WithDependencies(
				TaskGroupInitializeSecretsManagement,
				TaskGroupDeployCloudProviderSecret,
			).
			WithDependenciesIf(b.isGardenlet(),
				TaskGroupReconcileBackupResources,
			)

		deployEtcdDruid = g.Add(flow.Task{
			Name: "Deploying ETCD Druid",
			Fn: func(ctx context.Context) error {
				return b.Shoot.Components.ControlPlane.EtcdDruid.Deploy(ctx)
			},
			SkipIf: shootIsGarden || !b.Shoot.IsSelfHosted(),
		})
		configureEtcd = g.Add(flow.Task{
			Name: "Configuring static pod control plane node IP addresses for ETCDs",
			Fn: func(ctx context.Context) error {
				nodes, err := b.ListControlPlaneNodes(ctx)
				if err != nil {
					return fmt.Errorf("failed listing control plane nodes: %w", err)
				}

				ip, err := kubernetesutils.NodeInternalIP(nodes[0], b.Shoot.PreferIPv6())
				if err != nil {
					return fmt.Errorf("failed determining IP address of first control plane node: %w", err)
				}

				b.Shoot.Components.ControlPlane.EtcdMain.SetStaticPodControlPlaneNodesIPAddresses(ip)
				b.Shoot.Components.ControlPlane.EtcdEvents.SetStaticPodControlPlaneNodesIPAddresses(ip)
				return nil
			},
			SkipIf: !b.Shoot.IsSelfHosted(),
		})
		deployEtcds = g.Add(flow.Task{
			Name:         "Deploying main and events ETCDs",
			Fn:           flow.TaskFn(b.DeployEtcd).RetryUntilTimeout(5*time.Second, helper.GetEtcdDeployTimeout(b.Shoot, 30*time.Second)),
			Dependencies: flow.NewTaskIDs(deployEtcdDruid, configureEtcd),
		})
		_ = g.Add(flow.Task{
			Name:         "Waiting until main and event ETCDs have been reconciled",
			Fn:           b.WaitUntilEtcdsReady,
			SkipIf:       (!isRestoringHAControlPlane && b.Shoot.HibernationEnabled) || skipReadiness,
			Dependencies: flow.NewTaskIDs(deployEtcds),
		})
	)

	return g
}

// TaskGroupReconcileStaticPods is a flow.TaskID for a logical flow.TaskGroup.
const TaskGroupReconcileStaticPods flow.TaskID = "TaskGroupReconcileStaticPods"

// ReconcileStaticControlPlanePodsTaskGroup returns the flow.TaskGroup for deploying the static control plane
// deployments to the cluster (with replicas=0). It then translates them into static pod manifests, adds them to the
// OperatingSystemConfig, updates the ManagedResource containing the gardener-node-agent OSC Secret, and waits for the
// changes to be rolled out.
func (b *Botanist) ReconcileStaticControlPlanePodsTaskGroup(useBootstrapEtcd bool) flow.TaskGroup {
	var (
		g = flow.NewTaskGroup(TaskGroupReconcileStaticPods).
			SkipIf(!b.Shoot.IsSelfHosted()).
			WithDependencies(
				TaskGroupInitializeSecretsManagement,
				TaskGroupReconcileGardenerResourceManager,
				TaskGroupReconcileETCDs,
			).
			WithDependenciesIf(b.isGardenlet(),
				TaskGroupReconcileExtensionsBeforeKubeAPIServer,
			)

		_ = g.Add(flow.Task{
			Name: "Reconciling cluster-admin access resources for kubeconfig on control plane nodes",
			Fn: func(ctx context.Context) error {
				return component.OpWait(b.Shoot.Components.AdminAccess).Deploy(ctx)
			},
		})
		deployControlPlaneDeployments = g.Add(flow.Task{
			Name: "Deploying control plane components as Deployments/StatefulSets and updating gardener-node-agent Secret",
			Fn: func(ctx context.Context) error {
				return b.DeployStaticControlPlaneDeployments(ctx, useBootstrapEtcd)
			},
		})
		// 'gardenadm init' creates the OperatingSystemConfig and gardener-node-agent secrets based on the Shoot
		// manifest on the local filesystem (manually crafted). However, after 'gardenadm connect', the Shoot gets
		// registered with the gardener-apiserver, which runs additional mutations via admission plugins that might
		// change the Shoot spec in a way that affects the computation of the OSC/GNA secret names. Hence, when
		// gardenlet reconciles the first time after 'gardenadm init', we have to update the respective label on the
		// nodes to make sure that gardener-node-agent uses the correct secrets going forward.
		updateNodeAgentSecretNameLabels = g.Add(flow.Task{
			Name: fmt.Sprintf("Updating %s label on nodes after 'gardenadm init' to reflect computations of gardenlet", v1beta1constants.LabelWorkerPoolGardenerNodeAgentSecretName),
			Fn: func(ctx context.Context) error {
				if err := b.UpdateNodeAgentSecretNameLabelsOnNodes(ctx); err != nil {
					return fmt.Errorf("error updating %s labels on nodes: %w", v1beta1constants.LabelWorkerPoolGardenerNodeAgentSecretName, err)
				}
				if err := b.Shoot.Components.Extensions.OperatingSystemConfig.DeleteStaleResources(ctx); err != nil {
					return fmt.Errorf("error deleting stale OperatingSystemConfig resources: %w", err)
				}
				if err := b.Shoot.Components.Extensions.OperatingSystemConfig.WaitCleanupStaleResources(ctx); err != nil {
					return fmt.Errorf("error waiting until stale OperatingSystemConfig resources have been deleted: %w", err)
				}
				return b.RemoveTaskAnnotation(ctx, v1beta1constants.ShootTaskUpdateGardenerNodeAgentSecretName)
			},
			SkipIf:       !controllerutils.HasTask(b.Shoot.GetInfo().Annotations, v1beta1constants.ShootTaskUpdateGardenerNodeAgentSecretName),
			Dependencies: flow.NewTaskIDs(deployControlPlaneDeployments),
		})
		waitUntilControlPlaneComponentsRolledOut = g.Add(flow.Task{
			Name: "Waiting until control plane components (static pods) are rolled out and ready",
			Fn: func(ctx context.Context) error {
				return b.WaitUntilOperatingSystemConfigUpdatedForAllWorkerPools(ctx, b.isGardenlet(), true)
			},
			Dependencies: flow.NewTaskIDs(updateNodeAgentSecretNameLabels),
		})
	)

	b.handleCredentialsRotationForStaticPods(&g, waitUntilControlPlaneComponentsRolledOut)
	return g
}

func (b *Botanist) handleCredentialsRotationForStaticPods(g *flow.TaskGroup, readyForSecondRollout flow.TaskIDer) {
	var (
		rotationPreparingPhases            = sets.New(gardencorev1beta1.RotationPreparing, gardencorev1beta1.RotationPreparingWithoutWorkersRollout)
		caRotationPreparing                = rotationPreparingPhases.Has(v1beta1helper.GetShootCARotationPhase(b.Shoot.GetInfo().Status.Credentials))
		etcdEncryptionKeyRotationPreparing = rotationPreparingPhases.Has(v1beta1helper.GetShootETCDEncryptionKeyRotationPhase(b.Shoot.GetInfo().Status.Credentials))

		patchKubeAPIServerDeployment = g.Add(flow.Task{
			Name: "Marking kube-apiserver deployment as ready for encryption key switch",
			Fn: func(ctx context.Context) error {
				return shared.MarkAPIServerDeploymentAsReadyForEncryptionKeySwitch(ctx, b.SeedClientSet.Client(), b.Shoot.ControlPlaneNamespace, v1beta1constants.DeploymentNameKubeAPIServer)
			},
			SkipIf:       !etcdEncryptionKeyRotationPreparing,
			Dependencies: flow.NewTaskIDs(readyForSecondRollout),
		})
		patchETCDs = g.Add(flow.Task{
			Name: "Marking Etcd resources as peer CA rotation completed",
			Fn: flow.Parallel(
				b.Shoot.Components.ControlPlane.EtcdMain.MarkAsPeerCARolloutCompleted,
				b.Shoot.Components.ControlPlane.EtcdEvents.MarkAsPeerCARolloutCompleted,
			),
			SkipIf:       !caRotationPreparing,
			Dependencies: flow.NewTaskIDs(readyForSecondRollout),
		})

		deployEtcds = g.Add(flow.Task{
			Name:         "Deploying main and events ETCDs (second rollout)",
			Fn:           flow.TaskFn(b.DeployEtcd).RetryUntilTimeout(5*time.Second, helper.GetEtcdDeployTimeout(b.Shoot, 30*time.Second)),
			SkipIf:       !caRotationPreparing,
			Dependencies: flow.NewTaskIDs(patchETCDs),
		})
		waitUntilEtcdsReady = g.Add(flow.Task{
			Name:         "Waiting until main and event ETCDs have been reconciled (second rollout)",
			Fn:           b.WaitUntilEtcdsReady,
			SkipIf:       !caRotationPreparing,
			Dependencies: flow.NewTaskIDs(deployEtcds),
		})

		deployControlPlaneDeployments = g.Add(flow.Task{
			Name: "Deploying control plane components as Deployments/StatefulSets and updating gardener-node-agent Secret (second rollout)",
			Fn: func(ctx context.Context) error {
				return b.DeployStaticControlPlaneDeployments(ctx, false)
			},
			SkipIf:       !etcdEncryptionKeyRotationPreparing && !caRotationPreparing,
			Dependencies: flow.NewTaskIDs(patchKubeAPIServerDeployment, waitUntilEtcdsReady),
		})
		_ = g.Add(flow.Task{
			Name: "Waiting until control plane components (static pods) are rolled out and ready (second rollout)",
			Fn: func(ctx context.Context) error {
				return b.WaitUntilOperatingSystemConfigUpdatedForAllWorkerPools(ctx, true, true)
			},
			SkipIf:       !etcdEncryptionKeyRotationPreparing && !caRotationPreparing,
			Dependencies: flow.NewTaskIDs(deployControlPlaneDeployments),
		})
	)
}

// TaskGroupHibernateControlPlane is a flow.TaskID for a logical flow.TaskGroup.
const TaskGroupHibernateControlPlane flow.TaskID = "TaskGroupHibernateControlPlane"

// HibernateControlPlaneTaskGroup hibernates the control plane of a hosted shoot.
func (b *Botanist) HibernateControlPlaneTaskGroup(skipReadiness bool) flow.TaskGroup {
	var (
		g = flow.NewTaskGroup(TaskGroupHibernateControlPlane).
			SkipIf(!b.Shoot.HibernationEnabled || b.Shoot.IsSelfHosted()).
			WithDependencies(
				TaskGroupReconcileWorker,
				TaskGroupReconcileExtensionsAfterKubeAPIServer,
			)

		hibernateControlPlane = g.Add(flow.Task{
			Name: "Hibernating control plane",
			Fn:   flow.TaskFn(b.HibernateControlPlane).RetryUntilTimeout(defaultInterval, 2*time.Minute),
		})

		// logic is inverted here
		// extensions that are deployed before the kube-apiserver are hibernated after it
		hibernateExtensionResourcesAfterKAPIHibernation = g.Add(flow.Task{
			Name:         "Hibernating extension resources after kube-apiserver hibernation",
			Fn:           flow.TaskFn(b.DeployExtensionsBeforeKubeAPIServer).RetryUntilTimeout(defaultInterval, defaultTimeout),
			Dependencies: flow.NewTaskIDs(hibernateControlPlane),
		})
		_ = g.Add(flow.Task{
			Name:         "Waiting until extension resources hibernated after kube-apiserver hibernation are ready",
			Fn:           b.Shoot.Components.Extensions.Extension.WaitBeforeKubeAPIServer,
			SkipIf:       skipReadiness,
			Dependencies: flow.NewTaskIDs(hibernateExtensionResourcesAfterKAPIHibernation),
		})
		_ = g.Add(flow.Task{
			Name:         "Destroying ingress domain DNS record if hibernated",
			Fn:           b.DestroyIngressDNSRecord,
			Dependencies: flow.NewTaskIDs(hibernateControlPlane),
		})
		_ = g.Add(flow.Task{
			Name:         "Destroying external domain DNS record if hibernated",
			Fn:           b.DestroyExternalDNSRecord,
			Dependencies: flow.NewTaskIDs(hibernateControlPlane),
		})
		_ = g.Add(flow.Task{
			Name:         "Destroying internal domain DNS record if hibernated",
			Fn:           b.DestroyInternalDNSRecord,
			Dependencies: flow.NewTaskIDs(hibernateControlPlane),
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

func (b *Botanist) isGardenadmBootstrap() bool {
	return b.Shoot.IsSelfHosted() && !b.Shoot.RunsControlPlane()
}

func (b *Botanist) isGardenlet() bool {
	return strings.HasPrefix(b.Shoot.GetInfo().Status.Gardener.Name, v1beta1constants.DeploymentNameGardenlet)
}
