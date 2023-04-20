// Copyright 2021 SAP SE or an SAP affiliate company. All rights reserved. This file is licensed under the Apache Software License, v. 2 except as noted otherwise in the LICENSE file
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

package resourcemanager

import (
	"context"
	_ "embed"
	"fmt"
	"time"

	"github.com/Masterminds/semver"
	druidv1alpha1 "github.com/gardener/etcd-druid/api/v1alpha1"
	hvpav1alpha1 "github.com/gardener/hvpa-controller/api/v1alpha1"
	admissionv1 "k8s.io/api/admission/v1"
	admissionv1beta1 "k8s.io/api/admission/v1beta1"
	admissionregistrationv1 "k8s.io/api/admissionregistration/v1"
	appsv1 "k8s.io/api/apps/v1"
	autoscalingv1 "k8s.io/api/autoscaling/v1"
	autoscalingv2 "k8s.io/api/autoscaling/v2"
	autoscalingv2beta1 "k8s.io/api/autoscaling/v2beta1"
	corev1 "k8s.io/api/core/v1"
	discoveryv1 "k8s.io/api/discovery/v1"
	networkingv1 "k8s.io/api/networking/v1"
	policyv1 "k8s.io/api/policy/v1"
	policyv1beta1 "k8s.io/api/policy/v1beta1"
	rbacv1 "k8s.io/api/rbac/v1"
	apiextensionsv1 "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1"
	apiextensionsv1beta1 "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1beta1"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/runtime/serializer"
	"k8s.io/apimachinery/pkg/runtime/serializer/json"
	"k8s.io/apimachinery/pkg/util/intstr"
	utilruntime "k8s.io/apimachinery/pkg/util/runtime"
	vpaautoscalingv1 "k8s.io/autoscaler/vertical-pod-autoscaler/pkg/apis/autoscaling.k8s.io/v1"
	componentbaseconfigv1alpha1 "k8s.io/component-base/config/v1alpha1"
	"k8s.io/utils/pointer"
	"sigs.k8s.io/controller-runtime/pkg/client"

	gardencorev1beta1 "github.com/gardener/gardener/pkg/apis/core/v1beta1"
	v1beta1constants "github.com/gardener/gardener/pkg/apis/core/v1beta1/constants"
	extensionsv1alpha1 "github.com/gardener/gardener/pkg/apis/extensions/v1alpha1"
	resourcesv1alpha1 "github.com/gardener/gardener/pkg/apis/resources/v1alpha1"
	"github.com/gardener/gardener/pkg/client/kubernetes"
	"github.com/gardener/gardener/pkg/controllerutils"
	"github.com/gardener/gardener/pkg/operation/botanist/component"
	kubeapiserverconstants "github.com/gardener/gardener/pkg/operation/botanist/component/kubeapiserver/constants"
	"github.com/gardener/gardener/pkg/operation/botanist/component/kubescheduler"
	resourcemanagerconstants "github.com/gardener/gardener/pkg/operation/botanist/component/resourcemanager/constants"
	resourcemanagerv1alpha1 "github.com/gardener/gardener/pkg/resourcemanager/apis/config/v1alpha1"
	"github.com/gardener/gardener/pkg/resourcemanager/controller/garbagecollector/references"
	"github.com/gardener/gardener/pkg/resourcemanager/webhook/crddeletionprotection"
	"github.com/gardener/gardener/pkg/resourcemanager/webhook/endpointslicehints"
	"github.com/gardener/gardener/pkg/resourcemanager/webhook/extensionvalidation"
	"github.com/gardener/gardener/pkg/resourcemanager/webhook/highavailabilityconfig"
	"github.com/gardener/gardener/pkg/resourcemanager/webhook/podschedulername"
	"github.com/gardener/gardener/pkg/resourcemanager/webhook/podtopologyspreadconstraints"
	"github.com/gardener/gardener/pkg/resourcemanager/webhook/projectedtokenmount"
	"github.com/gardener/gardener/pkg/resourcemanager/webhook/seccompprofile"
	"github.com/gardener/gardener/pkg/resourcemanager/webhook/systemcomponentsconfig"
	"github.com/gardener/gardener/pkg/resourcemanager/webhook/tokeninvalidator"
	"github.com/gardener/gardener/pkg/utils"
	"github.com/gardener/gardener/pkg/utils/flow"
	gardenerutils "github.com/gardener/gardener/pkg/utils/gardener"
	kubernetesutils "github.com/gardener/gardener/pkg/utils/kubernetes"
	"github.com/gardener/gardener/pkg/utils/kubernetes/health"
	"github.com/gardener/gardener/pkg/utils/managedresources"
	"github.com/gardener/gardener/pkg/utils/retry"
	"github.com/gardener/gardener/pkg/utils/secrets"
	secretsmanager "github.com/gardener/gardener/pkg/utils/secrets/manager"
	"github.com/gardener/gardener/pkg/utils/version"
)

var (
	scheme *runtime.Scheme
	codec  runtime.Codec

	//go:embed assets/crd-resources.gardener.cloud_managedresources.yaml
	// CRD is the custom resource definition for ManagedResources.
	CRD string

	// SkipWebhookDeployment is a variable which controls whether the webhook deployment should be skipped.
	// Exposed for testing.
	SkipWebhookDeployment bool
)

func init() {
	scheme = runtime.NewScheme()
	utilruntime.Must(resourcemanagerv1alpha1.AddToScheme(scheme))
	utilruntime.Must(apiextensionsv1.AddToScheme(scheme))

	var (
		ser = json.NewSerializerWithOptions(json.DefaultMetaFactory, scheme, scheme, json.SerializerOptions{
			Yaml:   true,
			Pretty: false,
			Strict: false,
		})
		versions = schema.GroupVersions([]schema.GroupVersion{
			resourcemanagerv1alpha1.SchemeGroupVersion,
			apiextensionsv1.SchemeGroupVersion,
		})
	)

	codec = serializer.NewCodecFactory(scheme).CodecForVersions(ser, ser, versions, versions)
}

const (
	// ManagedResourceName is the name for the ManagedResource containing resources deployed to the shoot cluster.
	ManagedResourceName = "shoot-core-gardener-resource-manager"
	// SecretNameShootAccess is the name of the shoot access secret for the gardener-resource-manager.
	SecretNameShootAccess = gardenerutils.SecretNamePrefixShootAccess + v1beta1constants.DeploymentNameGardenerResourceManager
	// LabelValue is a constant for the value of the 'app' label on Kubernetes resources.
	LabelValue = "gardener-resource-manager"
	// labelChecksum is a constant for the label key which holds the checksum of the pod template.
	labelChecksum = "checksum/pod-template"

	configMapNamePrefix = "gardener-resource-manager"
	secretNameServer    = "gardener-resource-manager-server"
	clusterRoleName     = "gardener-resource-manager-seed"
	roleName            = "gardener-resource-manager"
	serviceAccountName  = "gardener-resource-manager"
	metricsPortName     = "metrics"
	containerName       = v1beta1constants.DeploymentNameGardenerResourceManager

	healthPort        = 8081
	metricsPort       = 8080
	serverServicePort = 443

	configMapDataKey = "config.yaml"

	volumeNameBootstrapKubeconfig = "kubeconfig-bootstrap"
	volumeNameCerts               = "tls"
	volumeNameAPIServerAccess     = "kube-api-access-gardener"
	volumeNameRootCA              = "root-ca"
	volumeNameConfiguration       = "config"

	volumeMountPathCerts           = "/etc/gardener-resource-manager-tls"
	volumeMountPathAPIServerAccess = "/var/run/secrets/kubernetes.io/serviceaccount"
	volumeMountPathRootCA          = "/etc/gardener-resource-manager-root-ca"
	volumeMountPathConfiguration   = "/etc/gardener-resource-manager-config"
)

var (
	allowAll = []rbacv1.PolicyRule{{
		APIGroups: []string{"*"},
		Resources: []string{"*"},
		Verbs:     []string{"*"},
	}}

	allowManagedResources = []rbacv1.PolicyRule{
		{
			APIGroups: []string{"resources.gardener.cloud"},
			Resources: []string{"managedresources", "managedresources/status"},
			Verbs:     []string{"get", "list", "watch", "update", "patch"},
		},
		{
			APIGroups: []string{""},
			Resources: []string{"secrets"},
			Verbs:     []string{"get", "list", "watch", "update", "patch"},
		},
		{
			APIGroups: []string{""},
			Resources: []string{"configmaps", "events"},
			Verbs:     []string{"create"},
		},
		{
			APIGroups:     []string{""},
			Resources:     []string{"configmaps"},
			ResourceNames: []string{"gardener-resource-manager"},
			Verbs:         []string{"get", "watch", "update", "patch"},
		},
		{
			APIGroups: []string{"coordination.k8s.io"},
			Resources: []string{"leases"},
			Verbs:     []string{"create"},
		},
		{
			APIGroups:     []string{"coordination.k8s.io"},
			Resources:     []string{"leases"},
			ResourceNames: []string{"gardener-resource-manager"},
			Verbs:         []string{"get", "watch", "update"},
		},
	}
	allowMachines = []rbacv1.PolicyRule{
		{
			APIGroups: []string{"machine.sapcloud.io"},
			Resources: []string{"machines"},
			Verbs:     []string{"get", "list", "watch"},
		},
	}
)

// Interface contains functions for a gardener-resource-manager deployer.
type Interface interface {
	component.DeployWaiter
	component.MonitoringComponent
	// GetReplicas gets the Replicas field in the Values.
	GetReplicas() *int32
	// SetReplicas sets the Replicas field in the Values.
	SetReplicas(*int32)
	// SetSecrets sets the secrets.
	SetSecrets(Secrets)
	// GetValues returns the current configuration values of the deployer.
	GetValues() Values
}

// New creates a new instance of the gardener-resource-manager.
func New(
	client client.Client,
	namespace string,
	secretsManager secretsmanager.Interface,
	values Values,
) Interface {
	return &resourceManager{
		client:         client,
		namespace:      namespace,
		secretsManager: secretsManager,
		values:         values,
	}
}

type resourceManager struct {
	client         client.Client
	namespace      string
	secretsManager secretsmanager.Interface
	values         Values
	secrets        Secrets
}

// Values holds the optional configuration options for the gardener resource manager
type Values struct {
	// AlwaysUpdate if set to false then a resource will only be updated if its desired state differs from the actual state. otherwise, an update request will be always sent
	AlwaysUpdate *bool
	// ClusterIdentity is the identity of the managing cluster.
	ClusterIdentity *string
	// ConcurrentSyncs are the number of worker threads for concurrent reconciliation of resources
	ConcurrentSyncs *int
	// HealthSyncPeriod describes the duration of how often the health of existing resources should be synced
	HealthSyncPeriod *metav1.Duration
	// FullNetworkPolicies makes the network policy controller to consider all relevant namespaces.
	FullNetworkPolicies bool
	// NetworkPolicyControllerIncludesGardenNamespace describes whether the 'garden' namespace should be targeted by the
	// network policy controller.
	NetworkPolicyControllerIncludesGardenNamespace bool
	// NetworkPolicyControllerIngressControllerSelector is the peer information of the ingress controller for the
	// network policy controller.
	NetworkPolicyControllerIngressControllerSelector *resourcemanagerv1alpha1.IngressControllerSelector
	// Image is the container image.
	Image string
	// LogLevel is the level/severity for the logs. Must be one of [info,debug,error].
	LogLevel string
	// LogFormat is the output format for the logs. Must be one of [text,json].
	LogFormat string
	// MaxConcurrentHealthWorkers configures the number of worker threads for concurrent health reconciliation of resources
	MaxConcurrentHealthWorkers *int
	// MaxConcurrentTokenInvalidatorWorkers configures the number of worker threads for concurrent token invalidator reconciliations
	MaxConcurrentTokenInvalidatorWorkers *int
	// MaxConcurrentTokenRequestorWorkers configures the number of worker threads for concurrent token requestor reconciliations
	MaxConcurrentTokenRequestorWorkers *int
	// MaxConcurrentCSRApproverWorkers configures the number of worker threads for concurrent kubelet CSR approver reconciliations
	MaxConcurrentCSRApproverWorkers *int
	// PriorityClassName is the name of the priority class.
	PriorityClassName string
	// Replicas is the number of replicas for the gardener-resource-manager deployment.
	Replicas *int32
	// ResourceClass is used to filter resource resources
	ResourceClass *string
	// SecretNameServerCA is the name of the server CA secret.
	SecretNameServerCA string
	// SyncPeriod configures the duration of how often existing resources should be synced
	SyncPeriod *metav1.Duration
	// SystemComponentTolerations are the tolerations required for shoot system components.
	SystemComponentTolerations []corev1.Toleration
	// TargetDiffersFromSourceCluster states whether the target cluster is a different one than the source cluster
	TargetDiffersFromSourceCluster bool
	// TargetDisableCache disables the cache for target cluster and always talk directly to the API server (defaults to false)
	TargetDisableCache *bool
	// WatchedNamespace restricts the gardener-resource-manager to only watch ManagedResources in the defined namespace.
	// If not set the gardener-resource-manager controller watches for ManagedResources in all namespaces
	WatchedNamespace *string
	// KubernetesVersion is the Kubernetes version for the Kubernetes components.
	KubernetesVersion *semver.Version
	// VPA contains information for configuring VerticalPodAutoscaler settings for the gardener-resource-manager deployment.
	VPA *VPAConfig
	// SchedulingProfile is the kube-scheduler profile configured for the Shoot.
	SchedulingProfile *gardencorev1beta1.SchedulingProfile
	// DefaultSeccompProfileEnabled specifies if the defaulting seccomp profile webhook of GRM should be enabled or not.
	DefaultSeccompProfileEnabled bool
	// EndpointSliceHintsEnabled specifies if the EndpointSlice hints webhook of GRM should be enabled or not.
	EndpointSliceHintsEnabled bool
	// PodTopologySpreadConstraintsEnabled specifies if the pod's TSC should be mutated to support rolling updates.
	PodTopologySpreadConstraintsEnabled bool
	// FailureToleranceType determines the failure tolerance type for the resource manager deployment.
	FailureToleranceType *gardencorev1beta1.FailureToleranceType
	// Zones is number of availability zones.
	Zones []string
	// TopologyAwareRoutingEnabled indicates whether topology-aware routing is enabled for the gardener-resource-manager service.
	// This value is only applicable for the GRM that is deployed in the Shoot control plane (when TargetDiffersFromSourceCluster=true).
	TopologyAwareRoutingEnabled bool
	// IsWorkerless specifies whether the cluster has workers.
	IsWorkerless bool
}

// VPAConfig contains information for configuring VerticalPodAutoscaler settings for the gardener-resource-manager deployment.
type VPAConfig struct {
	// MinAllowed specifies the minimal amount of resources that will be recommended
	// for the container.
	MinAllowed corev1.ResourceList
}

func (r *resourceManager) Deploy(ctx context.Context) error {
	if r.values.TargetDiffersFromSourceCluster {
		r.secrets.shootAccess = r.newShootAccessSecret()
		if err := r.secrets.shootAccess.WithTokenExpirationDuration("24h").Reconcile(ctx, r.client); err != nil {
			return err
		}
	} else {
		if err := r.ensureCustomResourceDefinition(ctx); err != nil {
			return err
		}
	}

	configMap := r.emptyConfigMap()

	fns := []flow.TaskFn{
		r.ensureServiceAccount,
		func(ctx context.Context) error { return r.ensureConfigMap(ctx, configMap) },
		r.ensureRBAC,
		r.ensureService,
		func(ctx context.Context) error { return r.ensureDeployment(ctx, configMap) },
		r.ensurePodDisruptionBudget,
		r.ensureVPA,
	}

	if r.values.TargetDiffersFromSourceCluster {
		fns = append(fns, r.ensureShootResources)
		// TODO(rfranzke): Remove this in a future version.
		fns = append(fns, func(ctx context.Context) error {
			return kubernetesutils.DeleteObject(ctx, r.client, &networkingv1.NetworkPolicy{ObjectMeta: metav1.ObjectMeta{Name: "allow-kube-apiserver-to-gardener-resource-manager", Namespace: r.namespace}})
		})
	} else {
		fns = append(fns, r.ensureMutatingWebhookConfiguration)
		fns = append(fns, r.ensureValidatingWebhookConfiguration)
	}

	if err := flow.Sequential(fns...)(ctx); err != nil {
		return err
	}

	return nil
}

func (r *resourceManager) Destroy(ctx context.Context) error {
	objectsToDelete := []client.Object{
		r.emptyPodDisruptionBudget(),
		r.emptyVPA(),
		r.emptyDeployment(),
		r.emptyService(),
		r.emptyServiceAccount(),
	}

	if r.values.TargetDiffersFromSourceCluster {
		if err := managedresources.DeleteForShoot(ctx, r.client, r.namespace, ManagedResourceName); err != nil {
			return err
		}

		timeoutCtx, cancel := context.WithTimeout(ctx, 2*time.Minute)
		defer cancel()

		if err := managedresources.WaitUntilDeleted(timeoutCtx, r.client, r.namespace, ManagedResourceName); err != nil {
			return err
		}

		objectsToDelete = append(objectsToDelete,
			r.newShootAccessSecret().Secret,
			r.emptyRoleInWatchedNamespace(),
			r.emptyRoleBindingInWatchedNamespace(),
		)
	} else {
		crd, err := r.emptyCustomResourceDefinition()
		if err != nil {
			return err
		}

		if err := gardenerutils.ConfirmDeletion(ctx, r.client, crd); client.IgnoreNotFound(err) != nil {
			return err
		}

		objectsToDelete = append([]client.Object{
			&apiextensionsv1.CustomResourceDefinition{ObjectMeta: metav1.ObjectMeta{Name: crd.Name}},
			r.emptyMutatingWebhookConfiguration(),
			r.emptyValidatingWebhookConfiguration(),
			r.emptyClusterRole(),
			r.emptyClusterRoleBinding(),
			// TODO(rfranzke): Remove this in a future version.
			&networkingv1.NetworkPolicy{ObjectMeta: metav1.ObjectMeta{Name: "allow-kube-apiserver-to-gardener-resource-manager", Namespace: r.namespace}},
		}, objectsToDelete...)
	}

	return kubernetesutils.DeleteObjects(ctx, r.client, objectsToDelete...)
}

func (r *resourceManager) emptyCustomResourceDefinition() (*apiextensionsv1.CustomResourceDefinition, error) {
	obj, err := runtime.Decode(codec, []byte(CRD))
	if err != nil {
		return nil, err
	}

	crd, ok := obj.(*apiextensionsv1.CustomResourceDefinition)
	if !ok {
		return nil, fmt.Errorf("expected *apiextensionsv1.CustomResourceDefinition but got %T", obj)
	}

	return crd, nil
}

func (r *resourceManager) ensureCustomResourceDefinition(ctx context.Context) error {
	desiredCRD, err := r.emptyCustomResourceDefinition()
	if err != nil {
		return err
	}

	crd := &apiextensionsv1.CustomResourceDefinition{ObjectMeta: metav1.ObjectMeta{Name: desiredCRD.Name}}
	_, err = controllerutils.GetAndCreateOrMergePatch(ctx, r.client, crd, func() error {
		crd.Annotations = utils.MergeStringMaps(crd.Annotations, desiredCRD.Annotations)
		crd.Labels = utils.MergeStringMaps(crd.Labels, desiredCRD.Labels)
		crd.Spec = desiredCRD.Spec
		return nil
	})
	return err
}

func (r *resourceManager) ensureRBAC(ctx context.Context) error {
	if r.values.TargetDiffersFromSourceCluster {
		if r.values.WatchedNamespace == nil {
			if err := r.ensureClusterRole(ctx, allowManagedResources); err != nil {
				return err
			}
			if err := r.ensureClusterRoleBinding(ctx); err != nil {
				return err
			}
		} else {
			if err := r.ensureRoleInWatchedNamespace(ctx, append(allowManagedResources, allowMachines...)...); err != nil {
				return err
			}
			if err := r.ensureRoleBinding(ctx); err != nil {
				return err
			}
		}
	} else {
		if err := r.ensureClusterRole(ctx, allowAll); err != nil {
			return err
		}
		if err := r.ensureClusterRoleBinding(ctx); err != nil {
			return err
		}
	}
	return nil
}

func (r *resourceManager) ensureClusterRole(ctx context.Context, policies []rbacv1.PolicyRule) error {
	clusterRole := r.emptyClusterRole()
	_, err := controllerutils.GetAndCreateOrMergePatch(ctx, r.client, clusterRole, func() error {
		clusterRole.Labels = r.getLabels()
		clusterRole.Rules = policies
		return nil
	})
	return err
}

func (r *resourceManager) emptyClusterRole() *rbacv1.ClusterRole {
	return &rbacv1.ClusterRole{ObjectMeta: metav1.ObjectMeta{Name: clusterRoleName}}
}

func (r *resourceManager) ensureClusterRoleBinding(ctx context.Context) error {
	clusterRoleBinding := r.emptyClusterRoleBinding()
	_, err := controllerutils.GetAndCreateOrMergePatch(ctx, r.client, clusterRoleBinding, func() error {
		clusterRoleBinding.Labels = r.getLabels()
		clusterRoleBinding.RoleRef = rbacv1.RoleRef{
			APIGroup: rbacv1.GroupName,
			Kind:     "ClusterRole",
			Name:     clusterRoleName,
		}
		clusterRoleBinding.Subjects = []rbacv1.Subject{{
			Kind:      rbacv1.ServiceAccountKind,
			Name:      serviceAccountName,
			Namespace: r.namespace,
		}}
		return nil
	})
	return err
}

func (r *resourceManager) emptyClusterRoleBinding() *rbacv1.ClusterRoleBinding {
	return &rbacv1.ClusterRoleBinding{ObjectMeta: metav1.ObjectMeta{Name: clusterRoleName}}
}

func (r *resourceManager) ensureConfigMap(ctx context.Context, configMap *corev1.ConfigMap) error {
	config := &resourcemanagerv1alpha1.ResourceManagerConfiguration{
		SourceClientConnection: resourcemanagerv1alpha1.SourceClientConnection{
			Namespace: r.values.WatchedNamespace,
		},
		LeaderElection: componentbaseconfigv1alpha1.LeaderElectionConfiguration{
			LeaderElect:       pointer.Bool(true),
			ResourceNamespace: r.namespace,
		},
		Server: resourcemanagerv1alpha1.ServerConfiguration{
			HealthProbes: &resourcemanagerv1alpha1.Server{
				Port: healthPort,
			},
			Metrics: &resourcemanagerv1alpha1.Server{
				Port: metricsPort,
			},
			Webhooks: resourcemanagerv1alpha1.HTTPSServer{
				Server: resourcemanagerv1alpha1.Server{
					Port: resourcemanagerconstants.ServerPort,
				},
				TLS: resourcemanagerv1alpha1.TLSServer{
					ServerCertDir: volumeMountPathCerts,
				},
			},
		},
		LogLevel:  r.values.LogLevel,
		LogFormat: r.values.LogFormat,
		Controllers: resourcemanagerv1alpha1.ResourceManagerControllerConfiguration{
			ClusterID:     r.values.ClusterIdentity,
			ResourceClass: r.values.ResourceClass,
			GarbageCollector: resourcemanagerv1alpha1.GarbageCollectorControllerConfig{
				Enabled:    true,
				SyncPeriod: &metav1.Duration{Duration: 12 * time.Hour},
			},
			Health: resourcemanagerv1alpha1.HealthControllerConfig{
				ConcurrentSyncs: r.values.MaxConcurrentHealthWorkers,
				SyncPeriod:      r.values.HealthSyncPeriod,
			},
			ManagedResource: resourcemanagerv1alpha1.ManagedResourceControllerConfig{
				ConcurrentSyncs: r.values.ConcurrentSyncs,
				SyncPeriod:      r.values.SyncPeriod,
				AlwaysUpdate:    r.values.AlwaysUpdate,
			},
		},
		Webhooks: resourcemanagerv1alpha1.ResourceManagerWebhookConfiguration{
			EndpointSliceHints: resourcemanagerv1alpha1.EndpointSliceHintsWebhookConfig{
				Enabled: r.values.EndpointSliceHintsEnabled,
			},
			HighAvailabilityConfig: resourcemanagerv1alpha1.HighAvailabilityConfigWebhookConfig{
				Enabled: true,
			},
			PodTopologySpreadConstraints: resourcemanagerv1alpha1.PodTopologySpreadConstraintsWebhookConfig{
				Enabled: r.values.PodTopologySpreadConstraintsEnabled,
			},
			ProjectedTokenMount: resourcemanagerv1alpha1.ProjectedTokenMountWebhookConfig{
				Enabled: true,
			},
			SeccompProfile: resourcemanagerv1alpha1.SeccompProfileWebhookConfig{
				Enabled: r.values.DefaultSeccompProfileEnabled,
			},
		},
	}

	if r.values.TargetDiffersFromSourceCluster {
		config.TargetClientConnection = &resourcemanagerv1alpha1.TargetClientConnection{
			ClientConnectionConfiguration: componentbaseconfigv1alpha1.ClientConnectionConfiguration{
				Kubeconfig: gardenerutils.PathGenericKubeconfig,
			},
			DisableCachedClient: r.values.TargetDisableCache,
		}
	} else {
		config.Controllers.NetworkPolicy = resourcemanagerv1alpha1.NetworkPolicyControllerConfig{
			Enabled: true,
			NamespaceSelectors: []metav1.LabelSelector{
				{MatchLabels: map[string]string{v1beta1constants.GardenRole: v1beta1constants.GardenRoleShoot}},
				{MatchLabels: map[string]string{v1beta1constants.GardenRole: v1beta1constants.GardenRoleIstioSystem}},
				{MatchLabels: map[string]string{v1beta1constants.GardenRole: v1beta1constants.GardenRoleIstioIngress}},
				{MatchExpressions: []metav1.LabelSelectorRequirement{{Key: v1beta1constants.LabelExposureClassHandlerName, Operator: metav1.LabelSelectorOpExists}}},
			},
			IngressControllerSelector: r.values.NetworkPolicyControllerIngressControllerSelector,
		}
		config.Webhooks.CRDDeletionProtection.Enabled = true
		config.Webhooks.ExtensionValidation.Enabled = true

		if r.values.FullNetworkPolicies {
			config.Controllers.NetworkPolicy.NamespaceSelectors = append(config.Controllers.NetworkPolicy.NamespaceSelectors,
				metav1.LabelSelector{MatchLabels: map[string]string{v1beta1constants.GardenRole: v1beta1constants.GardenRoleExtension}},
			)
		}

		if r.values.NetworkPolicyControllerIncludesGardenNamespace {
			config.Controllers.NetworkPolicy.NamespaceSelectors = append(config.Controllers.NetworkPolicy.NamespaceSelectors,
				metav1.LabelSelector{MatchLabels: map[string]string{corev1.LabelMetadataName: v1beta1constants.GardenNamespace}},
			)
		}
	}

	if v := r.values.MaxConcurrentCSRApproverWorkers; v != nil {
		config.Controllers.KubeletCSRApprover.Enabled = true
		config.Controllers.KubeletCSRApprover.ConcurrentSyncs = v
	}

	if v := r.values.MaxConcurrentTokenRequestorWorkers; v != nil {
		config.Controllers.TokenRequestor.Enabled = true
		config.Controllers.TokenRequestor.ConcurrentSyncs = v
	}

	if v := r.values.MaxConcurrentTokenInvalidatorWorkers; v != nil {
		config.Webhooks.TokenInvalidator.Enabled = true
		config.Controllers.TokenInvalidator.Enabled = true
		config.Controllers.TokenInvalidator.ConcurrentSyncs = v
	}

	if r.values.SchedulingProfile != nil && *r.values.SchedulingProfile != gardencorev1beta1.SchedulingProfileBalanced {
		config.Webhooks.PodSchedulerName.Enabled = true
		config.Webhooks.PodSchedulerName.SchedulerName = pointer.String(kubescheduler.BinPackingSchedulerName)
	}

	if r.values.TargetDiffersFromSourceCluster {
		config.Webhooks.SystemComponentsConfig = resourcemanagerv1alpha1.SystemComponentsConfigWebhookConfig{
			Enabled: true,
			NodeSelector: map[string]string{
				v1beta1constants.LabelWorkerPoolSystemComponents: "true",
			},
			PodNodeSelector: map[string]string{
				v1beta1constants.LabelWorkerPoolSystemComponents: "true",
			},
			PodTolerations: r.values.SystemComponentTolerations,
		}

		config.Controllers.Node.Enabled = true
	}

	// this function should be called at the last to make sure we disable
	// unneeded controllers and webhooks for workerless shoot, it is required so
	// that we don't overwrite it in the later stage.
	if r.values.IsWorkerless {
		disableControllersAndWebhooksForWorkerlessShoot(config)
	}

	data, err := runtime.Encode(codec, config)
	if err != nil {
		return err
	}

	configMap.Data = map[string]string{configMapDataKey: string(data)}
	utilruntime.Must(kubernetesutils.MakeUnique(configMap))

	return client.IgnoreAlreadyExists(r.client.Create(ctx, configMap))
}

func (r *resourceManager) emptyConfigMap() *corev1.ConfigMap {
	return &corev1.ConfigMap{ObjectMeta: metav1.ObjectMeta{Name: configMapNamePrefix, Namespace: r.namespace}}
}

func (r *resourceManager) ensureRoleInWatchedNamespace(ctx context.Context, policies ...rbacv1.PolicyRule) error {
	role := r.emptyRoleInWatchedNamespace()
	_, err := controllerutils.GetAndCreateOrMergePatch(ctx, r.client, role, func() error {
		role.Labels = r.getLabels()
		role.Rules = policies
		return nil
	})
	return err
}

func (r *resourceManager) emptyRoleInWatchedNamespace() *rbacv1.Role {
	return &rbacv1.Role{ObjectMeta: metav1.ObjectMeta{Name: roleName, Namespace: *r.values.WatchedNamespace}}
}

func (r *resourceManager) ensureRoleBinding(ctx context.Context) error {
	roleBinding := r.emptyRoleBindingInWatchedNamespace()
	_, err := controllerutils.GetAndCreateOrMergePatch(ctx, r.client, roleBinding, func() error {
		roleBinding.Labels = r.getLabels()
		roleBinding.RoleRef = rbacv1.RoleRef{
			APIGroup: rbacv1.GroupName,
			Kind:     "Role",
			Name:     roleName,
		}
		roleBinding.Subjects = []rbacv1.Subject{{
			Kind:      rbacv1.ServiceAccountKind,
			Name:      serviceAccountName,
			Namespace: r.namespace,
		}}
		return nil
	})
	return err
}

func (r *resourceManager) emptyRoleBindingInWatchedNamespace() *rbacv1.RoleBinding {
	return &rbacv1.RoleBinding{ObjectMeta: metav1.ObjectMeta{Name: "gardener-resource-manager", Namespace: *r.values.WatchedNamespace}}
}

func (r *resourceManager) ensureService(ctx context.Context) error {
	const (
		healthPortName = "health"
		serverPortName = "server"
	)

	service := r.emptyService()
	_, err := controllerutils.GetAndCreateOrMergePatch(ctx, r.client, service, func() error {
		service.Labels = utils.MergeStringMaps(service.Labels, r.getLabels())

		portMetrics := networkingv1.NetworkPolicyPort{
			Port:     utils.IntStrPtrFromInt(metricsPort),
			Protocol: utils.ProtocolPtr(corev1.ProtocolTCP),
		}

		if !r.values.TargetDiffersFromSourceCluster {
			utilruntime.Must(gardenerutils.InjectNetworkPolicyAnnotationsForSeedScrapeTargets(service, portMetrics))
			metav1.SetMetaDataAnnotation(&service.ObjectMeta, resourcesv1alpha1.NetworkingFromWorldToPorts, fmt.Sprintf(`[{"protocol":"TCP","port":%d}]`, resourcemanagerconstants.ServerPort))
		} else {
			utilruntime.Must(gardenerutils.InjectNetworkPolicyAnnotationsForScrapeTargets(service, portMetrics))
		}

		topologyAwareRoutingEnabled := r.values.TopologyAwareRoutingEnabled && r.values.TargetDiffersFromSourceCluster
		gardenerutils.ReconcileTopologyAwareRoutingMetadata(service, topologyAwareRoutingEnabled)

		service.Spec.Selector = appLabel()
		service.Spec.Type = corev1.ServiceTypeClusterIP
		desiredPorts := []corev1.ServicePort{
			{
				Name:     metricsPortName,
				Protocol: corev1.ProtocolTCP,
				Port:     metricsPort,
			},
			{
				Name:     healthPortName,
				Protocol: corev1.ProtocolTCP,
				Port:     healthPort,
			},
			{
				Name:       serverPortName,
				Protocol:   corev1.ProtocolTCP,
				Port:       serverServicePort,
				TargetPort: intstr.FromInt(resourcemanagerconstants.ServerPort),
			},
		}
		service.Spec.Ports = kubernetesutils.ReconcileServicePorts(service.Spec.Ports, desiredPorts, corev1.ServiceTypeClusterIP)
		return nil
	})
	return err
}

func (r *resourceManager) emptyService() *corev1.Service {
	return &corev1.Service{ObjectMeta: metav1.ObjectMeta{Name: resourcemanagerconstants.ServiceName, Namespace: r.namespace}}
}

func (r *resourceManager) ensureDeployment(ctx context.Context, configMap *corev1.ConfigMap) error {
	deployment := r.emptyDeployment()

	secretServer, err := r.secretsManager.Generate(ctx, &secrets.CertificateSecretConfig{
		Name:                        secretNameServer,
		CommonName:                  v1beta1constants.DeploymentNameGardenerResourceManager,
		DNSNames:                    kubernetesutils.DNSNamesForService(resourcemanagerconstants.ServiceName, r.namespace),
		CertType:                    secrets.ServerCert,
		SkipPublishingCACertificate: true,
	}, secretsmanager.SignedByCA(r.values.SecretNameServerCA, secretsmanager.UseCurrentCA), secretsmanager.Rotate(secretsmanager.InPlace))
	if err != nil {
		return err
	}

	_, err = controllerutils.GetAndCreateOrMergePatch(ctx, r.client, deployment, func() error {
		deployment.Labels = r.getLabels()

		deployment.Spec.Replicas = r.values.Replicas
		deployment.Spec.RevisionHistoryLimit = pointer.Int32(2)
		deployment.Spec.Selector = &metav1.LabelSelector{MatchLabels: appLabel()}

		deployment.Spec.Template = corev1.PodTemplateSpec{
			ObjectMeta: metav1.ObjectMeta{
				Labels: utils.MergeStringMaps(r.getDeploymentTemplateLabels(), r.getNetworkPolicyLabels(), map[string]string{
					resourcesv1alpha1.ProjectedTokenSkip: "true",
				}),
			},
			Spec: corev1.PodSpec{
				PriorityClassName: r.values.PriorityClassName,
				SecurityContext: &corev1.PodSecurityContext{
					SeccompProfile: &corev1.SeccompProfile{
						Type: corev1.SeccompProfileTypeRuntimeDefault,
					},
				},
				ServiceAccountName: serviceAccountName,
				Containers: []corev1.Container{
					{
						Name:            containerName,
						Image:           r.values.Image,
						ImagePullPolicy: corev1.PullIfNotPresent,
						Args:            []string{fmt.Sprintf("--config=%s/%s", volumeMountPathConfiguration, configMapDataKey)},
						Ports: []corev1.ContainerPort{
							{
								Name:          "metrics",
								ContainerPort: metricsPort,
								Protocol:      corev1.ProtocolTCP,
							},
							{
								Name:          "health",
								ContainerPort: healthPort,
								Protocol:      corev1.ProtocolTCP,
							},
						},
						Resources: corev1.ResourceRequirements{
							Requests: corev1.ResourceList{
								corev1.ResourceCPU:    resource.MustParse("23m"),
								corev1.ResourceMemory: resource.MustParse("47Mi"),
							},
						},
						LivenessProbe: &corev1.Probe{
							ProbeHandler: corev1.ProbeHandler{
								HTTPGet: &corev1.HTTPGetAction{
									Path:   "/healthz",
									Scheme: "HTTP",
									Port:   intstr.FromInt(healthPort),
								},
							},
							InitialDelaySeconds: 30,
							FailureThreshold:    5,
							PeriodSeconds:       10,
							SuccessThreshold:    1,
							TimeoutSeconds:      5,
						},
						ReadinessProbe: &corev1.Probe{
							ProbeHandler: corev1.ProbeHandler{
								HTTPGet: &corev1.HTTPGetAction{
									Path:   "/readyz",
									Scheme: "HTTP",
									Port:   intstr.FromInt(healthPort),
								},
							},
							InitialDelaySeconds: 10,
						},
						VolumeMounts: []corev1.VolumeMount{
							{
								Name:      volumeNameAPIServerAccess,
								MountPath: volumeMountPathAPIServerAccess,
								ReadOnly:  true,
							},
							{
								MountPath: volumeMountPathCerts,
								Name:      volumeNameCerts,
								ReadOnly:  true,
							},
							{
								MountPath: volumeMountPathConfiguration,
								Name:      volumeNameConfiguration,
								ReadOnly:  true,
							},
						},
					},
				},
				Volumes: []corev1.Volume{
					{
						Name: volumeNameAPIServerAccess,
						VolumeSource: corev1.VolumeSource{
							Projected: &corev1.ProjectedVolumeSource{
								DefaultMode: pointer.Int32(420),
								Sources: []corev1.VolumeProjection{
									{
										ServiceAccountToken: &corev1.ServiceAccountTokenProjection{
											ExpirationSeconds: pointer.Int64(60 * 60 * 12),
											Path:              "token",
										},
									},
									{
										ConfigMap: &corev1.ConfigMapProjection{
											LocalObjectReference: corev1.LocalObjectReference{
												Name: "kube-root-ca.crt",
											},
											Items: []corev1.KeyToPath{{
												Key:  "ca.crt",
												Path: "ca.crt",
											}},
										},
									},
									{
										DownwardAPI: &corev1.DownwardAPIProjection{
											Items: []corev1.DownwardAPIVolumeFile{{
												FieldRef: &corev1.ObjectFieldSelector{
													APIVersion: "v1",
													FieldPath:  "metadata.namespace",
												},
												Path: "namespace",
											}},
										},
									},
								},
							},
						},
					},
					{
						Name: volumeNameCerts,
						VolumeSource: corev1.VolumeSource{
							Secret: &corev1.SecretVolumeSource{
								SecretName:  secretServer.Name,
								DefaultMode: pointer.Int32(420),
							},
						},
					},
					{
						Name: volumeNameConfiguration,
						VolumeSource: corev1.VolumeSource{
							ConfigMap: &corev1.ConfigMapVolumeSource{
								LocalObjectReference: corev1.LocalObjectReference{
									Name: configMap.Name,
								},
							},
						},
					},
				},
			},
		}

		if r.values.TargetDiffersFromSourceCluster {
			clusterCASecret, found := r.secretsManager.Get(v1beta1constants.SecretNameCACluster)
			if !found {
				return fmt.Errorf("secret %q not found", v1beta1constants.SecretNameCACluster)
			}

			deployment.Spec.Template.Spec.Volumes = append(deployment.Spec.Template.Spec.Volumes, corev1.Volume{
				Name: volumeNameRootCA,
				VolumeSource: corev1.VolumeSource{
					Secret: &corev1.SecretVolumeSource{
						SecretName:  clusterCASecret.Name,
						DefaultMode: pointer.Int32(420),
					},
				},
			})
			deployment.Spec.Template.Spec.Containers[0].VolumeMounts = append(deployment.Spec.Template.Spec.Containers[0].VolumeMounts, corev1.VolumeMount{
				MountPath: volumeMountPathRootCA,
				Name:      volumeNameRootCA,
				ReadOnly:  true,
			})

			if r.secrets.BootstrapKubeconfig != nil {
				deployment.Spec.Template.Spec.Volumes = append(deployment.Spec.Template.Spec.Volumes, corev1.Volume{
					Name: volumeNameBootstrapKubeconfig,
					VolumeSource: corev1.VolumeSource{
						Secret: &corev1.SecretVolumeSource{
							SecretName:  r.secrets.BootstrapKubeconfig.Name,
							DefaultMode: pointer.Int32(420),
						},
					},
				})
				deployment.Spec.Template.Spec.Containers[0].VolumeMounts = append(deployment.Spec.Template.Spec.Containers[0].VolumeMounts, corev1.VolumeMount{
					MountPath: gardenerutils.VolumeMountPathGenericKubeconfig,
					Name:      volumeNameBootstrapKubeconfig,
					ReadOnly:  true,
				})
			} else if r.secrets.shootAccess != nil {
				genericTokenKubeconfigSecret, found := r.secretsManager.Get(v1beta1constants.SecretNameGenericTokenKubeconfig)
				if !found {
					return fmt.Errorf("secret %q not found", v1beta1constants.SecretNameGenericTokenKubeconfig)
				}

				utilruntime.Must(gardenerutils.InjectGenericKubeconfig(deployment, genericTokenKubeconfigSecret.Name, r.secrets.shootAccess.Secret.Name))
			}
		}

		utilruntime.Must(references.InjectAnnotations(deployment))

		if r.values.TargetDiffersFromSourceCluster {
			deployment.Labels = utils.MergeStringMaps(deployment.Labels, map[string]string{
				resourcesv1alpha1.HighAvailabilityConfigType: resourcesv1alpha1.HighAvailabilityConfigTypeServer,
			})
		} else {
			deployment.Labels = utils.MergeStringMaps(deployment.Labels, map[string]string{
				resourcesv1alpha1.HighAvailabilityConfigSkip: "true",
			})

			deployment.Spec.Template.Spec.TopologySpreadConstraints = kubernetesutils.GetTopologySpreadConstraints(pointer.Int32Deref(r.values.Replicas, 0), pointer.Int32Deref(r.values.Replicas, 0), metav1.LabelSelector{MatchLabels: r.getDeploymentTemplateLabels()}, int32(len(r.values.Zones)), nil)

			// ATTENTION: THIS MUST BE THE LAST THING HAPPENING IN THIS FUNCTION TO MAKE SURE THE COMPUTED CHECKSUM IS
			// ACCURATE!
			// TODO(timuthy): Remove this workaround once the Kubernetes MatchLabelKeysInPodTopologySpread feature gate is beta
			//  and enabled by default (probably 1.26+) for all supported clusters.
			{
				// Assign a predictable but unique label value per ReplicaSet which can be used for the
				// Topology Spread Constraint selectors to prevent imbalanced deployments after rolling-updates.
				// See https://github.com/kubernetes/kubernetes/issues/98215 for more information.
				// This must be done as a last step because we need to consider that the pod topology constraints themselves
				// can change and cause a rolling update.
				podTemplateChecksum := utils.ComputeChecksum(deployment.Spec.Template)[:16]

				deployment.Spec.Template.Labels[labelChecksum] = podTemplateChecksum
				for i := range deployment.Spec.Template.Spec.TopologySpreadConstraints {
					deployment.Spec.Template.Spec.TopologySpreadConstraints[i].LabelSelector.MatchLabels[labelChecksum] = podTemplateChecksum
				}
			}
		}

		return nil
	})
	return err
}

func (r *resourceManager) emptyDeployment() *appsv1.Deployment {
	return &appsv1.Deployment{ObjectMeta: metav1.ObjectMeta{Name: v1beta1constants.DeploymentNameGardenerResourceManager, Namespace: r.namespace}}
}

func (r *resourceManager) ensureServiceAccount(ctx context.Context) error {
	serviceAccount := r.emptyServiceAccount()
	_, err := controllerutils.GetAndCreateOrMergePatch(ctx, r.client, serviceAccount, func() error {
		serviceAccount.Labels = r.getLabels()
		serviceAccount.AutomountServiceAccountToken = pointer.Bool(false)
		return nil
	})
	return err
}

func (r *resourceManager) emptyServiceAccount() *corev1.ServiceAccount {
	return &corev1.ServiceAccount{ObjectMeta: metav1.ObjectMeta{Name: serviceAccountName, Namespace: r.namespace}}
}

func (r *resourceManager) ensureVPA(ctx context.Context) error {
	vpa := r.emptyVPA()
	vpaUpdateMode := vpaautoscalingv1.UpdateModeAuto
	controlledValues := vpaautoscalingv1.ContainerControlledValuesRequestsOnly

	_, err := controllerutils.GetAndCreateOrMergePatch(ctx, r.client, vpa, func() error {
		vpa.Labels = r.getLabels()
		vpa.Spec.TargetRef = &autoscalingv1.CrossVersionObjectReference{
			APIVersion: appsv1.SchemeGroupVersion.String(),
			Kind:       "Deployment",
			Name:       v1beta1constants.DeploymentNameGardenerResourceManager,
		}
		vpa.Spec.UpdatePolicy = &vpaautoscalingv1.PodUpdatePolicy{
			UpdateMode: &vpaUpdateMode,
		}
		vpa.Spec.ResourcePolicy = &vpaautoscalingv1.PodResourcePolicy{
			ContainerPolicies: []vpaautoscalingv1.ContainerResourcePolicy{
				{
					ContainerName: vpaautoscalingv1.DefaultContainerResourcePolicy,
					MinAllowed:    r.values.VPA.MinAllowed,
					MaxAllowed: corev1.ResourceList{
						corev1.ResourceCPU:    resource.MustParse("4"),
						corev1.ResourceMemory: resource.MustParse("10G"),
					},
					ControlledValues: &controlledValues,
				},
			},
		}
		return nil
	})
	return err
}

func (r *resourceManager) emptyVPA() *vpaautoscalingv1.VerticalPodAutoscaler {
	return &vpaautoscalingv1.VerticalPodAutoscaler{ObjectMeta: metav1.ObjectMeta{Name: "gardener-resource-manager-vpa", Namespace: r.namespace}}
}

func (r *resourceManager) ensurePodDisruptionBudget(ctx context.Context) error {
	obj := r.emptyPodDisruptionBudget()

	pdbSelector := &metav1.LabelSelector{
		MatchLabels: r.getDeploymentTemplateLabels(),
	}
	maxUnavailable := intstr.FromInt(1)

	_, err := controllerutils.GetAndCreateOrMergePatch(ctx, r.client, obj, func() error {
		switch pdb := obj.(type) {
		case *policyv1.PodDisruptionBudget:
			pdb.Labels = r.getLabels()
			pdb.Spec = policyv1.PodDisruptionBudgetSpec{
				MaxUnavailable: &maxUnavailable,
				Selector:       pdbSelector,
			}
		case *policyv1beta1.PodDisruptionBudget:
			pdb.Labels = r.getLabels()
			pdb.Spec = policyv1beta1.PodDisruptionBudgetSpec{
				MaxUnavailable: &maxUnavailable,
				Selector:       pdbSelector,
			}
		}
		return nil
	})

	return err
}

func (r *resourceManager) emptyPodDisruptionBudget() client.Object {
	pdbObjectMeta := metav1.ObjectMeta{
		Name:      "gardener-resource-manager",
		Namespace: r.namespace,
	}

	if version.ConstraintK8sGreaterEqual121.Check(r.values.KubernetesVersion) {
		return &policyv1.PodDisruptionBudget{
			ObjectMeta: pdbObjectMeta,
		}
	}
	return &policyv1beta1.PodDisruptionBudget{
		ObjectMeta: pdbObjectMeta,
	}
}

func (r *resourceManager) ensureMutatingWebhookConfiguration(ctx context.Context) error {
	if SkipWebhookDeployment {
		return nil
	}

	mutatingWebhookConfiguration := r.emptyMutatingWebhookConfiguration()

	secretServerCA, found := r.secretsManager.Get(r.values.SecretNameServerCA)
	if !found {
		return fmt.Errorf("secret %q not found", r.values.SecretNameServerCA)
	}

	_, err := controllerutils.GetAndCreateOrMergePatch(ctx, r.client, mutatingWebhookConfiguration, func() error {
		mutatingWebhookConfiguration.Labels = utils.MergeStringMaps(appLabel(), map[string]string{
			v1beta1constants.LabelExcludeWebhookFromRemediation: "true",
		})
		mutatingWebhookConfiguration.Webhooks = r.getMutatingWebhookConfigurationWebhooks(secretServerCA, r.buildWebhookClientConfig)
		return nil
	})
	return err
}

func (r *resourceManager) emptyMutatingWebhookConfiguration() *admissionregistrationv1.MutatingWebhookConfiguration {
	suffix := ""
	if r.values.TargetDiffersFromSourceCluster {
		suffix = "-shoot"
	}
	return &admissionregistrationv1.MutatingWebhookConfiguration{ObjectMeta: metav1.ObjectMeta{Name: "gardener-resource-manager" + suffix, Namespace: r.namespace}}
}

func (r *resourceManager) ensureValidatingWebhookConfiguration(ctx context.Context) error {
	if SkipWebhookDeployment {
		return nil
	}

	validatingWebhookConfiguration := r.emptyValidatingWebhookConfiguration()

	secretServerCA, found := r.secretsManager.Get(r.values.SecretNameServerCA)
	if !found {
		return fmt.Errorf("secret %q not found", r.values.SecretNameServerCA)
	}

	_, err := controllerutils.GetAndCreateOrMergePatch(ctx, r.client, validatingWebhookConfiguration, func() error {
		validatingWebhookConfiguration.Labels = utils.MergeStringMaps(appLabel(), map[string]string{
			v1beta1constants.LabelExcludeWebhookFromRemediation: "true",
		})
		validatingWebhookConfiguration.Webhooks = r.getValidatingWebhookConfigurationWebhooks(secretServerCA, r.buildWebhookClientConfig)
		return nil
	})
	return err
}

func (r *resourceManager) emptyValidatingWebhookConfiguration() *admissionregistrationv1.ValidatingWebhookConfiguration {
	return &admissionregistrationv1.ValidatingWebhookConfiguration{ObjectMeta: metav1.ObjectMeta{Name: "gardener-resource-manager", Namespace: r.namespace}}
}

func (r *resourceManager) ensureShootResources(ctx context.Context) error {
	secretServerCA, found := r.secretsManager.Get(r.values.SecretNameServerCA)
	if !found {
		return fmt.Errorf("secret %q not found", r.values.SecretNameServerCA)
	}

	var (
		registry = managedresources.NewRegistry(kubernetes.ShootScheme, kubernetes.ShootCodec, kubernetes.ShootSerializer)

		mutatingWebhookConfiguration = r.emptyMutatingWebhookConfiguration()

		clusterRoleBinding = &rbacv1.ClusterRoleBinding{
			ObjectMeta: metav1.ObjectMeta{
				Name:        "gardener.cloud:target:resource-manager",
				Annotations: map[string]string{resourcesv1alpha1.KeepObject: "true"},
			},
			RoleRef: rbacv1.RoleRef{
				APIGroup: rbacv1.GroupName,
				Kind:     "ClusterRole",
				Name:     "cluster-admin",
			},
			Subjects: []rbacv1.Subject{{
				Kind:      rbacv1.ServiceAccountKind,
				Name:      r.secrets.shootAccess.ServiceAccountName,
				Namespace: metav1.NamespaceSystem,
			}},
		}
	)

	mutatingWebhookConfiguration.Labels = appLabel()
	mutatingWebhookConfiguration.Webhooks = r.getMutatingWebhookConfigurationWebhooks(secretServerCA, r.buildWebhookClientConfig)

	data, err := registry.AddAllAndSerialize(
		mutatingWebhookConfiguration,
		clusterRoleBinding,
	)
	if err != nil {
		return err
	}

	return managedresources.CreateForShoot(ctx, r.client, r.namespace, ManagedResourceName, managedresources.LabelValueGardener, false, data)
}

func (r *resourceManager) newShootAccessSecret() *gardenerutils.ShootAccessSecret {
	return gardenerutils.NewShootAccessSecret(SecretNameShootAccess, r.namespace)
}

func (r *resourceManager) getMutatingWebhookConfigurationWebhooks(
	secretServerCA *corev1.Secret,
	buildClientConfigFn func(*corev1.Secret, string) admissionregistrationv1.WebhookClientConfig,
) []admissionregistrationv1.MutatingWebhook {
	var (
		namespaceSelector = r.buildWebhookNamespaceSelector()
		objectSelector    *metav1.LabelSelector
	)

	if r.values.TargetDiffersFromSourceCluster {
		objectSelector = &metav1.LabelSelector{
			MatchLabels: map[string]string{
				resourcesv1alpha1.ManagedBy: resourcesv1alpha1.GardenerManager,
			},
		}
	}

	webhooks := []admissionregistrationv1.MutatingWebhook{
		GetTokenInvalidatorMutatingWebhook(namespaceSelector, secretServerCA, buildClientConfigFn),
		getProjectedTokenMountMutatingWebhook(namespaceSelector, secretServerCA, buildClientConfigFn),
		GetHighAvailabilityConfigMutatingWebhook(namespaceSelector, objectSelector, secretServerCA, buildClientConfigFn),
	}

	if r.values.SchedulingProfile != nil && *r.values.SchedulingProfile == gardencorev1beta1.SchedulingProfileBinPacking {
		// pod scheduler name webhook should be active on all namespaces
		webhooks = append(webhooks, GetPodSchedulerNameMutatingWebhook(&metav1.LabelSelector{}, secretServerCA, buildClientConfigFn))
	}

	if r.values.DefaultSeccompProfileEnabled {
		webhooks = append(webhooks, GetSeccompProfileMutatingWebhook(namespaceSelector, secretServerCA, buildClientConfigFn))
	}

	if r.values.TargetDiffersFromSourceCluster {
		webhooks = append(webhooks, GetSystemComponentsConfigMutatingWebhook(namespaceSelector, objectSelector, secretServerCA, buildClientConfigFn))
	}

	if r.values.EndpointSliceHintsEnabled {
		webhooks = append(webhooks, GetEndpointSliceHintsMutatingWebhook(namespaceSelector, secretServerCA, buildClientConfigFn))
	}

	if r.values.PodTopologySpreadConstraintsEnabled {
		webhooks = append(webhooks, GetPodTopologySpreadConstraintsMutatingWebhook(namespaceSelector, objectSelector, secretServerCA, buildClientConfigFn))
	}

	return webhooks
}

func (r *resourceManager) getValidatingWebhookConfigurationWebhooks(
	secretServerCA *corev1.Secret,
	buildClientConfigFn func(*corev1.Secret, string) admissionregistrationv1.WebhookClientConfig,
) []admissionregistrationv1.ValidatingWebhook {
	return append(
		GetCRDDeletionProtectionValidatingWebhooks(secretServerCA, buildClientConfigFn),
		GetExtensionValidationValidatingWebhooks(secretServerCA, buildClientConfigFn)...,
	)
}

// GetTokenInvalidatorMutatingWebhook returns the token-invalidator mutating webhook for the resourcemanager component for reuse
// between the component and integration tests.
func GetTokenInvalidatorMutatingWebhook(namespaceSelector *metav1.LabelSelector, secretServerCA *corev1.Secret, buildClientConfigFn func(*corev1.Secret, string) admissionregistrationv1.WebhookClientConfig) admissionregistrationv1.MutatingWebhook {
	var (
		failurePolicy = admissionregistrationv1.Fail
		matchPolicy   = admissionregistrationv1.Exact
		sideEffect    = admissionregistrationv1.SideEffectClassNone
	)

	return admissionregistrationv1.MutatingWebhook{
		Name: "token-invalidator.resources.gardener.cloud",
		Rules: []admissionregistrationv1.RuleWithOperations{{
			Rule: admissionregistrationv1.Rule{
				APIGroups:   []string{corev1.GroupName},
				APIVersions: []string{corev1.SchemeGroupVersion.Version},
				Resources:   []string{"secrets"},
			},
			Operations: []admissionregistrationv1.OperationType{
				admissionregistrationv1.Create,
				admissionregistrationv1.Update,
			},
		}},
		NamespaceSelector: namespaceSelector,
		ObjectSelector: &metav1.LabelSelector{
			MatchLabels: map[string]string{resourcesv1alpha1.ResourceManagerPurpose: resourcesv1alpha1.LabelPurposeTokenInvalidation},
		},
		ClientConfig:            buildClientConfigFn(secretServerCA, tokeninvalidator.WebhookPath),
		AdmissionReviewVersions: []string{admissionv1beta1.SchemeGroupVersion.Version, admissionv1.SchemeGroupVersion.Version},
		FailurePolicy:           &failurePolicy,
		MatchPolicy:             &matchPolicy,
		SideEffects:             &sideEffect,
		TimeoutSeconds:          pointer.Int32(10),
	}
}

// GetCRDDeletionProtectionValidatingWebhooks returns the ValidatingWebhooks for the crd-deletion-protection webhook for
// reuse between the component and integration tests.
func GetCRDDeletionProtectionValidatingWebhooks(secretServerCA *corev1.Secret, buildClientConfigFn func(*corev1.Secret, string) admissionregistrationv1.WebhookClientConfig) []admissionregistrationv1.ValidatingWebhook {
	var (
		failurePolicy = admissionregistrationv1.Fail
		matchPolicy   = admissionregistrationv1.Exact
		sideEffect    = admissionregistrationv1.SideEffectClassNone
	)

	return []admissionregistrationv1.ValidatingWebhook{
		{
			Name: "crd-deletion-protection.resources.gardener.cloud",
			Rules: []admissionregistrationv1.RuleWithOperations{{
				Rule: admissionregistrationv1.Rule{
					APIGroups:   []string{apiextensionsv1.GroupName},
					APIVersions: []string{apiextensionsv1beta1.SchemeGroupVersion.Version, apiextensionsv1.SchemeGroupVersion.Version},
					Resources:   []string{"customresourcedefinitions"},
				},
				Operations: []admissionregistrationv1.OperationType{admissionregistrationv1.Delete},
			}},
			FailurePolicy:           &failurePolicy,
			NamespaceSelector:       &metav1.LabelSelector{},
			ObjectSelector:          &metav1.LabelSelector{MatchLabels: crddeletionprotection.ObjectSelector},
			ClientConfig:            buildClientConfigFn(secretServerCA, crddeletionprotection.WebhookPath),
			AdmissionReviewVersions: []string{admissionv1beta1.SchemeGroupVersion.Version, admissionv1.SchemeGroupVersion.Version},
			MatchPolicy:             &matchPolicy,
			SideEffects:             &sideEffect,
			TimeoutSeconds:          pointer.Int32(10),
		},
		{
			Name: "cr-deletion-protection.resources.gardener.cloud",
			Rules: []admissionregistrationv1.RuleWithOperations{
				{
					Rule: admissionregistrationv1.Rule{
						APIGroups:   []string{druidv1alpha1.GroupVersion.Group},
						APIVersions: []string{druidv1alpha1.GroupVersion.Version},
						Resources: []string{
							"etcds",
						},
					},
					Operations: []admissionregistrationv1.OperationType{admissionregistrationv1.Delete},
				},
				{
					Rule: admissionregistrationv1.Rule{
						APIGroups:   []string{extensionsv1alpha1.SchemeGroupVersion.Group},
						APIVersions: []string{extensionsv1alpha1.SchemeGroupVersion.Version},
						Resources: []string{
							"backupbuckets",
							"backupentries",
							"bastions",
							"containerruntimes",
							"controlplanes",
							"dnsrecords",
							"extensions",
							"infrastructures",
							"networks",
							"operatingsystemconfigs",
							"workers",
						},
					},
					Operations: []admissionregistrationv1.OperationType{admissionregistrationv1.Delete},
				},
			},
			FailurePolicy:           &failurePolicy,
			NamespaceSelector:       &metav1.LabelSelector{},
			ClientConfig:            buildClientConfigFn(secretServerCA, crddeletionprotection.WebhookPath),
			AdmissionReviewVersions: []string{admissionv1beta1.SchemeGroupVersion.Version, admissionv1.SchemeGroupVersion.Version},
			MatchPolicy:             &matchPolicy,
			SideEffects:             &sideEffect,
			TimeoutSeconds:          pointer.Int32(10),
		},
	}
}

// GetExtensionValidationValidatingWebhooks returns the ValidatingWebhooks for the crd-deletion-protection webhook for
// reuse between the component and integration tests.
func GetExtensionValidationValidatingWebhooks(secretServerCA *corev1.Secret, buildClientConfigFn func(*corev1.Secret, string) admissionregistrationv1.WebhookClientConfig) []admissionregistrationv1.ValidatingWebhook {
	var (
		failurePolicy = admissionregistrationv1.Fail
		matchPolicy   = admissionregistrationv1.Exact
		sideEffect    = admissionregistrationv1.SideEffectClassNone
		webhooks      []admissionregistrationv1.ValidatingWebhook
	)

	for _, webhook := range []struct {
		resource string
		path     string
		rule     admissionregistrationv1.Rule
	}{
		{
			resource: "backupbuckets",
			rule: admissionregistrationv1.Rule{
				APIGroups:   []string{extensionsv1alpha1.SchemeGroupVersion.Group},
				APIVersions: []string{extensionsv1alpha1.SchemeGroupVersion.Version},
				Resources:   []string{"backupbuckets"},
			},
			path: extensionvalidation.WebhookPathBackupBucket,
		},
		{
			resource: "backupentries",
			rule: admissionregistrationv1.Rule{
				APIGroups:   []string{extensionsv1alpha1.SchemeGroupVersion.Group},
				APIVersions: []string{extensionsv1alpha1.SchemeGroupVersion.Version},
				Resources:   []string{"backupentries"},
			},
			path: extensionvalidation.WebhookPathBackupEntry,
		},
		{
			resource: "bastions",
			rule: admissionregistrationv1.Rule{
				APIGroups:   []string{extensionsv1alpha1.SchemeGroupVersion.Group},
				APIVersions: []string{extensionsv1alpha1.SchemeGroupVersion.Version},
				Resources:   []string{"bastions"},
			},
			path: extensionvalidation.WebhookPathBastion,
		},
		{
			resource: "containerruntimes",
			rule: admissionregistrationv1.Rule{
				APIGroups:   []string{extensionsv1alpha1.SchemeGroupVersion.Group},
				APIVersions: []string{extensionsv1alpha1.SchemeGroupVersion.Version},
				Resources:   []string{"containerruntimes"},
			},
			path: extensionvalidation.WebhookPathContainerRuntime,
		},
		{
			resource: "controlplanes",
			rule: admissionregistrationv1.Rule{
				APIGroups:   []string{extensionsv1alpha1.SchemeGroupVersion.Group},
				APIVersions: []string{extensionsv1alpha1.SchemeGroupVersion.Version},
				Resources:   []string{"controlplanes"},
			},
			path: extensionvalidation.WebhookPathControlPlane,
		},
		{
			resource: "dnsrecords",
			rule: admissionregistrationv1.Rule{
				APIGroups:   []string{extensionsv1alpha1.SchemeGroupVersion.Group},
				APIVersions: []string{extensionsv1alpha1.SchemeGroupVersion.Version},
				Resources:   []string{"dnsrecords"},
			},
			path: extensionvalidation.WebhookPathDNSRecord,
		},
		{
			resource: "etcds",
			rule: admissionregistrationv1.Rule{
				APIGroups:   []string{druidv1alpha1.GroupVersion.Group},
				APIVersions: []string{druidv1alpha1.GroupVersion.Version},
				Resources:   []string{"etcds"},
			},
			path: extensionvalidation.WebhookPathEtcd,
		},
		{
			resource: "extensions",
			rule: admissionregistrationv1.Rule{
				APIGroups:   []string{extensionsv1alpha1.SchemeGroupVersion.Group},
				APIVersions: []string{extensionsv1alpha1.SchemeGroupVersion.Version},
				Resources:   []string{"extensions"},
			},
			path: extensionvalidation.WebhookPathExtension,
		},
		{
			resource: "infrastructures",
			rule: admissionregistrationv1.Rule{
				APIGroups:   []string{extensionsv1alpha1.SchemeGroupVersion.Group},
				APIVersions: []string{extensionsv1alpha1.SchemeGroupVersion.Version},
				Resources:   []string{"infrastructures"},
			},
			path: extensionvalidation.WebhookPathInfrastructure,
		},
		{
			resource: "networks",
			rule: admissionregistrationv1.Rule{
				APIGroups:   []string{extensionsv1alpha1.SchemeGroupVersion.Group},
				APIVersions: []string{extensionsv1alpha1.SchemeGroupVersion.Version},
				Resources:   []string{"networks"},
			},
			path: extensionvalidation.WebhookPathNetwork,
		},
		{
			resource: "operatingsystemconfigs",
			rule: admissionregistrationv1.Rule{
				APIGroups:   []string{extensionsv1alpha1.SchemeGroupVersion.Group},
				APIVersions: []string{extensionsv1alpha1.SchemeGroupVersion.Version},
				Resources:   []string{"operatingsystemconfigs"},
			},
			path: extensionvalidation.WebhookPathOperatingSystemConfig,
		},
		{
			resource: "workers",
			rule: admissionregistrationv1.Rule{
				APIGroups:   []string{extensionsv1alpha1.SchemeGroupVersion.Group},
				APIVersions: []string{extensionsv1alpha1.SchemeGroupVersion.Version},
				Resources:   []string{"workers"},
			},
			path: extensionvalidation.WebhookPathWorker,
		},
	} {
		webhooks = append(webhooks, admissionregistrationv1.ValidatingWebhook{
			Name: "validation.extensions." + webhook.resource + ".resources.gardener.cloud",
			Rules: []admissionregistrationv1.RuleWithOperations{
				{
					Rule:       webhook.rule,
					Operations: []admissionregistrationv1.OperationType{admissionregistrationv1.Create, admissionregistrationv1.Update},
				},
			},
			FailurePolicy:           &failurePolicy,
			NamespaceSelector:       &metav1.LabelSelector{},
			ClientConfig:            buildClientConfigFn(secretServerCA, webhook.path),
			AdmissionReviewVersions: []string{admissionv1beta1.SchemeGroupVersion.Version, admissionv1.SchemeGroupVersion.Version},
			MatchPolicy:             &matchPolicy,
			SideEffects:             &sideEffect,
			TimeoutSeconds:          pointer.Int32(10),
		})
	}

	return webhooks
}

func getProjectedTokenMountMutatingWebhook(namespaceSelector *metav1.LabelSelector, secretServerCA *corev1.Secret, buildClientConfigFn func(*corev1.Secret, string) admissionregistrationv1.WebhookClientConfig) admissionregistrationv1.MutatingWebhook {
	var (
		failurePolicy = admissionregistrationv1.Fail
		matchPolicy   = admissionregistrationv1.Exact
		sideEffect    = admissionregistrationv1.SideEffectClassNone
	)

	return admissionregistrationv1.MutatingWebhook{
		Name: "projected-token-mount.resources.gardener.cloud",
		Rules: []admissionregistrationv1.RuleWithOperations{{
			Rule: admissionregistrationv1.Rule{
				APIGroups:   []string{corev1.GroupName},
				APIVersions: []string{corev1.SchemeGroupVersion.Version},
				Resources:   []string{"pods"},
			},
			Operations: []admissionregistrationv1.OperationType{admissionregistrationv1.Create},
		}},
		NamespaceSelector: namespaceSelector,
		ObjectSelector: &metav1.LabelSelector{
			MatchExpressions: []metav1.LabelSelectorRequirement{
				{
					Key:      resourcesv1alpha1.ProjectedTokenSkip,
					Operator: metav1.LabelSelectorOpDoesNotExist,
				},
				{
					Key:      v1beta1constants.LabelApp,
					Operator: metav1.LabelSelectorOpNotIn,
					Values:   []string{LabelValue},
				},
			},
		},
		ClientConfig:            buildClientConfigFn(secretServerCA, projectedtokenmount.WebhookPath),
		AdmissionReviewVersions: []string{admissionv1beta1.SchemeGroupVersion.Version, admissionv1.SchemeGroupVersion.Version},
		FailurePolicy:           &failurePolicy,
		MatchPolicy:             &matchPolicy,
		SideEffects:             &sideEffect,
		TimeoutSeconds:          pointer.Int32(10),
	}
}

// GetPodSchedulerNameMutatingWebhook returns the pod-scheduler-name1 mutating webhook for the resourcemanager component for reuse
// between the component and integration tests.
func GetPodSchedulerNameMutatingWebhook(namespaceSelector *metav1.LabelSelector, secretServerCA *corev1.Secret, buildClientConfigFn func(*corev1.Secret, string) admissionregistrationv1.WebhookClientConfig) admissionregistrationv1.MutatingWebhook {
	var (
		failurePolicy = admissionregistrationv1.Ignore
		matchPolicy   = admissionregistrationv1.Exact
		sideEffect    = admissionregistrationv1.SideEffectClassNone
	)

	return admissionregistrationv1.MutatingWebhook{
		Name: "pod-scheduler-name.resources.gardener.cloud",
		Rules: []admissionregistrationv1.RuleWithOperations{{
			Rule: admissionregistrationv1.Rule{
				APIGroups:   []string{corev1.GroupName},
				APIVersions: []string{corev1.SchemeGroupVersion.Version},
				Resources:   []string{"pods"},
			},
			Operations: []admissionregistrationv1.OperationType{admissionregistrationv1.Create},
		}},
		NamespaceSelector:       namespaceSelector,
		ObjectSelector:          &metav1.LabelSelector{},
		ClientConfig:            buildClientConfigFn(secretServerCA, podschedulername.WebhookPath),
		AdmissionReviewVersions: []string{admissionv1beta1.SchemeGroupVersion.Version, admissionv1.SchemeGroupVersion.Version},
		FailurePolicy:           &failurePolicy,
		MatchPolicy:             &matchPolicy,
		SideEffects:             &sideEffect,
		TimeoutSeconds:          pointer.Int32(10),
	}
}

// GetPodTopologySpreadConstraintsMutatingWebhook returns the TSC mutating webhook for the resourcemanager component for reuse
// between the component and integration tests.
func GetPodTopologySpreadConstraintsMutatingWebhook(
	namespaceSelector *metav1.LabelSelector,
	objectSelector *metav1.LabelSelector,
	secretServerCA *corev1.Secret,
	buildClientConfigFn func(*corev1.Secret, string) admissionregistrationv1.WebhookClientConfig,
) admissionregistrationv1.MutatingWebhook {
	var (
		failurePolicy = admissionregistrationv1.Fail
		matchPolicy   = admissionregistrationv1.Exact
		sideEffect    = admissionregistrationv1.SideEffectClassNone
	)

	oSelector := &metav1.LabelSelector{}
	if objectSelector != nil {
		oSelector = objectSelector.DeepCopy()
	}
	oSelector.MatchExpressions = append(oSelector.MatchExpressions,
		// Don't apply the webhook to GRM as it would block itself when the change is rolled out
		// or when scaled up from 0 replicas.
		metav1.LabelSelectorRequirement{
			Key:      v1beta1constants.LabelApp,
			Operator: metav1.LabelSelectorOpNotIn,
			Values:   []string{LabelValue},
		},
		metav1.LabelSelectorRequirement{
			Key:      resourcesv1alpha1.PodTopologySpreadConstraintsSkip,
			Operator: metav1.LabelSelectorOpDoesNotExist,
		},
	)

	return admissionregistrationv1.MutatingWebhook{
		Name: "pod-topology-spread-constraints.resources.gardener.cloud",
		Rules: []admissionregistrationv1.RuleWithOperations{{
			Rule: admissionregistrationv1.Rule{
				APIGroups:   []string{corev1.GroupName},
				APIVersions: []string{corev1.SchemeGroupVersion.Version},
				Resources:   []string{"pods"},
			},
			Operations: []admissionregistrationv1.OperationType{admissionregistrationv1.Create},
		}},
		NamespaceSelector:       namespaceSelector,
		ObjectSelector:          oSelector,
		ClientConfig:            buildClientConfigFn(secretServerCA, podtopologyspreadconstraints.WebhookPath),
		AdmissionReviewVersions: []string{admissionv1beta1.SchemeGroupVersion.Version, admissionv1.SchemeGroupVersion.Version},
		FailurePolicy:           &failurePolicy,
		MatchPolicy:             &matchPolicy,
		SideEffects:             &sideEffect,
		TimeoutSeconds:          pointer.Int32(10),
	}
}

// GetSeccompProfileMutatingWebhook returns the seccomp-profile mutating webhook for the resourcemanager component for reuse
// between the component and integration tests.
func GetSeccompProfileMutatingWebhook(
	namespaceSelector *metav1.LabelSelector,
	secretServerCA *corev1.Secret,
	buildClientConfigFn func(*corev1.Secret, string) admissionregistrationv1.WebhookClientConfig,
) admissionregistrationv1.MutatingWebhook {
	var (
		failurePolicy = admissionregistrationv1.Fail
		matchPolicy   = admissionregistrationv1.Exact
		sideEffect    = admissionregistrationv1.SideEffectClassNone
	)

	return admissionregistrationv1.MutatingWebhook{
		Name: "seccomp-profile.resources.gardener.cloud",
		Rules: []admissionregistrationv1.RuleWithOperations{{
			Rule: admissionregistrationv1.Rule{
				APIGroups:   []string{corev1.GroupName},
				APIVersions: []string{corev1.SchemeGroupVersion.Version},
				Resources:   []string{"pods"},
			},
			Operations: []admissionregistrationv1.OperationType{admissionregistrationv1.Create},
		}},
		NamespaceSelector: namespaceSelector,
		ObjectSelector: &metav1.LabelSelector{
			MatchExpressions: []metav1.LabelSelectorRequirement{
				{
					Key:      resourcesv1alpha1.SeccompProfileSkip,
					Operator: metav1.LabelSelectorOpDoesNotExist,
				},
				{
					Key:      v1beta1constants.LabelApp,
					Operator: metav1.LabelSelectorOpNotIn,
					Values:   []string{LabelValue},
				},
			},
		},
		ClientConfig:            buildClientConfigFn(secretServerCA, seccompprofile.WebhookPath),
		AdmissionReviewVersions: []string{admissionv1beta1.SchemeGroupVersion.Version, admissionv1.SchemeGroupVersion.Version},
		FailurePolicy:           &failurePolicy,
		MatchPolicy:             &matchPolicy,
		SideEffects:             &sideEffect,
		TimeoutSeconds:          pointer.Int32(10),
	}
}

// GetSystemComponentsConfigMutatingWebhook returns the system-components-config mutating webhook for the resourcemanager component for reuse
// between the component and integration tests.
func GetSystemComponentsConfigMutatingWebhook(namespaceSelector, objectSelector *metav1.LabelSelector, secretServerCA *corev1.Secret, buildClientConfigFn func(*corev1.Secret, string) admissionregistrationv1.WebhookClientConfig) admissionregistrationv1.MutatingWebhook {
	var (
		failurePolicy = admissionregistrationv1.Fail
		matchPolicy   = admissionregistrationv1.Exact
		sideEffect    = admissionregistrationv1.SideEffectClassNone
	)

	oSelector := &metav1.LabelSelector{}
	if objectSelector != nil {
		oSelector = objectSelector.DeepCopy()
	}
	oSelector.MatchExpressions = append(oSelector.MatchExpressions,
		metav1.LabelSelectorRequirement{
			Key:      resourcesv1alpha1.SystemComponentsConfigSkip,
			Operator: metav1.LabelSelectorOpDoesNotExist,
		},
	)

	return admissionregistrationv1.MutatingWebhook{
		Name: "system-components-config.resources.gardener.cloud",
		Rules: []admissionregistrationv1.RuleWithOperations{{
			Rule: admissionregistrationv1.Rule{
				APIGroups:   []string{corev1.GroupName},
				APIVersions: []string{corev1.SchemeGroupVersion.Version},
				Resources:   []string{"pods"},
			},
			Operations: []admissionregistrationv1.OperationType{
				admissionregistrationv1.Create,
			},
		}},
		NamespaceSelector:       namespaceSelector,
		ObjectSelector:          oSelector,
		ClientConfig:            buildClientConfigFn(secretServerCA, systemcomponentsconfig.WebhookPath),
		AdmissionReviewVersions: []string{admissionv1beta1.SchemeGroupVersion.Version, admissionv1.SchemeGroupVersion.Version},
		FailurePolicy:           &failurePolicy,
		MatchPolicy:             &matchPolicy,
		SideEffects:             &sideEffect,
		TimeoutSeconds:          pointer.Int32(10),
	}
}

// GetHighAvailabilityConfigMutatingWebhook returns the high-availability-config mutating webhook for the
// resourcemanager component for reuse between the component and integration tests.
func GetHighAvailabilityConfigMutatingWebhook(namespaceSelector, objectSelector *metav1.LabelSelector, secretServerCA *corev1.Secret, buildClientConfigFn func(*corev1.Secret, string) admissionregistrationv1.WebhookClientConfig) admissionregistrationv1.MutatingWebhook {
	var (
		failurePolicy = admissionregistrationv1.Fail
		matchPolicy   = admissionregistrationv1.Equivalent
		sideEffect    = admissionregistrationv1.SideEffectClassNone
	)

	nsSelector := &metav1.LabelSelector{}
	if namespaceSelector != nil {
		nsSelector = namespaceSelector.DeepCopy()
	}
	if nsSelector.MatchLabels == nil {
		nsSelector.MatchLabels = make(map[string]string, 1)
	}
	nsSelector.MatchLabels[resourcesv1alpha1.HighAvailabilityConfigConsider] = "true"

	oSelector := &metav1.LabelSelector{}
	if objectSelector != nil {
		oSelector = objectSelector.DeepCopy()
	}
	oSelector.MatchExpressions = append(oSelector.MatchExpressions, metav1.LabelSelectorRequirement{
		Key:      resourcesv1alpha1.HighAvailabilityConfigSkip,
		Operator: metav1.LabelSelectorOpDoesNotExist,
	})

	return admissionregistrationv1.MutatingWebhook{
		Name: "high-availability-config.resources.gardener.cloud",
		Rules: []admissionregistrationv1.RuleWithOperations{
			{
				Rule: admissionregistrationv1.Rule{
					APIGroups:   []string{appsv1.GroupName},
					APIVersions: []string{appsv1.SchemeGroupVersion.Version},
					Resources:   []string{"deployments", "statefulsets"},
				},
				Operations: []admissionregistrationv1.OperationType{
					admissionregistrationv1.Create,
					admissionregistrationv1.Update,
				},
			},
			{
				Rule: admissionregistrationv1.Rule{
					APIGroups:   []string{autoscalingv2.GroupName},
					APIVersions: []string{autoscalingv2beta1.SchemeGroupVersion.Version, autoscalingv2.SchemeGroupVersion.Version},
					Resources:   []string{"horizontalpodautoscalers"},
				},
				Operations: []admissionregistrationv1.OperationType{
					admissionregistrationv1.Create,
					admissionregistrationv1.Update,
				},
			},
			{
				Rule: admissionregistrationv1.Rule{
					APIGroups:   []string{hvpav1alpha1.GroupName},
					APIVersions: []string{hvpav1alpha1.SchemeGroupVersionHvpa.Version},
					Resources:   []string{"hvpas"},
				},
				Operations: []admissionregistrationv1.OperationType{
					admissionregistrationv1.Create,
					admissionregistrationv1.Update,
				},
			},
		},
		NamespaceSelector:       nsSelector,
		ObjectSelector:          oSelector,
		ClientConfig:            buildClientConfigFn(secretServerCA, highavailabilityconfig.WebhookPath),
		AdmissionReviewVersions: []string{admissionv1beta1.SchemeGroupVersion.Version, admissionv1.SchemeGroupVersion.Version},
		FailurePolicy:           &failurePolicy,
		MatchPolicy:             &matchPolicy,
		SideEffects:             &sideEffect,
		TimeoutSeconds:          pointer.Int32(10),
	}
}

// GetEndpointSliceHintsMutatingWebhook returns the EndpointSlice hints mutating webhook for the resourcemanager component for reuse
// between the component and integration tests.
func GetEndpointSliceHintsMutatingWebhook(
	namespaceSelector *metav1.LabelSelector,
	secretServerCA *corev1.Secret,
	buildClientConfigFn func(*corev1.Secret, string) admissionregistrationv1.WebhookClientConfig,
) admissionregistrationv1.MutatingWebhook {
	var (
		failurePolicy = admissionregistrationv1.Fail
		matchPolicy   = admissionregistrationv1.Equivalent
		sideEffect    = admissionregistrationv1.SideEffectClassNone
	)

	return admissionregistrationv1.MutatingWebhook{
		Name: "endpoint-slice-hints.resources.gardener.cloud",
		Rules: []admissionregistrationv1.RuleWithOperations{{
			Rule: admissionregistrationv1.Rule{
				APIGroups:   []string{discoveryv1.GroupName},
				APIVersions: []string{discoveryv1.SchemeGroupVersion.Version},
				Resources:   []string{"endpointslices"},
			},
			Operations: []admissionregistrationv1.OperationType{
				admissionregistrationv1.Create,
				admissionregistrationv1.Update,
			},
		}},
		NamespaceSelector: namespaceSelector,
		ObjectSelector: &metav1.LabelSelector{
			MatchLabels: map[string]string{
				resourcesv1alpha1.EndpointSliceHintsConsider: "true",
			},
		},
		ClientConfig:            buildClientConfigFn(secretServerCA, endpointslicehints.WebhookPath),
		AdmissionReviewVersions: []string{admissionv1beta1.SchemeGroupVersion.Version, admissionv1.SchemeGroupVersion.Version},
		FailurePolicy:           &failurePolicy,
		MatchPolicy:             &matchPolicy,
		SideEffects:             &sideEffect,
		TimeoutSeconds:          pointer.Int32(10),
	}
}

func (r *resourceManager) buildWebhookNamespaceSelector() *metav1.LabelSelector {
	namespaceSelectorOperator := metav1.LabelSelectorOpIn
	if !r.values.TargetDiffersFromSourceCluster {
		namespaceSelectorOperator = metav1.LabelSelectorOpNotIn
	}

	return &metav1.LabelSelector{
		MatchExpressions: []metav1.LabelSelectorRequirement{{
			Key:      v1beta1constants.GardenerPurpose,
			Operator: namespaceSelectorOperator,
			Values:   []string{metav1.NamespaceSystem, "kubernetes-dashboard"},
		}},
	}
}

func (r *resourceManager) buildWebhookClientConfig(secretServerCA *corev1.Secret, path string) admissionregistrationv1.WebhookClientConfig {
	clientConfig := admissionregistrationv1.WebhookClientConfig{CABundle: secretServerCA.Data[secrets.DataKeyCertificateBundle]}

	if r.values.TargetDiffersFromSourceCluster {
		clientConfig.URL = pointer.String(fmt.Sprintf("https://%s.%s:%d%s", resourcemanagerconstants.ServiceName, r.namespace, serverServicePort, path))
	} else {
		clientConfig.Service = &admissionregistrationv1.ServiceReference{
			Name:      resourcemanagerconstants.ServiceName,
			Namespace: r.namespace,
			Path:      &path,
		}
	}

	return clientConfig
}

func (r *resourceManager) getLabels() map[string]string {
	if r.values.TargetDiffersFromSourceCluster {
		return utils.MergeStringMaps(appLabel(), map[string]string{
			v1beta1constants.GardenRole: v1beta1constants.GardenRoleControlPlane,
		})
	}

	return appLabel()
}

func (r *resourceManager) getDeploymentTemplateLabels() map[string]string {
	role := v1beta1constants.GardenRoleSeed
	if r.values.TargetDiffersFromSourceCluster {
		role = v1beta1constants.GardenRoleControlPlane
	}

	return utils.MergeStringMaps(appLabel(), map[string]string{
		v1beta1constants.GardenRole: role,
	})
}

func (r *resourceManager) getNetworkPolicyLabels() map[string]string {
	labels := map[string]string{
		v1beta1constants.LabelNetworkPolicyToDNS:              v1beta1constants.LabelNetworkPolicyAllowed,
		v1beta1constants.LabelNetworkPolicyToRuntimeAPIServer: v1beta1constants.LabelNetworkPolicyAllowed,
	}

	if r.values.TargetDiffersFromSourceCluster {
		labels[gardenerutils.NetworkPolicyLabel(v1beta1constants.DeploymentNameKubeAPIServer, kubeapiserverconstants.Port)] = v1beta1constants.LabelNetworkPolicyAllowed
	}

	return labels
}

func appLabel() map[string]string {
	return map[string]string{
		v1beta1constants.LabelApp: LabelValue,
	}
}

var (
	// IntervalWaitForDeployment is the interval used while waiting for the Deployments to become healthy
	// or deleted.
	IntervalWaitForDeployment = 5 * time.Second
	// TimeoutWaitForDeployment is the timeout used while waiting for the Deployments to become healthy
	// or deleted.
	TimeoutWaitForDeployment = 5 * time.Minute
	// Until is an alias for retry.Until. Exposed for tests.
	Until = retry.Until
)

// Wait signals whether a deployment is ready or needs more time to be deployed.
func (r *resourceManager) Wait(ctx context.Context) error {
	timeoutCtx, cancel := context.WithTimeout(ctx, TimeoutWaitForDeployment)
	defer cancel()

	return Until(timeoutCtx, IntervalWaitForDeployment, func(ctx context.Context) (done bool, err error) {
		deployment := r.emptyDeployment()
		if err := r.client.Get(ctx, client.ObjectKeyFromObject(deployment), deployment); err != nil {
			return retry.SevereError(err)
		}

		if err := health.CheckDeployment(deployment); err != nil {
			return retry.MinorError(err)
		}

		return retry.Ok()
	})
}

// WaitCleanup for destruction to finish and component to be fully removed. Gardener-Resource-manager does not need to wait for cleanup.
func (r *resourceManager) WaitCleanup(_ context.Context) error { return nil }

// GetReplicas returns Replicas field in the Values.
func (r *resourceManager) GetReplicas() *int32 { return r.values.Replicas }

// SetReplicas sets the Replicas field in the Values.
func (r *resourceManager) SetReplicas(replicas *int32) { r.values.Replicas = replicas }

// SetSecrets sets the secrets for the gardener-resource-manager.
func (r *resourceManager) SetSecrets(s Secrets) { r.secrets = s }

// GetValues returns the current configuration values of the deployer.
func (r *resourceManager) GetValues() Values { return r.values }

// Secrets is collection of secrets for the gardener-resource-manager.
type Secrets struct {
	// BootstrapKubeconfig is the kubeconfig of the gardener-resource-manager used during the bootstrapping process. Its
	// token requestor controller will request a JWT token for itself with this kubeconfig.
	BootstrapKubeconfig *component.Secret

	shootAccess *gardenerutils.ShootAccessSecret
}

func disableControllersAndWebhooksForWorkerlessShoot(config *resourcemanagerv1alpha1.ResourceManagerConfiguration) {
	// disable unneeded controllers
	config.Controllers.KubeletCSRApprover.Enabled = false
	config.Controllers.Node.Enabled = false

	// disable unneeded webhooks
	config.Webhooks.PodSchedulerName.Enabled = false
	config.Webhooks.SystemComponentsConfig.Enabled = false
	config.Webhooks.ProjectedTokenMount.Enabled = false
	config.Webhooks.HighAvailabilityConfig.Enabled = false
	config.Webhooks.PodTopologySpreadConstraints.Enabled = false
}
