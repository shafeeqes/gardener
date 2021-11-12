// Copyright (c) 2021 SAP SE or an SAP affiliate company. All rights reserved. This file is licensed under the Apache Software License, v. 2 except as noted otherwise in the LICENSE file
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

package vpnshoot

import (
	"context"
	"time"

	v1beta1constants "github.com/gardener/gardener/pkg/apis/core/v1beta1/constants"
	resourcesv1alpha1 "github.com/gardener/gardener/pkg/apis/resources/v1alpha1"
	"github.com/gardener/gardener/pkg/client/kubernetes"
	"github.com/gardener/gardener/pkg/operation/botanist/component"
	"github.com/gardener/gardener/pkg/operation/botanist/component/vpnseedserver"
	"github.com/gardener/gardener/pkg/resourcemanager/controller/garbagecollector/references"
	kutil "github.com/gardener/gardener/pkg/utils/kubernetes"
	"github.com/gardener/gardener/pkg/utils/managedresources"

	appsv1 "k8s.io/api/apps/v1"
	autoscalingv1 "k8s.io/api/autoscaling/v1"
	corev1 "k8s.io/api/core/v1"
	networkingv1 "k8s.io/api/networking/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/intstr"
	utilruntime "k8s.io/apimachinery/pkg/util/runtime"
	autoscalingv1beta2 "k8s.io/autoscaler/vertical-pod-autoscaler/pkg/apis/autoscaling.k8s.io/v1beta2"
	"k8s.io/utils/pointer"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

const (
	// LabelValue is the value of a label used for the identification of vpn-shoot pods.
	LabelValue = "vpn-shoot"
	// ManagedResourceName is the name of the ManagedResource containing the resource specifications.
	ManagedResourceName = "shoot-core-vpn-shoot"
	// SecretNameTLSAuth is a constant for the tls auth secret name.
	SecretNameTLSAuth = vpnseedserver.VpnSeedServerTLSAuth
	// SecretNameDH is a constant for the dh secret name.
	SecretNameDH = vpnseedserver.VpnSeedServerDH

	//TODO(shafeeqes): set the secret name properly
	// SecretName is the name of the shoot secret.
	SecretName = vpnseedserver.VpnShootSecretName

	// servicePort is the service port used for the VPN LoadBalancer.
	servicePort int32 = 4314
	// containerPort is the target port used for the VPN LoadBalancer.
	containerPort int32 = 1194
	//deploymentName is the name of the vpnShoot deployment
	deploymentName = "vpn-shoot"

	containerName       = "vpn-shoot"
	serviceName         = "vpn-test"
	volumeNameSecret    = "vpn-shoot"
	volumeNameSecretTLS = "vpn-shoot-tlsauth"
	volumeNameSecretDH  = "vpn-shoot-dh"

	volumeMountPathSecret    = "/srv/secrets/vpn-shoot"
	volumeMountPathSecretTLS = "/srv/secrets/tlsauth"
	volumeMountPathSecretDH  = "/srv/secrets/dh"
)

// Interface contains functions for a VPNShoot Deployer
type Interface interface {
	component.DeployWaiter
	component.MonitoringComponent
	// SetSecrets sets the secrets.
	SetSecrets(Secrets)
	SetPodAnnotations(map[string]string)
}

// Values is a set of configuration values for the VPNShoot component.
type Values struct {
	// Image is the container image used for vpnShoot.
	Image string
	// PodAnnotations is the set of additional annotations to be used for the pods.
	PodAnnotations map[string]string
	// vpaEnabled marks whether VerticalPodAutoscaler is enabled for the shoot
	VPAEnabled bool
	// reversedVPNEnabled marks whether ReversedVPN is enabled for the shoot
	ReversedVPNEnabled bool
	// PodNetworkCIDR is the CIDR of the pod network.
	PodNetworkCIDR string
	// ServiceNetworkCIDR is the CIDR of the node network.
	ServiceNetworkCIDR string
	// NodeNetworkCIDR is the CIDR of the node network.
	NodeNetworkCIDR string
	// ReversedVPNHeader is the header for the reversedVPN.
	ReversedVPNHeader string
	// ReversedVPNEndPoint is the end point for the reversedVPN.
	ReversedVPNEndPoint string
	// ReversedVPNOpenVPNPort is the port for the reversedVPN.
	ReversedVPNOpenVPNPort string
}

// New creates a new instance of DeployWaiter for vpnshoot
func New(
	client client.Client,
	namespace string,
	values Values,
) Interface {
	return &vpnShoot{
		client:    client,
		namespace: namespace,
		values:    values,
	}
}

type vpnShoot struct {
	client    client.Client
	namespace string
	values    Values
	secrets   Secrets
}

func (v *vpnShoot) Deploy(ctx context.Context) error {
	data, err := v.computeResourcesData()
	if err != nil {
		return err
	}
	return managedresources.CreateForShoot(ctx, v.client, v.namespace, ManagedResourceName, false, data)
}

func (v *vpnShoot) Destroy(ctx context.Context) error {
	return managedresources.DeleteForShoot(ctx, v.client, v.namespace, ManagedResourceName)
}

// TimeoutWaitForManagedResource is the timeout used while waiting for the ManagedResources to become healthy
// or deleted.
var TimeoutWaitForManagedResource = 2 * time.Minute

func (v *vpnShoot) Wait(ctx context.Context) error {
	timeoutCtx, cancel := context.WithTimeout(ctx, TimeoutWaitForManagedResource)
	defer cancel()

	return managedresources.WaitUntilHealthy(timeoutCtx, v.client, v.namespace, ManagedResourceName)
}

func (v *vpnShoot) WaitCleanup(ctx context.Context) error {
	timeoutCtx, cancel := context.WithTimeout(ctx, TimeoutWaitForManagedResource)
	defer cancel()

	return managedresources.WaitUntilDeleted(timeoutCtx, v.client, v.namespace, ManagedResourceName)
}

func (v *vpnShoot) SetSecrets(secrets Secrets) { v.secrets = secrets }

func (v *vpnShoot) computeResourcesData() (map[string][]byte, error) {

	var (
		registry = managedresources.NewRegistry(kubernetes.ShootScheme, kubernetes.ShootCodec, kubernetes.ShootSerializer)
		err      error

		secretTLSAuth = &corev1.Secret{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "vpn-shoot-tlsauth",
				Namespace: metav1.NamespaceSystem,
			},
			Type: corev1.SecretTypeOpaque,
			Data: v.secrets.TLSAuth.Data,
		}
		secretDH = &corev1.Secret{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "vpn-shoot-dh",
				Namespace: metav1.NamespaceSystem,
			},
			Type: corev1.SecretTypeOpaque,
			Data: v.secrets.DH.Data,
		}
		secret = &corev1.Secret{
			ObjectMeta: metav1.ObjectMeta{
				//TODO(shafeeqes): what about for ReversedVPN not enabled case?
				Name:      "vpn-shoot",
				Namespace: metav1.NamespaceSystem,
			},
			Type: corev1.SecretTypeOpaque,
			Data: v.secrets.Server.Data,
		}
	)

	utilruntime.Must(kutil.MakeUnique(secretTLSAuth))
	utilruntime.Must(kutil.MakeUnique(secretDH))
	utilruntime.Must(kutil.MakeUnique(secret))

	_, err = registry.AddAllAndSerialize(
		secret,
		secretDH,
		secretTLSAuth,
	)
	if err != nil {
		return nil, err
	}

	var (
		intStrMax  = intstr.FromString("100%")
		intStrZero = intstr.FromString("0%")

		vpa                *autoscalingv1beta2.VerticalPodAutoscaler
		service            *corev1.Service
		clusterRole        *rbacv1.ClusterRole
		clusterRoleBinding *rbacv1.ClusterRoleBinding

		serviceAccount = &corev1.ServiceAccount{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "vpn-shoot",
				Namespace: metav1.NamespaceSystem,
				Labels:    map[string]string{v1beta1constants.LabelApp: LabelValue},
			},
		}
		networkPolicy = &networkingv1.NetworkPolicy{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "gardener.cloud--allow-vpn",
				Namespace: metav1.NamespaceSystem,
				Annotations: map[string]string{
					v1beta1constants.GardenerDescription: "Allows the VPN to communicate with shoot components and makes the VPN reachable from the seed.",
				},
			},
			Spec: networkingv1.NetworkPolicySpec{
				PodSelector: metav1.LabelSelector{
					MatchLabels: map[string]string{v1beta1constants.LabelApp: LabelValue},
				},
				Egress:      []networkingv1.NetworkPolicyEgressRule{{}},
				Ingress:     []networkingv1.NetworkPolicyIngressRule{{}},
				PolicyTypes: []networkingv1.PolicyType{networkingv1.PolicyTypeEgress, networkingv1.PolicyTypeIngress},
			},
		}

		deployment = &appsv1.Deployment{
			ObjectMeta: metav1.ObjectMeta{
				Name:      deploymentName,
				Namespace: metav1.NamespaceSystem,
				Labels: map[string]string{
					v1beta1constants.GardenRole:     v1beta1constants.GardenRoleSystemComponent,
					v1beta1constants.LabelApp:       LabelValue,
					managedresources.LabelKeyOrigin: managedresources.LabelValueGardener,
				},
			},
			Spec: appsv1.DeploymentSpec{
				RevisionHistoryLimit: pointer.Int32(1),
				Replicas:             pointer.Int32(1),
				Strategy: appsv1.DeploymentStrategy{
					Type: appsv1.RollingUpdateDeploymentStrategyType,
					RollingUpdate: &appsv1.RollingUpdateDeployment{
						MaxSurge:       &intStrMax,
						MaxUnavailable: &intStrZero,
					},
				},
				Selector: &metav1.LabelSelector{
					MatchLabels: map[string]string{v1beta1constants.LabelApp: LabelValue},
				},
				Template: corev1.PodTemplateSpec{
					ObjectMeta: metav1.ObjectMeta{
						Annotations: v.values.PodAnnotations,
						Labels: map[string]string{
							v1beta1constants.GardenRole:     v1beta1constants.GardenRoleSystemComponent,
							v1beta1constants.LabelApp:       LabelValue,
							managedresources.LabelKeyOrigin: managedresources.LabelValueGardener,
							"type":                          "tunnel",
						},
					},
					Spec: corev1.PodSpec{
						AutomountServiceAccountToken: pointer.Bool(false),
						ServiceAccountName:           serviceAccount.Name,
						PriorityClassName:            "system-cluster-critical",
						DNSPolicy:                    corev1.DNSDefault,
						NodeSelector:                 map[string]string{v1beta1constants.LabelWorkerPoolSystemComponents: "true"},
						Tolerations: []corev1.Toleration{{
							Key:      "CriticalAddonsOnly",
							Operator: corev1.TolerationOpExists,
						}},
						Containers: []corev1.Container{
							{
								Name:            containerName,
								Image:           v.values.Image,
								ImagePullPolicy: corev1.PullIfNotPresent,
								Env:             getEnvVar(v),
								SecurityContext: &corev1.SecurityContext{
									Privileged: pointer.Bool(true),
									Capabilities: &corev1.Capabilities{
										Add: []corev1.Capability{"NET_ADMIN"},
									},
								},
								Resources: corev1.ResourceRequirements{
									Requests: corev1.ResourceList{
										corev1.ResourceCPU:    resource.MustParse("100m"),
										corev1.ResourceMemory: resource.MustParse("100Mi"),
									},
									Limits: getResourceLimits(v),
								},
								VolumeMounts: getVolumeMounts(v),
							},
						},
						Volumes: []corev1.Volume{
							{
								Name: volumeNameSecret,
								VolumeSource: corev1.VolumeSource{
									Secret: &corev1.SecretVolumeSource{
										SecretName:  secret.Name,
										DefaultMode: pointer.Int32(0400),
									},
								},
							},
							{
								Name: volumeNameSecret,
								VolumeSource: corev1.VolumeSource{
									Secret: &corev1.SecretVolumeSource{
										SecretName:  secretTLSAuth.Name,
										DefaultMode: pointer.Int32(0400),
									},
								},
							},
							{
								Name: volumeNameSecret,
								VolumeSource: corev1.VolumeSource{
									Secret: &corev1.SecretVolumeSource{
										SecretName:  secretDH.Name,
										DefaultMode: pointer.Int32(0400),
									},
								},
							},
						},
					},
				},
			},
		}
	)
	utilruntime.Must(references.InjectAnnotations(deployment))

	_, err = registry.AddAllAndSerialize(
		serviceAccount,
		networkPolicy,
		deployment,
	)

	if !v.values.ReversedVPNEnabled {
		service = &corev1.Service{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "vpn-shoot",
				Namespace: metav1.NamespaceSystem,
				Labels:    map[string]string{v1beta1constants.LabelApp: LabelValue},
			},
			Spec: corev1.ServiceSpec{
				Selector: map[string]string{v1beta1constants.LabelApp: LabelValue},
				Type:     corev1.ServiceTypeLoadBalancer,
				Ports: []corev1.ServicePort{
					{
						Name:       "openvpn",
						Port:       servicePort,
						TargetPort: intstr.FromInt(int(containerPort)),
						Protocol:   corev1.ProtocolTCP,
					},
				},
			},
		}
		clusterRole = &rbacv1.ClusterRole{
			ObjectMeta: metav1.ObjectMeta{
				Name: "system:gardener.cloud:vpn-seed",
			},
			Rules: []rbacv1.PolicyRule{
				{
					APIGroups:     []string{""},
					Resources:     []string{"services"},
					ResourceNames: []string{"vpn-shoot"},
					Verbs:         []string{"get"},
				},
			},
		}

		clusterRoleBinding = &rbacv1.ClusterRoleBinding{
			ObjectMeta: metav1.ObjectMeta{
				Name:        "system:gardener.cloud:vpn-seed",
				Annotations: map[string]string{resourcesv1alpha1.DeleteOnInvalidUpdate: "true"},
			},
			RoleRef: rbacv1.RoleRef{
				APIGroup: rbacv1.GroupName,
				Kind:     "ClusterRole",
				Name:     clusterRole.Name,
			},
			Subjects: []rbacv1.Subject{
				{
					Kind: rbacv1.UserKind,
					Name: "vpn-seed",
				},
			},
		}

		_, err = registry.AddAllAndSerialize(
			service,
			clusterRole,
			clusterRoleBinding,
		)
	}

	//TODO: Add VPA in addons
	if v.values.VPAEnabled {
		vpaUpdateMode := autoscalingv1beta2.UpdateModeAuto
		vpa = &autoscalingv1beta2.VerticalPodAutoscaler{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "vpn-shoot",
				Namespace: metav1.NamespaceSystem,
			},
			Spec: autoscalingv1beta2.VerticalPodAutoscalerSpec{
				TargetRef: &autoscalingv1.CrossVersionObjectReference{
					APIVersion: appsv1.SchemeGroupVersion.String(),
					Kind:       "Deployment",
					Name:       deploymentName,
				},
				UpdatePolicy: &autoscalingv1beta2.PodUpdatePolicy{
					UpdateMode: &vpaUpdateMode,
				},
				ResourcePolicy: &autoscalingv1beta2.PodResourcePolicy{
					ContainerPolicies: []autoscalingv1beta2.ContainerResourcePolicy{
						{
							ContainerName: autoscalingv1beta2.DefaultContainerResourcePolicy,
							MinAllowed: corev1.ResourceList{
								corev1.ResourceCPU:    resource.MustParse("10m"),
								corev1.ResourceMemory: resource.MustParse("10Mi"),
							},
						},
					},
				},
			},
		}
		err = registry.Add(vpa)
	}
	return registry.SerializedObjects(), err
}

// Secrets is collection of secrets for the vpn-shoot.
type Secrets struct {
	// TLSAuth is a secret containing the tls auth credentials.
	TLSAuth component.Secret
	// DH is a secret containing the dh credentials.
	DH component.Secret
	// Server is a secret containing the server certificate and key.
	Server component.Secret
}

func (v *vpnShoot) SetPodAnnotations(Annotations map[string]string) {
	v.values.PodAnnotations = Annotations
}

func getEnvVar(v *vpnShoot) []corev1.EnvVar {
	envVariables := []corev1.EnvVar{
		{
			Name:  "SERVICE_NETWORK",
			Value: v.values.ServiceNetworkCIDR,
		},
		{
			Name:  "POD_NETWORK",
			Value: v.values.PodNetworkCIDR,
		},
		{
			Name:  "NODE_NETWORK",
			Value: v.values.NodeNetworkCIDR,
		},
	}
	// These are the additional env variables if ReversedVPN is enabled
	if v.values.ReversedVPNEnabled {
		envVariables = append(envVariables,
			corev1.EnvVar{
				Name:  "ENDPOINT",
				Value: v.values.ReversedVPNEndPoint,
			},
			corev1.EnvVar{
				Name:  "OPENVPN_PORT",
				Value: v.values.ReversedVPNOpenVPNPort,
			},
			corev1.EnvVar{
				Name:  "REVERSED_VPN_HEADER",
				Value: v.values.ReversedVPNHeader,
			},
		)
	}
	return envVariables
}

func getResourceLimits(v *vpnShoot) corev1.ResourceList {
	if v.values.VPAEnabled {
		return corev1.ResourceList{
			corev1.ResourceCPU:    resource.MustParse("400m"),
			corev1.ResourceMemory: resource.MustParse("400Mi"),
		}
	} else {
		return corev1.ResourceList{
			corev1.ResourceCPU:    resource.MustParse("1"),
			corev1.ResourceMemory: resource.MustParse("1Gi"),
		}
	}
}

func getVolumeMounts(v *vpnShoot) []corev1.VolumeMount {
	volumeMounts := []corev1.VolumeMount{
		{
			Name:      volumeNameSecret,
			MountPath: volumeMountPathSecret,
		},
		{
			Name:      volumeNameSecretTLS,
			MountPath: volumeMountPathSecretTLS,
		},
	}
	if !v.values.ReversedVPNEnabled {
		volumeMounts = append(volumeMounts, corev1.VolumeMount{
			Name:      volumeNameSecretDH,
			MountPath: volumeMountPathSecretDH,
		})
	}
	return volumeMounts
}
