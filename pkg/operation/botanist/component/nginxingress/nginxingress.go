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

package nginxingress

import (
	"context"
	"time"

	v1beta1constants "github.com/gardener/gardener/pkg/apis/core/v1beta1/constants"
	"github.com/gardener/gardener/pkg/client/kubernetes"
	"github.com/gardener/gardener/pkg/operation/botanist/component"
	"github.com/gardener/gardener/pkg/resourcemanager/controller/garbagecollector/references"
	kutil "github.com/gardener/gardener/pkg/utils/kubernetes"
	"github.com/gardener/gardener/pkg/utils/managedresources"
	"github.com/gardener/gardener/pkg/utils/version"

	"github.com/Masterminds/semver"
	appsv1 "k8s.io/api/apps/v1"
	autoscalingv1 "k8s.io/api/autoscaling/v1"
	corev1 "k8s.io/api/core/v1"
	networkingv1 "k8s.io/api/networking/v1"
	policyv1beta1 "k8s.io/api/policy/v1beta1"
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
	name                = "nginx-ingress"
	managedResourceName = name

	labelAppValue        = "nginx-ingress"
	labelKeyComponent    = "component"
	labelValueController = "controller"
	labelValueBackend    = "nginx-ingress-k8s-backend"
	labelKeyRelease      = "release"
	labelValueAddons     = "addons"

	controllerName            = "nginx-ingress-controller"
	depoloymentNameController = "nginx-ingress-controller"
	containerNameController   = "nginx-ingress-controller"
	serviceNameController     = "nginx-ingress-controller"

	deploymentNameBackend = "nginx-ingress-k8s-backend"
	containerNameBackend  = "nginx-ingress-k8s-backend"
	serviceNameBackend    = "nginx-ingress-k8s-backend"

	servicePortControllerHttp    int32 = 80
	containerPortControllerHttp  int32 = 80
	servicePortControllerHttps   int32 = 443
	containerPortControllerHttps int32 = 443

	servicePortBackend   int32 = 80
	containerPortBackend int32 = 8080
)

var (
	ingressClassName = v1beta1constants.SeedNginxIngressClass122
)

// Values is a set of configuration values for the nginxIngress component.
type Values struct {
	// ImageController is the container image used for nginxIngress Controller.
	ImageController string
	// ImageDefaultBackend is the container image used for Default Ingress backend.
	ImageDefaultBackend string
	// KubernetesVersion is the version of kubernetes for the seed cluster.
	KubernetesVersion *semver.Version
}

// New creates a new instance of DeployWaiter for nginxIngress
func New(
	client client.Client,
	namespace string,
	values Values,
) component.DeployWaiter {
	return &nginxIngress{
		client:    client,
		namespace: namespace,
		values:    values,
	}
}

type nginxIngress struct {
	client    client.Client
	namespace string
	values    Values
}

func (n *nginxIngress) Deploy(ctx context.Context) error {
	data, err := n.computeResourcesData()
	if err != nil {
		return err
	}
	return managedresources.CreateForSeed(ctx, n.client, n.namespace, managedResourceName, false, data)
}

func (n *nginxIngress) Destroy(ctx context.Context) error {
	return managedresources.DeleteForSeed(ctx, n.client, n.namespace, managedResourceName)
}

// TimeoutWaitForManagedResource is the timeout used while waiting for the ManagedResources to become healthy
// or deleted.
var TimeoutWaitForManagedResource = 2 * time.Minute

func (n *nginxIngress) Wait(ctx context.Context) error {
	timeoutCtx, cancel := context.WithTimeout(ctx, TimeoutWaitForManagedResource)
	defer cancel()

	return managedresources.WaitUntilHealthy(timeoutCtx, n.client, n.namespace, managedResourceName)
}

func (n *nginxIngress) WaitCleanup(ctx context.Context) error {
	timeoutCtx, cancel := context.WithTimeout(ctx, TimeoutWaitForManagedResource)
	defer cancel()

	return managedresources.WaitUntilDeleted(timeoutCtx, n.client, n.namespace, managedResourceName)
}

func (n *nginxIngress) computeResourcesData() (map[string][]byte, error) {
	if !version.ConstraintK8sGreaterEqual122.Check(n.values.KubernetesVersion) {
		ingressClassName = v1beta1constants.SeedNginxIngressClass
	}

	configMap := &corev1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{
			Name: controllerName,
			Labels: map[string]string{
				v1beta1constants.LabelApp: labelAppValue,
				labelKeyComponent:         labelValueController,
			},
			Namespace: n.namespace,
		},
		Data: map[string]string{
			"server-name-hash-bucket-size": "256",
			"use-proxy-protocol":           "false",
			"worker-processes":             "2",
		},
	}

	utilruntime.Must(kutil.MakeUnique(configMap))

	var (
		intStrOne                              = intstr.FromInt(1)
		uIDPodSecurityContextBackend     int64 = 65534
		fsGroupPodSecurityContextBackend int64 = 65534
		uIDPodSecurityContextController  int64 = 101

		registry = managedresources.NewRegistry(kubernetes.SeedScheme, kubernetes.SeedCodec, kubernetes.SeedSerializer)

		serviceAccount = &corev1.ServiceAccount{
			ObjectMeta: metav1.ObjectMeta{
				Name:      name,
				Namespace: n.namespace,
				Labels:    map[string]string{v1beta1constants.LabelApp: labelAppValue},
			},
			AutomountServiceAccountToken: pointer.Bool(false),
		}

		serviceController = &corev1.Service{
			ObjectMeta: metav1.ObjectMeta{
				Name:      serviceNameController,
				Namespace: n.namespace,
				Labels: map[string]string{
					v1beta1constants.LabelApp: labelAppValue,
					labelKeyComponent:         labelValueController,
				},
			},
			Spec: corev1.ServiceSpec{
				Type: corev1.ServiceTypeLoadBalancer,
				Ports: []corev1.ServicePort{
					{
						Name:       "http",
						Port:       servicePortControllerHttp,
						Protocol:   corev1.ProtocolTCP,
						TargetPort: intstr.FromInt(int(containerPortControllerHttp)),
					},
					{
						Name:       "https",
						Port:       servicePortControllerHttps,
						Protocol:   corev1.ProtocolTCP,
						TargetPort: intstr.FromInt(int(containerPortControllerHttps)),
					},
				},
				Selector: getLabels("controller"),
			},
		}

		serviceBackend = &corev1.Service{
			ObjectMeta: metav1.ObjectMeta{
				Name:      serviceNameBackend,
				Labels:    map[string]string{v1beta1constants.LabelApp: labelAppValue},
				Namespace: n.namespace,
			},
			Spec: corev1.ServiceSpec{
				Type: corev1.ServiceTypeClusterIP,
				Ports: []corev1.ServicePort{{
					Port:       servicePortBackend,
					TargetPort: intstr.FromInt(int(containerPortBackend)),
				}},
				Selector: getLabels("backend"),
			},
		}

		podDisruptionBudgetController = &policyv1beta1.PodDisruptionBudget{
			ObjectMeta: metav1.ObjectMeta{
				Name:      controllerName,
				Namespace: n.namespace,
				Labels: map[string]string{
					v1beta1constants.LabelApp: labelAppValue,
					labelKeyComponent:         labelValueController,
				},
			},
			Spec: policyv1beta1.PodDisruptionBudgetSpec{
				MinAvailable: &intStrOne,
				Selector: &metav1.LabelSelector{
					MatchLabels: getLabels("controller"),
				},
			},
		}

		roleBackend = &rbacv1.Role{
			ObjectMeta: metav1.ObjectMeta{
				Name:      name,
				Namespace: n.namespace,
				Labels:    map[string]string{v1beta1constants.LabelApp: labelAppValue},
			},
			Rules: []rbacv1.PolicyRule{
				{
					APIGroups: []string{""},
					Resources: []string{"configmaps", "namespaces", "pods", "secrets"},
					Verbs:     []string{"get"},
				},
				{
					APIGroups:     []string{""},
					Resources:     []string{"configmaps"},
					ResourceNames: []string{"ingress-controller-leader-nginx"},
					Verbs:         []string{"get", "update"},
				},
				{
					APIGroups: []string{""},
					Resources: []string{"configmaps"},
					Verbs:     []string{"create"},
				},
				{
					APIGroups: []string{""},
					Resources: []string{"endpoints"},
					Verbs:     []string{"create", "get", "update"},
				},
			},
		}

		roleBindingBackend = &rbacv1.RoleBinding{
			ObjectMeta: metav1.ObjectMeta{
				Name:      name,
				Namespace: n.namespace,
				Labels:    map[string]string{v1beta1constants.LabelApp: labelValueBackend},
			},
			RoleRef: rbacv1.RoleRef{
				APIGroup: rbacv1.GroupName,
				Kind:     "Role",
				Name:     roleBackend.Name,
			},
			Subjects: []rbacv1.Subject{{
				Kind:      rbacv1.ServiceAccountKind,
				Name:      serviceAccount.Name,
				Namespace: serviceAccount.Namespace,
			}},
		}

		clusterRole = &rbacv1.ClusterRole{
			ObjectMeta: metav1.ObjectMeta{
				Name:   "gardener.cloud:seed:" + name,
				Labels: map[string]string{v1beta1constants.LabelApp: labelAppValue},
			},
			Rules: []rbacv1.PolicyRule{
				{
					APIGroups: []string{""},
					Resources: []string{"endpoints", "nodes", "pods", "secrets"},
					Verbs:     []string{"list", "watch"},
				},
				{
					APIGroups: []string{""},
					Resources: []string{"nodes"},
					Verbs:     []string{"get"},
				},
				{
					APIGroups: []string{""},
					Resources: []string{"services", "configmaps"},
					Verbs:     []string{"get", "list", "update", "watch"},
				},
				{
					APIGroups: []string{"extensions", "networking.k8s.io"},
					Resources: []string{"ingresses"},
					Verbs:     []string{"get", "list", "watch"},
				},
				{
					APIGroups: []string{""},
					Resources: []string{"events"},
					Verbs:     []string{"create", "patch"},
				},
				{
					APIGroups: []string{"extensions", "networking.k8s.io"},
					Resources: []string{"ingresses/status"},
					Verbs:     []string{"update"},
				},
				{
					APIGroups: []string{"networking.k8s.io"},
					Resources: []string{"ingressclasses"},
					Verbs:     []string{"get", "list", "watch"},
				},
			},
		}

		clusterRoleBinding = &rbacv1.ClusterRoleBinding{
			ObjectMeta: metav1.ObjectMeta{
				Name:   "gardener.cloud:seed:" + name,
				Labels: map[string]string{v1beta1constants.LabelApp: labelAppValue},
			},
			RoleRef: rbacv1.RoleRef{
				APIGroup: rbacv1.GroupName,
				Kind:     "ClusterRole",
				Name:     clusterRole.Name,
			},
			Subjects: []rbacv1.Subject{{
				Kind:      rbacv1.ServiceAccountKind,
				Name:      serviceAccount.Name,
				Namespace: serviceAccount.Namespace,
			}},
		}

		deploymentBackend = &appsv1.Deployment{
			ObjectMeta: metav1.ObjectMeta{
				Name:      deploymentNameBackend,
				Namespace: n.namespace,
				Labels:    map[string]string{v1beta1constants.LabelApp: labelAppValue},
			},
			Spec: appsv1.DeploymentSpec{
				RevisionHistoryLimit: pointer.Int32(2),
				Replicas:             pointer.Int32(1),
				Selector: &metav1.LabelSelector{
					MatchLabels: getLabels("backend"),
				},
				Template: corev1.PodTemplateSpec{
					ObjectMeta: metav1.ObjectMeta{
						Labels: getLabels("backend"),
					},
					Spec: corev1.PodSpec{
						PriorityClassName: v1beta1constants.PriorityClassNameShootControlPlane,
						SecurityContext: &corev1.PodSecurityContext{
							RunAsUser: &uIDPodSecurityContextBackend,
							FSGroup:   &fsGroupPodSecurityContextBackend,
						},
						Containers: []corev1.Container{{
							Name:            containerNameBackend,
							Image:           n.values.ImageDefaultBackend,
							ImagePullPolicy: corev1.PullIfNotPresent,
							LivenessProbe: &corev1.Probe{
								Handler: corev1.Handler{
									HTTPGet: &corev1.HTTPGetAction{
										Path:   "/healthy",
										Port:   intstr.FromInt(int(containerPortBackend)),
										Scheme: corev1.URISchemeHTTP,
									},
								},
								InitialDelaySeconds: 30,
								TimeoutSeconds:      5,
							},
							Ports: []corev1.ContainerPort{{
								ContainerPort: containerPortBackend,
								Protocol:      corev1.ProtocolTCP,
							}},
							Resources: corev1.ResourceRequirements{
								Limits: corev1.ResourceList{
									corev1.ResourceCPU:    resource.MustParse("100m"),
									corev1.ResourceMemory: resource.MustParse("100Mi"),
								},
								Requests: corev1.ResourceList{
									corev1.ResourceCPU:    resource.MustParse("20m"),
									corev1.ResourceMemory: resource.MustParse("20Mi"),
								},
							},
						}},
						TerminationGracePeriodSeconds: pointer.Int64(60),
					},
				},
			},
		}

		deploymentController = &appsv1.Deployment{
			ObjectMeta: metav1.ObjectMeta{
				Name:      depoloymentNameController,
				Namespace: n.namespace,
				Labels: map[string]string{
					v1beta1constants.LabelApp: labelAppValue,
					labelKeyComponent:         labelValueController,
				},
				Annotations: map[string]string{
					references.AnnotationKey(references.KindConfigMap, configMap.Name): configMap.Name,
				},
			},
			Spec: appsv1.DeploymentSpec{
				Replicas:             pointer.Int32(3),
				RevisionHistoryLimit: pointer.Int32(2),
				Selector: &metav1.LabelSelector{
					MatchLabels: getLabels("controller"),
				},
				Template: corev1.PodTemplateSpec{
					ObjectMeta: metav1.ObjectMeta{
						Labels: getLabels("controller"),
						Annotations: map[string]string{
							// TODO(rfranzke): Remove in a future release.
							"security.gardener.cloud/trigger":                                  "rollout",
							references.AnnotationKey(references.KindConfigMap, configMap.Name): configMap.Name,
						},
					},
					Spec: corev1.PodSpec{
						PriorityClassName: v1beta1constants.PriorityClassNameShootControlPlane,
						Affinity: &corev1.Affinity{
							PodAntiAffinity: &corev1.PodAntiAffinity{
								PreferredDuringSchedulingIgnoredDuringExecution: []corev1.WeightedPodAffinityTerm{{
									Weight: 100,
									PodAffinityTerm: corev1.PodAffinityTerm{
										TopologyKey: corev1.LabelHostname,
										LabelSelector: &metav1.LabelSelector{
											MatchExpressions: []metav1.LabelSelectorRequirement{
												{
													Key:      v1beta1constants.LabelApp,
													Operator: metav1.LabelSelectorOpIn,
													Values:   []string{labelAppValue},
												},
												{
													Key:      labelKeyComponent,
													Operator: metav1.LabelSelectorOpIn,
													Values:   []string{labelValueController},
												},
												{
													Key:      labelKeyRelease,
													Operator: metav1.LabelSelectorOpIn,
													Values:   []string{labelValueAddons},
												},
											},
										},
									}},
								},
							},
						},
						Containers: []corev1.Container{{
							Name:            containerNameController,
							Image:           n.values.ImageController,
							ImagePullPolicy: corev1.PullIfNotPresent,
							Args:            n.getArgs(configMap),
							SecurityContext: &corev1.SecurityContext{
								Capabilities: &corev1.Capabilities{
									Drop: []corev1.Capability{"ALL"},
									Add:  []corev1.Capability{"NET_BIND_SERVICE"},
								},
								RunAsUser:                &uIDPodSecurityContextController,
								AllowPrivilegeEscalation: pointer.Bool(true),
							},
							Env: []corev1.EnvVar{
								{
									Name: "POD_NAME",
									ValueFrom: &corev1.EnvVarSource{
										FieldRef: &corev1.ObjectFieldSelector{
											FieldPath: "metadata.name",
										},
									},
								},
								{
									Name: "POD_NAMESPACE",
									ValueFrom: &corev1.EnvVarSource{
										FieldRef: &corev1.ObjectFieldSelector{
											FieldPath: "metadata.namespace",
										},
									},
								},
							},
							LivenessProbe: &corev1.Probe{
								FailureThreshold: 3,
								Handler: corev1.Handler{
									HTTPGet: &corev1.HTTPGetAction{
										Path:   "/healthz",
										Port:   intstr.FromInt(10254),
										Scheme: corev1.URISchemeHTTP,
									},
								},
								InitialDelaySeconds: 40,
								PeriodSeconds:       10,
								SuccessThreshold:    1,
								TimeoutSeconds:      1,
							},
							Ports: []corev1.ContainerPort{
								{
									Name:          "http",
									ContainerPort: containerPortControllerHttp,
									Protocol:      corev1.ProtocolTCP,
								},
								{
									Name:          "https",
									ContainerPort: containerPortControllerHttps,
									Protocol:      corev1.ProtocolTCP,
								},
							},
							ReadinessProbe: &corev1.Probe{
								FailureThreshold:    3,
								InitialDelaySeconds: 40,
								Handler: corev1.Handler{
									HTTPGet: &corev1.HTTPGetAction{
										Path:   "/healthz",
										Port:   intstr.FromInt(10254),
										Scheme: corev1.URISchemeHTTP,
									},
								},
								PeriodSeconds:    10,
								SuccessThreshold: 1,
								TimeoutSeconds:   1,
							},
							Resources: corev1.ResourceRequirements{
								Limits: corev1.ResourceList{
									corev1.ResourceCPU:    resource.MustParse("400m"),
									corev1.ResourceMemory: resource.MustParse("1500Mi"),
								},
								Requests: corev1.ResourceList{
									corev1.ResourceCPU:    resource.MustParse("100m"),
									corev1.ResourceMemory: resource.MustParse("375Mi"),
								},
							},
						}},
						ServiceAccountName:            serviceAccount.Name,
						TerminationGracePeriodSeconds: pointer.Int64(60),
					},
				},
			},
		}

		updateMode = autoscalingv1beta2.UpdateModeAuto
		vpa        = &autoscalingv1beta2.VerticalPodAutoscaler{
			ObjectMeta: metav1.ObjectMeta{
				Name:      controllerName,
				Namespace: n.namespace,
			},
			Spec: autoscalingv1beta2.VerticalPodAutoscalerSpec{
				TargetRef: &autoscalingv1.CrossVersionObjectReference{
					APIVersion: appsv1.SchemeGroupVersion.String(),
					Kind:       "Deployment",
					Name:       deploymentController.Name,
				},
				UpdatePolicy: &autoscalingv1beta2.PodUpdatePolicy{
					UpdateMode: &updateMode,
				},
				ResourcePolicy: &autoscalingv1beta2.PodResourcePolicy{
					ContainerPolicies: []autoscalingv1beta2.ContainerResourcePolicy{
						{
							ContainerName: autoscalingv1beta2.DefaultContainerResourcePolicy,
							MinAllowed: corev1.ResourceList{
								corev1.ResourceCPU:    resource.MustParse("25m"),
								corev1.ResourceMemory: resource.MustParse("100Mi"),
							},
						},
					},
				},
			},
		}

		ingressClass *networkingv1.IngressClass
	)

	if version.ConstraintK8sGreaterEqual122.Check(n.values.KubernetesVersion) {
		ingressClass = &networkingv1.IngressClass{
			ObjectMeta: metav1.ObjectMeta{
				Name: ingressClassName,
				Labels: map[string]string{
					v1beta1constants.LabelApp: labelAppValue,
					labelKeyComponent:         labelValueController,
				},
			},
			Spec: networkingv1.IngressClassSpec{
				Controller: "k8s.io/" + ingressClassName,
			},
		}
	}

	return registry.AddAllAndSerialize(
		serviceAccount,
		vpa,
		configMap,
		deploymentController,
		deploymentBackend,
		clusterRole,
		clusterRoleBinding,
		serviceController,
		serviceBackend,
		podDisruptionBudgetController,
		roleBackend,
		roleBindingBackend,
		ingressClass,
	)
}

func getLabels(resourceType string) map[string]string {
	labels := map[string]string{
		v1beta1constants.LabelApp: labelAppValue,
		labelKeyRelease:           labelValueAddons,
	}
	if resourceType == "controller" {
		labels[labelKeyComponent] = labelValueController
	} else {
		labels[labelKeyComponent] = labelValueBackend
	}

	return labels
}

func (n *nginxIngress) getArgs(configMap *corev1.ConfigMap) []string {
	out := []string{
		"/nginx-ingress-controller",
		"--default-backend-service=garden/nginx-ingress-k8s-backend",
		"--enable-ssl-passthrough=true",
		"--publish-service=garden/nginx-ingress-controller",
		"--election-id=ingress-controller-seed-leader",
		"--update-status=true",
		"--annotations-prefix=nginx.ingress.kubernetes.io",
		"--configmap=garden/" + configMap.Name,
		"--ingress-class=" + ingressClassName,
	}
	if version.ConstraintK8sGreaterEqual122.Check(n.values.KubernetesVersion) {
		out = append(out, "--controller-class=k8s.io/"+ingressClassName)
	}
	return out
}
