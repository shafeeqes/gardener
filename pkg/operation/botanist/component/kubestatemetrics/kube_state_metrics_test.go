// Copyright 2022 SAP SE or an SAP affiliate company. All rights reserved. This file is licensed under the Apache Software License, v. 2 except as noted otherwise in the LICENSE file
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

package kubestatemetrics_test

import (
	"context"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	appsv1 "k8s.io/api/apps/v1"
	autoscalingv1 "k8s.io/api/autoscaling/v1"
	corev1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/intstr"
	vpaautoscalingv1 "k8s.io/autoscaler/vertical-pod-autoscaler/pkg/apis/autoscaling.k8s.io/v1"
	"k8s.io/utils/pointer"
	"sigs.k8s.io/controller-runtime/pkg/client"
	fakeclient "sigs.k8s.io/controller-runtime/pkg/client/fake"

	gardencorev1beta1 "github.com/gardener/gardener/pkg/apis/core/v1beta1"
	v1beta1constants "github.com/gardener/gardener/pkg/apis/core/v1beta1/constants"
	resourcesv1alpha1 "github.com/gardener/gardener/pkg/apis/resources/v1alpha1"
	"github.com/gardener/gardener/pkg/client/kubernetes"
	"github.com/gardener/gardener/pkg/operation/botanist/component"
	. "github.com/gardener/gardener/pkg/operation/botanist/component/kubestatemetrics"
	componenttest "github.com/gardener/gardener/pkg/operation/botanist/component/test"
	"github.com/gardener/gardener/pkg/utils/retry"
	retryfake "github.com/gardener/gardener/pkg/utils/retry/fake"
	secretsmanager "github.com/gardener/gardener/pkg/utils/secrets/manager"
	fakesecretsmanager "github.com/gardener/gardener/pkg/utils/secrets/manager/fake"
	"github.com/gardener/gardener/pkg/utils/test"
	. "github.com/gardener/gardener/pkg/utils/test/matchers"
)

var _ = Describe("KubeStateMetrics", func() {
	var (
		ctx = context.TODO()

		namespace = "some-namespace"
		values    = Values{}

		c   client.Client
		sm  secretsmanager.Interface
		ksm component.DeployWaiter

		image = "some-image:some-tag"

		managedResourceName   string
		managedResource       *resourcesv1alpha1.ManagedResource
		managedResourceSecret *corev1.Secret

		vpaUpdateMode       = vpaautoscalingv1.UpdateModeAuto
		vpaControlledValues = vpaautoscalingv1.ContainerControlledValuesRequestsOnly

		serviceAccount    *corev1.ServiceAccount
		secretShootAccess *corev1.Secret
		vpa               *vpaautoscalingv1.VerticalPodAutoscaler
		clusterRoleFor    = func(clusterType component.ClusterType) *rbacv1.ClusterRole {
			name := "gardener.cloud:monitoring:kube-state-metrics"
			if clusterType == component.ClusterTypeSeed {
				name += "-seed"
			}

			obj := &rbacv1.ClusterRole{
				TypeMeta: metav1.TypeMeta{
					APIVersion: "rbac.authorization.k8s.io/v1",
					Kind:       "ClusterRole",
				},
				ObjectMeta: metav1.ObjectMeta{
					Name: name,
					Labels: map[string]string{
						"component": "kube-state-metrics",
						"type":      string(clusterType),
					},
				},
				Rules: []rbacv1.PolicyRule{
					{
						APIGroups: []string{""},
						Resources: []string{
							"nodes",
							"pods",
							"services",
							"resourcequotas",
							"replicationcontrollers",
							"limitranges",
							"persistentvolumeclaims",
							"namespaces",
						},
						Verbs: []string{"list", "watch"},
					},
					{
						APIGroups: []string{"apps", "extensions"},
						Resources: []string{"daemonsets", "deployments", "replicasets", "statefulsets"},
						Verbs:     []string{"list", "watch"},
					},
					{
						APIGroups: []string{"batch"},
						Resources: []string{"cronjobs", "jobs"},
						Verbs:     []string{"list", "watch"},
					},
					{
						APIGroups: []string{"autoscaling.k8s.io"},
						Resources: []string{"verticalpodautoscalers"},
						Verbs:     []string{"get", "list", "watch"},
					},
				},
			}

			if clusterType == component.ClusterTypeSeed {
				obj.Rules = append(obj.Rules, rbacv1.PolicyRule{
					APIGroups: []string{"autoscaling"},
					Resources: []string{"horizontalpodautoscalers"},
					Verbs:     []string{"list", "watch"},
				})
			}

			return obj
		}
		clusterRoleBindingFor = func(clusterType component.ClusterType) *rbacv1.ClusterRoleBinding {
			name := "gardener.cloud:monitoring:kube-state-metrics"
			if clusterType == component.ClusterTypeSeed {
				name += "-seed"
			}

			obj := &rbacv1.ClusterRoleBinding{
				TypeMeta: metav1.TypeMeta{
					APIVersion: "rbac.authorization.k8s.io/v1",
					Kind:       "ClusterRoleBinding",
				},
				ObjectMeta: metav1.ObjectMeta{
					Name: name,
					Labels: map[string]string{
						"component": "kube-state-metrics",
						"type":      string(clusterType),
					},
					Annotations: map[string]string{
						"resources.gardener.cloud/delete-on-invalid-update": "true",
					},
				},
				RoleRef: rbacv1.RoleRef{
					APIGroup: rbacv1.GroupName,
					Kind:     "ClusterRole",
					Name:     name,
				},
				Subjects: []rbacv1.Subject{{
					Kind: rbacv1.ServiceAccountKind,
					Name: "kube-state-metrics",
				}},
			}

			if clusterType == component.ClusterTypeSeed {
				obj.Subjects[0].Namespace = namespace
			} else {
				obj.Subjects[0].Namespace = "kube-system"
			}

			return obj
		}
		serviceFor = func(clusterType component.ClusterType) *corev1.Service {
			obj := &corev1.Service{
				TypeMeta: metav1.TypeMeta{
					APIVersion: "v1",
					Kind:       "Service",
				},
				ObjectMeta: metav1.ObjectMeta{
					Name:      "kube-state-metrics",
					Namespace: namespace,
					Labels: map[string]string{
						"component": "kube-state-metrics",
						"type":      string(clusterType),
					},
				},
				Spec: corev1.ServiceSpec{
					Type: corev1.ServiceTypeClusterIP,
					Selector: map[string]string{
						"component": "kube-state-metrics",
						"type":      string(clusterType),
					},
					Ports: []corev1.ServicePort{{
						Name:       "metrics",
						Port:       80,
						TargetPort: intstr.FromInt(8080),
						Protocol:   corev1.ProtocolTCP,
					}},
				},
			}

			obj.Annotations = map[string]string{
				"networking.resources.gardener.cloud/from-policy-allowed-ports": `[{"protocol":"TCP","port":8080}]`,
			}
			if clusterType == component.ClusterTypeSeed {
				obj.Annotations["networking.resources.gardener.cloud/from-policy-pod-label-selector"] = "all-seed-scrape-targets"
			}
			if clusterType == component.ClusterTypeShoot {
				obj.Annotations["networking.resources.gardener.cloud/from-policy-pod-label-selector"] = "all-scrape-targets"
			}

			return obj
		}
		deploymentFor = func(clusterType component.ClusterType) *appsv1.Deployment {
			var (
				maxUnavailable = intstr.FromInt(1)
				selectorLabels = map[string]string{
					"component": "kube-state-metrics",
					"type":      string(clusterType),
				}
				priorityClassName = v1beta1constants.PriorityClassNameSeedSystem600

				deploymentLabels             map[string]string
				podLabels                    map[string]string
				args                         []string
				automountServiceAccountToken *bool
				serviceAccountName           string
				volumeMounts                 []corev1.VolumeMount
				volumes                      []corev1.Volume
			)

			if clusterType == component.ClusterTypeSeed {
				deploymentLabels = map[string]string{
					"component": "kube-state-metrics",
					"type":      string(clusterType),
					"role":      "monitoring",
				}
				podLabels = map[string]string{
					"component":                        "kube-state-metrics",
					"type":                             string(clusterType),
					"role":                             "monitoring",
					"networking.gardener.cloud/to-dns": "allowed",
					"networking.gardener.cloud/to-runtime-apiserver": "allowed",
				}
				args = []string{
					"--port=8080",
					"--telemetry-port=8081",
					"--resources=deployments,pods,statefulsets,nodes,verticalpodautoscalers,horizontalpodautoscalers,persistentvolumeclaims,replicasets,namespaces",
					"--metric-labels-allowlist=nodes=[*]",
					"--metric-annotations-allowlist=namespaces=[shoot.gardener.cloud/uid]",
				}
				serviceAccountName = "kube-state-metrics"
			}

			if clusterType == component.ClusterTypeShoot {
				priorityClassName = v1beta1constants.PriorityClassNameShootControlPlane100
				deploymentLabels = map[string]string{
					"component":           "kube-state-metrics",
					"type":                string(clusterType),
					"gardener.cloud/role": "monitoring",
				}
				podLabels = map[string]string{
					"component":                        "kube-state-metrics",
					"type":                             string(clusterType),
					"gardener.cloud/role":              "monitoring",
					"networking.gardener.cloud/to-dns": "allowed",
					"networking.resources.gardener.cloud/to-kube-apiserver-tcp-443": "allowed",
				}
				args = []string{
					"--port=8080",
					"--telemetry-port=8081",
					"--resources=daemonsets,deployments,nodes,pods,statefulsets,verticalpodautoscalers,replicasets",
					"--namespaces=kube-system",
					"--kubeconfig=/var/run/secrets/gardener.cloud/shoot/generic-kubeconfig/kubeconfig",
					"--metric-labels-allowlist=nodes=[*]",
				}
				automountServiceAccountToken = pointer.Bool(false)
				volumeMounts = []corev1.VolumeMount{{
					Name:      "kubeconfig",
					MountPath: "/var/run/secrets/gardener.cloud/shoot/generic-kubeconfig",
					ReadOnly:  true,
				}}
				volumes = []corev1.Volume{{
					Name: "kubeconfig",
					VolumeSource: corev1.VolumeSource{
						Projected: &corev1.ProjectedVolumeSource{
							DefaultMode: pointer.Int32(420),
							Sources: []corev1.VolumeProjection{
								{
									Secret: &corev1.SecretProjection{
										LocalObjectReference: corev1.LocalObjectReference{
											Name: "generic-token-kubeconfig",
										},
										Items: []corev1.KeyToPath{{
											Key:  "kubeconfig",
											Path: "kubeconfig",
										}},
										Optional: pointer.Bool(false),
									},
								},
								{
									Secret: &corev1.SecretProjection{
										LocalObjectReference: corev1.LocalObjectReference{
											Name: "shoot-access-kube-state-metrics",
										},
										Items: []corev1.KeyToPath{{
											Key:  "token",
											Path: "token",
										}},
										Optional: pointer.Bool(false),
									},
								},
							},
						},
					},
				}}
			}

			return &appsv1.Deployment{
				TypeMeta: metav1.TypeMeta{
					APIVersion: "apps/v1",
					Kind:       "Deployment",
				},
				ObjectMeta: metav1.ObjectMeta{
					Name:      "kube-state-metrics",
					Namespace: namespace,
					Labels:    deploymentLabels,
				},
				Spec: appsv1.DeploymentSpec{
					Replicas:             pointer.Int32(0),
					RevisionHistoryLimit: pointer.Int32(2),
					Selector:             &metav1.LabelSelector{MatchLabels: selectorLabels},
					Strategy: appsv1.DeploymentStrategy{
						Type: appsv1.RollingUpdateDeploymentStrategyType,
						RollingUpdate: &appsv1.RollingUpdateDeployment{
							MaxUnavailable: &maxUnavailable,
						},
					},
					Template: corev1.PodTemplateSpec{
						ObjectMeta: metav1.ObjectMeta{
							Labels: podLabels,
						},
						Spec: corev1.PodSpec{
							Containers: []corev1.Container{{
								Name:            "kube-state-metrics",
								Image:           image,
								ImagePullPolicy: corev1.PullIfNotPresent,
								Args:            args,
								Ports: []corev1.ContainerPort{{
									Name:          "metrics",
									ContainerPort: 8080,
									Protocol:      corev1.ProtocolTCP,
								}},
								LivenessProbe: &corev1.Probe{
									ProbeHandler: corev1.ProbeHandler{
										HTTPGet: &corev1.HTTPGetAction{
											Path: "/healthz",
											Port: intstr.FromInt(8080),
										},
									},
									InitialDelaySeconds: 5,
									TimeoutSeconds:      5,
								},
								ReadinessProbe: &corev1.Probe{
									ProbeHandler: corev1.ProbeHandler{
										HTTPGet: &corev1.HTTPGetAction{
											Path: "/healthz",
											Port: intstr.FromInt(8080),
										},
									},
									InitialDelaySeconds: 5,
									PeriodSeconds:       30,
									SuccessThreshold:    1,
									FailureThreshold:    3,
									TimeoutSeconds:      5,
								},
								Resources: corev1.ResourceRequirements{
									Requests: corev1.ResourceList{
										corev1.ResourceCPU:    resource.MustParse("10m"),
										corev1.ResourceMemory: resource.MustParse("32Mi"),
									},
								},
								VolumeMounts: volumeMounts,
							}},
							AutomountServiceAccountToken: automountServiceAccountToken,
							PriorityClassName:            priorityClassName,
							ServiceAccountName:           serviceAccountName,
							Volumes:                      volumes,
						},
					},
				},
			}
		}
	)

	BeforeEach(func() {
		c = fakeclient.NewClientBuilder().WithScheme(kubernetes.SeedScheme).Build()
		sm = fakesecretsmanager.New(c, namespace)

		ksm = New(c, namespace, sm, values, false)
		managedResourceName = ""

		By("Create secrets managed outside of this package for whose secretsmanager.Get() will be called")
		Expect(c.Create(ctx, &corev1.Secret{ObjectMeta: metav1.ObjectMeta{Name: "generic-token-kubeconfig", Namespace: namespace}})).To(Succeed())

		serviceAccount = &corev1.ServiceAccount{
			TypeMeta: metav1.TypeMeta{
				APIVersion: "v1",
				Kind:       "ServiceAccount",
			},
			ObjectMeta: metav1.ObjectMeta{
				Name:      "kube-state-metrics",
				Namespace: namespace,
				Labels: map[string]string{
					"component": "kube-state-metrics",
					"type":      "seed",
				},
			},
			AutomountServiceAccountToken: pointer.Bool(false),
		}
		secretShootAccess = &corev1.Secret{
			TypeMeta: metav1.TypeMeta{
				APIVersion: "v1",
				Kind:       "Secret",
			},
			ObjectMeta: metav1.ObjectMeta{
				Name:      "shoot-access-kube-state-metrics",
				Namespace: namespace,
				Annotations: map[string]string{
					"serviceaccount.resources.gardener.cloud/name":      "kube-state-metrics",
					"serviceaccount.resources.gardener.cloud/namespace": "kube-system",
				},
				Labels: map[string]string{
					"resources.gardener.cloud/purpose": "token-requestor",
				},
			},
			Type: corev1.SecretTypeOpaque,
		}
		vpa = &vpaautoscalingv1.VerticalPodAutoscaler{
			TypeMeta: metav1.TypeMeta{
				APIVersion: "autoscaling.k8s.io/v1",
				Kind:       "VerticalPodAutoscaler",
			},
			ObjectMeta: metav1.ObjectMeta{
				Name:      "kube-state-metrics-vpa",
				Namespace: namespace,
			},
			Spec: vpaautoscalingv1.VerticalPodAutoscalerSpec{
				TargetRef: &autoscalingv1.CrossVersionObjectReference{
					APIVersion: "apps/v1",
					Kind:       "Deployment",
					Name:       "kube-state-metrics",
				},
				UpdatePolicy: &vpaautoscalingv1.PodUpdatePolicy{UpdateMode: &vpaUpdateMode},
				ResourcePolicy: &vpaautoscalingv1.PodResourcePolicy{
					ContainerPolicies: []vpaautoscalingv1.ContainerResourcePolicy{
						{
							ContainerName:    "*",
							ControlledValues: &vpaControlledValues,
							MinAllowed: corev1.ResourceList{
								corev1.ResourceMemory: resource.MustParse("32Mi"),
							},
						},
					},
				},
			},
		}
	})

	JustBeforeEach(func() {
		managedResource = &resourcesv1alpha1.ManagedResource{
			ObjectMeta: metav1.ObjectMeta{
				Name:      managedResourceName,
				Namespace: namespace,
			},
		}
		managedResourceSecret = &corev1.Secret{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "managedresource-" + managedResource.Name,
				Namespace: namespace,
			},
		}
	})

	Describe("#Deploy", func() {
		Context("cluster type seed", func() {
			BeforeEach(func() {
				ksm = New(c, namespace, nil, Values{
					ClusterType: component.ClusterTypeSeed,
					Image:       image,
				},
					false,
				)
				managedResourceName = "kube-state-metrics"
			})

			It("should successfully deploy all resources", func() {
				Expect(c.Get(ctx, client.ObjectKeyFromObject(managedResource), managedResource)).To(BeNotFoundError())
				Expect(c.Get(ctx, client.ObjectKeyFromObject(managedResourceSecret), managedResourceSecret)).To(BeNotFoundError())

				Expect(ksm.Deploy(ctx)).To(Succeed())

				Expect(c.Get(ctx, client.ObjectKeyFromObject(managedResource), managedResource)).To(Succeed())
				Expect(managedResource).To(DeepEqual(&resourcesv1alpha1.ManagedResource{
					TypeMeta: metav1.TypeMeta{
						APIVersion: resourcesv1alpha1.SchemeGroupVersion.String(),
						Kind:       "ManagedResource",
					},
					ObjectMeta: metav1.ObjectMeta{
						Name:            managedResourceName,
						Namespace:       namespace,
						Labels:          map[string]string{"gardener.cloud/role": "seed-system-component"},
						ResourceVersion: "1",
					},
					Spec: resourcesv1alpha1.ManagedResourceSpec{
						Class: pointer.String("seed"),
						SecretRefs: []corev1.LocalObjectReference{{
							Name: managedResourceSecret.Name,
						}},
						KeepObjects: pointer.Bool(false),
					},
				}))

				Expect(c.Get(ctx, client.ObjectKeyFromObject(managedResourceSecret), managedResourceSecret)).To(Succeed())
				Expect(managedResourceSecret.Type).To(Equal(corev1.SecretTypeOpaque))
				Expect(managedResourceSecret.Data).To(HaveLen(6))

				Expect(string(managedResourceSecret.Data["serviceaccount__"+namespace+"__kube-state-metrics.yaml"])).To(Equal(componenttest.Serialize(serviceAccount)))
				Expect(string(managedResourceSecret.Data["clusterrole____gardener.cloud_monitoring_kube-state-metrics-seed.yaml"])).To(Equal(componenttest.Serialize(clusterRoleFor(component.ClusterTypeSeed))))
				Expect(string(managedResourceSecret.Data["clusterrolebinding____gardener.cloud_monitoring_kube-state-metrics-seed.yaml"])).To(Equal(componenttest.Serialize(clusterRoleBindingFor(component.ClusterTypeSeed))))
				Expect(string(managedResourceSecret.Data["service__"+namespace+"__kube-state-metrics.yaml"])).To(Equal(componenttest.Serialize(serviceFor(component.ClusterTypeSeed))))
				Expect(string(managedResourceSecret.Data["deployment__"+namespace+"__kube-state-metrics.yaml"])).To(Equal(componenttest.Serialize(deploymentFor(component.ClusterTypeSeed))))
				Expect(string(managedResourceSecret.Data["verticalpodautoscaler__"+namespace+"__kube-state-metrics-vpa.yaml"])).To(Equal(componenttest.Serialize(vpa)))
			})
		})

		Context("cluster type shoot", func() {
			BeforeEach(func() {
				ksm = New(c, namespace, sm, Values{
					ClusterType: component.ClusterTypeShoot,
					Image:       image,
				},
					false,
				)
				managedResourceName = "shoot-core-kube-state-metrics"
			})

			It("should successfully deploy all resources", func() {
				Expect(c.Get(ctx, client.ObjectKeyFromObject(managedResource), managedResource)).To(BeNotFoundError())
				Expect(c.Get(ctx, client.ObjectKeyFromObject(managedResourceSecret), managedResourceSecret)).To(BeNotFoundError())

				Expect(ksm.Deploy(ctx)).To(Succeed())

				Expect(c.Get(ctx, client.ObjectKeyFromObject(managedResource), managedResource)).To(Succeed())
				Expect(managedResource).To(DeepEqual(&resourcesv1alpha1.ManagedResource{
					TypeMeta: metav1.TypeMeta{
						APIVersion: resourcesv1alpha1.SchemeGroupVersion.String(),
						Kind:       "ManagedResource",
					},
					ObjectMeta: metav1.ObjectMeta{
						Name:            managedResourceName,
						Namespace:       namespace,
						ResourceVersion: "1",
						Labels:          map[string]string{"origin": "gardener"},
					},
					Spec: resourcesv1alpha1.ManagedResourceSpec{
						InjectLabels: map[string]string{"shoot.gardener.cloud/no-cleanup": "true"},
						SecretRefs: []corev1.LocalObjectReference{{
							Name: managedResourceSecret.Name,
						}},
						KeepObjects: pointer.Bool(false),
					},
				}))

				Expect(c.Get(ctx, client.ObjectKeyFromObject(managedResourceSecret), managedResourceSecret)).To(Succeed())
				Expect(managedResourceSecret.Type).To(Equal(corev1.SecretTypeOpaque))
				Expect(managedResourceSecret.Data).To(HaveLen(2))

				Expect(string(managedResourceSecret.Data["clusterrole____gardener.cloud_monitoring_kube-state-metrics.yaml"])).To(Equal(componenttest.Serialize(clusterRoleFor(component.ClusterTypeShoot))))
				Expect(string(managedResourceSecret.Data["clusterrolebinding____gardener.cloud_monitoring_kube-state-metrics.yaml"])).To(Equal(componenttest.Serialize(clusterRoleBindingFor(component.ClusterTypeShoot))))

				actualSecretShootAccess := &corev1.Secret{}
				Expect(c.Get(ctx, client.ObjectKeyFromObject(secretShootAccess), actualSecretShootAccess)).To(Succeed())
				expectedSecretShootAccess := secretShootAccess.DeepCopy()
				expectedSecretShootAccess.ResourceVersion = "1"
				Expect(actualSecretShootAccess).To(Equal(expectedSecretShootAccess))

				actualService := &corev1.Service{}
				Expect(c.Get(ctx, client.ObjectKeyFromObject(serviceFor(component.ClusterTypeShoot)), actualService)).To(Succeed())
				expectedService := serviceFor(component.ClusterTypeShoot).DeepCopy()
				expectedService.ResourceVersion = "1"
				Expect(actualService).To(Equal(expectedService))

				actualDeployment := &appsv1.Deployment{}
				Expect(c.Get(ctx, client.ObjectKeyFromObject(deploymentFor(component.ClusterTypeShoot)), actualDeployment)).To(Succeed())
				expectedDeployment := deploymentFor(component.ClusterTypeShoot).DeepCopy()
				expectedDeployment.ResourceVersion = "1"
				Expect(actualDeployment).To(Equal(expectedDeployment))

				actualVPA := &vpaautoscalingv1.VerticalPodAutoscaler{}
				Expect(c.Get(ctx, client.ObjectKeyFromObject(vpa), actualVPA)).To(Succeed())
				expectedVPA := vpa.DeepCopy()
				expectedVPA.ResourceVersion = "1"
				Expect(actualVPA).To(Equal(expectedVPA))
			})
		})
	})

	Describe("#Destroy", func() {
		Context("cluster type seed", func() {
			BeforeEach(func() {
				ksm = New(c, namespace, nil, Values{ClusterType: component.ClusterTypeSeed}, false)
				managedResourceName = "kube-state-metrics"
			})

			It("should successfully destroy all resources", func() {
				Expect(c.Create(ctx, managedResource)).To(Succeed())
				Expect(c.Create(ctx, managedResourceSecret)).To(Succeed())

				Expect(ksm.Destroy(ctx)).To(Succeed())

				Expect(c.Get(ctx, client.ObjectKeyFromObject(managedResource), managedResource)).To(BeNotFoundError())
				Expect(c.Get(ctx, client.ObjectKeyFromObject(managedResourceSecret), managedResourceSecret)).To(BeNotFoundError())
			})
		})

		Context("cluster type shoot", func() {
			BeforeEach(func() {
				ksm = New(c, namespace, sm, Values{ClusterType: component.ClusterTypeShoot}, false)
				managedResourceName = "shoot-core-kube-state-metrics"
			})

			It("should successfully destroy all resources", func() {
				Expect(c.Create(ctx, managedResource)).To(Succeed())
				Expect(c.Create(ctx, managedResourceSecret)).To(Succeed())
				Expect(c.Create(ctx, secretShootAccess)).To(Succeed())
				Expect(c.Create(ctx, serviceFor(component.ClusterTypeShoot))).To(Succeed())
				Expect(c.Create(ctx, deploymentFor(component.ClusterTypeShoot))).To(Succeed())
				Expect(c.Create(ctx, vpa)).To(Succeed())

				Expect(ksm.Destroy(ctx)).To(Succeed())

				Expect(c.Get(ctx, client.ObjectKeyFromObject(managedResource), managedResource)).To(BeNotFoundError())
				Expect(c.Get(ctx, client.ObjectKeyFromObject(managedResourceSecret), managedResourceSecret)).To(BeNotFoundError())
				Expect(c.Get(ctx, client.ObjectKeyFromObject(secretShootAccess), secretShootAccess)).To(BeNotFoundError())
				Expect(c.Get(ctx, client.ObjectKeyFromObject(serviceFor(component.ClusterTypeShoot)), serviceFor(component.ClusterTypeShoot))).To(BeNotFoundError())
				Expect(c.Get(ctx, client.ObjectKeyFromObject(deploymentFor(component.ClusterTypeShoot)), deploymentFor(component.ClusterTypeShoot))).To(BeNotFoundError())
				Expect(c.Get(ctx, client.ObjectKeyFromObject(vpa), vpa)).To(BeNotFoundError())
			})
		})
	})

	Context("waiting functions", func() {
		var fakeOps *retryfake.Ops

		BeforeEach(func() {
			fakeOps = &retryfake.Ops{MaxAttempts: 1}
			DeferCleanup(test.WithVars(
				&retry.Until, fakeOps.Until,
				&retry.UntilTimeout, fakeOps.UntilTimeout,
			))
		})

		Describe("#Wait", func() {
			tests := func(managedResourceName string) {
				It("should fail because reading the ManagedResource fails", func() {
					Expect(ksm.Wait(ctx)).To(MatchError(ContainSubstring("not found")))
				})

				It("should fail because the ManagedResource doesn't become healthy", func() {
					fakeOps.MaxAttempts = 2

					Expect(c.Create(ctx, &resourcesv1alpha1.ManagedResource{
						ObjectMeta: metav1.ObjectMeta{
							Name:       managedResourceName,
							Namespace:  namespace,
							Generation: 1,
						},
						Status: resourcesv1alpha1.ManagedResourceStatus{
							ObservedGeneration: 1,
							Conditions: []gardencorev1beta1.Condition{
								{
									Type:   resourcesv1alpha1.ResourcesApplied,
									Status: gardencorev1beta1.ConditionFalse,
								},
								{
									Type:   resourcesv1alpha1.ResourcesHealthy,
									Status: gardencorev1beta1.ConditionFalse,
								},
							},
						},
					})).To(Succeed())

					Expect(ksm.Wait(ctx)).To(MatchError(ContainSubstring("is not healthy")))
				})

				It("should successfully wait for the managed resource to become healthy", func() {
					fakeOps.MaxAttempts = 2

					Expect(c.Create(ctx, &resourcesv1alpha1.ManagedResource{
						ObjectMeta: metav1.ObjectMeta{
							Name:       managedResourceName,
							Namespace:  namespace,
							Generation: 1,
						},
						Status: resourcesv1alpha1.ManagedResourceStatus{
							ObservedGeneration: 1,
							Conditions: []gardencorev1beta1.Condition{
								{
									Type:   resourcesv1alpha1.ResourcesApplied,
									Status: gardencorev1beta1.ConditionTrue,
								},
								{
									Type:   resourcesv1alpha1.ResourcesHealthy,
									Status: gardencorev1beta1.ConditionTrue,
								},
							},
						},
					})).To(Succeed())

					Expect(ksm.Wait(ctx)).To(Succeed())
				})
			}

			Context("cluster type seed", func() {
				BeforeEach(func() {
					ksm = New(c, namespace, nil, Values{ClusterType: component.ClusterTypeSeed}, false)
				})

				tests("kube-state-metrics")
			})

			Context("cluster type shoot", func() {
				BeforeEach(func() {
					ksm = New(c, namespace, sm, Values{ClusterType: component.ClusterTypeShoot}, false)
				})

				tests("shoot-core-kube-state-metrics")
			})
		})

		Describe("#WaitCleanup", func() {
			tests := func(managedResourceName string) {
				It("should fail when the wait for the managed resource deletion times out", func() {
					fakeOps.MaxAttempts = 2

					managedResource := &resourcesv1alpha1.ManagedResource{
						ObjectMeta: metav1.ObjectMeta{
							Name:      managedResourceName,
							Namespace: namespace,
						},
					}

					Expect(c.Create(ctx, managedResource)).To(Succeed())

					Expect(ksm.WaitCleanup(ctx)).To(MatchError(ContainSubstring("still exists")))
				})

				It("should not return an error when it's already removed", func() {
					Expect(ksm.WaitCleanup(ctx)).To(Succeed())
				})
			}

			Context("cluster type seed", func() {
				BeforeEach(func() {
					ksm = New(c, namespace, nil, Values{ClusterType: component.ClusterTypeSeed}, false)
				})

				tests("kube-state-metrics")
			})

			Context("cluster type shoot", func() {
				BeforeEach(func() {
					ksm = New(c, namespace, sm, Values{ClusterType: component.ClusterTypeShoot}, false)
				})

				tests("shoot-core-kube-state-metrics")
			})
		})
	})
})
