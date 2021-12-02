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
	"github.com/gardener/gardener/pkg/utils/managedresources"

	appsv1 "k8s.io/api/apps/v1"
	autoscalingv1 "k8s.io/api/autoscaling/v1"
	corev1 "k8s.io/api/core/v1"
	policyv1beta1 "k8s.io/api/policy/v1beta1"
	rbacv1 "k8s.io/api/rbac/v1"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/intstr"
	autoscalingv1beta2 "k8s.io/autoscaler/vertical-pod-autoscaler/pkg/apis/autoscaling.k8s.io/v1beta2"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

const (
	// ManagedResourceName is the name of the ManagedResource containing the resource specifications.
	ManagedResourceName = "nginx-ingress"
	// LabelAppValue is the value of a label used for the identification of vpn-shoot pods.
	LabelAppValue = "nginx-ingress"

	labelKeyComponent    = "component"
	labelValueController = "controller"
	labelValueBackend    = "nginx-ingress-k8s-backend"

	name                  = "nginx-ingress"
	controllerName        = "nginx-ingress-controller"
	deploymentName        = "nginx-ingress"
	serviceNameController = "nginx-ingress-controller"
	serviceNameBackend    = "nginx-ingress-k8s-backend"

	servicePortControllerHttp  int32 = 80
	targetPortControllerHttp   int32 = 80
	servicePortControllerHttps int32 = 443
	targetPortControllerHttps  int32 = 443
	servicePortBackend         int32 = 80
	targetPortBackend          int32 = 8080
)

// Values is a set of configuration values for the nginxIngress component.
type Values struct {
	// ImageController is the container image used for nginxIngress Controller.
	ImageController string
	// ImageDefaultBackend is the container image used for Default Ingress backend.
	ImageDefaultBackend string
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
	return managedresources.CreateForSeed(ctx, n.client, n.namespace, ManagedResourceName, false, data)
}

func (n *nginxIngress) Destroy(ctx context.Context) error {
	return managedresources.DeleteForSeed(ctx, n.client, n.namespace, ManagedResourceName)
}

// TimeoutWaitForManagedResource is the timeout used while waiting for the ManagedResources to become healthy
// or deleted.
var TimeoutWaitForManagedResource = 2 * time.Minute

func (n *nginxIngress) Wait(ctx context.Context) error {
	timeoutCtx, cancel := context.WithTimeout(ctx, TimeoutWaitForManagedResource)
	defer cancel()

	return managedresources.WaitUntilHealthy(timeoutCtx, n.client, n.namespace, ManagedResourceName)
}

func (n *nginxIngress) WaitCleanup(ctx context.Context) error {
	timeoutCtx, cancel := context.WithTimeout(ctx, TimeoutWaitForManagedResource)
	defer cancel()

	return managedresources.WaitUntilDeleted(timeoutCtx, n.client, n.namespace, ManagedResourceName)
}

func (n *nginxIngress) computeResourcesData() (map[string][]byte, error) {
	var (
		intStrOne = intstr.FromInt(1)
		registry  = managedresources.NewRegistry(kubernetes.SeedScheme, kubernetes.SeedCodec, kubernetes.SeedSerializer)

		serviceAccount = &corev1.ServiceAccount{
			ObjectMeta: metav1.ObjectMeta{
				Name:      name,
				Namespace: n.namespace,
				Labels:    map[string]string{v1beta1constants.LabelApp: LabelAppValue},
			},
		}

		serviceController = &corev1.Service{
			ObjectMeta: metav1.ObjectMeta{
				Name:      serviceNameController,
				Namespace: n.namespace,
				Labels: map[string]string{
					v1beta1constants.LabelApp: LabelAppValue,
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
						TargetPort: intstr.FromInt(int(targetPortControllerHttp)),
					},
					{
						Name:       "https",
						Port:       servicePortControllerHttps,
						Protocol:   corev1.ProtocolTCP,
						TargetPort: intstr.FromInt(int(targetPortControllerHttps)),
					},
				},
				Selector: getLabels("controller"),
			},
		}

		serviceBackend = &corev1.Service{
			ObjectMeta: metav1.ObjectMeta{
				Name:      serviceNameBackend,
				Labels:    map[string]string{v1beta1constants.LabelApp: LabelAppValue},
				Namespace: n.namespace,
			},
			Spec: corev1.ServiceSpec{
				Type: corev1.ServiceTypeClusterIP,
				Ports: []corev1.ServicePort{{
					Port:       servicePortBackend,
					TargetPort: intstr.FromInt(int(targetPortBackend)),
				}},
				Selector: getLabels("backend"),
			},
		}

		podDisruptionBudgetController = &policyv1beta1.PodDisruptionBudget{
			ObjectMeta: metav1.ObjectMeta{
				Name:      controllerName,
				Namespace: n.namespace,
				Labels: map[string]string{
					v1beta1constants.LabelApp: LabelAppValue,
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
				Labels:    map[string]string{v1beta1constants.LabelApp: LabelAppValue},
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
				Labels:    map[string]string{v1beta1constants.LabelApp: LabelAppValue},
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
				Labels: map[string]string{v1beta1constants.LabelApp: LabelAppValue},
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
					APIGroups: []string{"extensions", "\"networking.k8s.io\""},
					Resources: []string{"ingresses"},
					Verbs:     []string{"get", "list", "watch"},
				},
				{
					APIGroups: []string{""},
					Resources: []string{"events"},
					Verbs:     []string{"create", "patch"},
				},
				{
					APIGroups: []string{"extensions", "\"networking.k8s.io\""},
					Resources: []string{"ingresses/status"},
					Verbs:     []string{"update"},
				},
				{
					APIGroups: []string{"\"networking.k8s.io\""},
					Resources: []string{"ingressclasses"},
					Verbs:     []string{"get", "list", "watch"},
				},
			},
		}

		clusterRoleBinding = &rbacv1.ClusterRoleBinding{
			ObjectMeta: metav1.ObjectMeta{
				Name:   "gardener.cloud:seed:" + name,
				Labels: map[string]string{v1beta1constants.LabelApp: LabelAppValue},
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

		deploymentController = &appsv1.Deployment{
			ObjectMeta: metav1.ObjectMeta{
				Name:      controllerName,
				Namespace: n.namespace,
				Labels: map[string]string{
					v1beta1constants.LabelApp: LabelAppValue,
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
	)

	return registry.AddAllAndSerialize(
		serviceAccount,
		vpa,
		deploymentController,
		clusterRole,
		clusterRoleBinding,
		serviceController,
		serviceBackend,
		podDisruptionBudgetController,
		roleBackend,
		roleBindingBackend,
	)
}

func getLabels(resourceType string) map[string]string {
	labels := map[string]string{
		v1beta1constants.LabelApp: LabelAppValue,
		"release":                 "addons",
	}
	if resourceType == "controller" {
		labels[labelKeyComponent] = labelValueController
	} else {
		labels[labelKeyComponent] = labelValueBackend
	}

	return labels
}
