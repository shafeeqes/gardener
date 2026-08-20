// SPDX-FileCopyrightText: SAP SE or an SAP affiliate company and Gardener contributors
//
// SPDX-License-Identifier: Apache-2.0

package apiserver

import (
	rbacv1 "k8s.io/api/rbac/v1"

	resourcesv1alpha1 "github.com/gardener/gardener/pkg/apis/resources/v1alpha1"
	"github.com/gardener/gardener/pkg/client/kubernetes"
	"github.com/gardener/gardener/pkg/utils/managedresources"
)

// ManagedResourceName is the name of the ManagedResource containing the resource specifications.
const ManagedResourceName = "shoot-core-kube-apiserver"

func (k *kubeAPIServer) emptyManagedResource() *resourcesv1alpha1.ManagedResource {
	return &resourcesv1alpha1.ManagedResource{Name: ManagedResourceName, Namespace: k.namespace}
}

func (k *kubeAPIServer) computeShootResourcesData() (map[string][]byte, error) {
	var (
		registry = managedresources.NewRegistry(kubernetes.ShootScheme, kubernetes.ShootCodec, kubernetes.ShootSerializer)

		clusterRole = &rbacv1.ClusterRole{
			Name: "system:apiserver:kubelet",
			Rules: []rbacv1.PolicyRule{
				{
					APIGroups: []string{""},
					Resources: []string{
						"nodes/proxy",
						"nodes/stats",
						"nodes/log",
						"nodes/spec",
						"nodes/metrics",
					},
					Verbs: []string{"create", "get", "update", "patch", "delete"},
				},
				{
					NonResourceURLs: []string{"*"},
					Verbs:           []string{"create", "get", "update", "patch", "delete"},
				},
			},
		}

		clusterRoleBinding = &rbacv1.ClusterRoleBinding{
			Name:        "system:apiserver:kubelet",
			Annotations: map[string]string{resourcesv1alpha1.DeleteOnInvalidUpdate: "true"},
			RoleRef: rbacv1.RoleRef{
				APIGroup: rbacv1.GroupName,
				Kind:     "ClusterRole",
				Name:     clusterRole.Name,
			},
			Subjects: []rbacv1.Subject{{
				Kind: rbacv1.UserKind,
				Name: userName,
			}},
		}
	)

	return registry.AddAllAndSerialize(
		clusterRole,
		clusterRoleBinding,
	)
}
