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

package vpnshoot_test

import (
	"context"

	gardencorev1beta1 "github.com/gardener/gardener/pkg/apis/core/v1beta1"
	resourcesv1alpha1 "github.com/gardener/gardener/pkg/apis/resources/v1alpha1"
	"github.com/gardener/gardener/pkg/client/kubernetes"
	. "github.com/gardener/gardener/pkg/operation/botanist/component/vpnshoot"
	"github.com/gardener/gardener/pkg/utils/retry"
	retryfake "github.com/gardener/gardener/pkg/utils/retry/fake"
	"github.com/gardener/gardener/pkg/utils/test"
	. "github.com/gardener/gardener/pkg/utils/test/matchers"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/utils/pointer"
	"sigs.k8s.io/controller-runtime/pkg/client"
	fakeclient "sigs.k8s.io/controller-runtime/pkg/client/fake"
)

var _ = Describe("VPNShoot", func() {
	var (
		ctx = context.TODO()

		managedResourceName = "shoot-core-vpn-shoot"
		namespace           = "some-namespace"
		image               = "some-image:some-tag"

		c        client.Client
		vpnShoot Interface

		managedResource       *resourcesv1alpha1.ManagedResource
		managedResourceSecret *corev1.Secret

		// secretTLSAuthYAML = `apiVersion: v1
		// data:
		//   bar: YmF6
		// immutable: true
		// kind: Secret
		// metadata:
		//   creationTimestamp: null
		//   labels:
		//   resources.gardener.cloud/garbage-collectable-reference: "true"
		//   name: ` + SecretNameTLSAuth + `
		//   namespace: kube-system
		// type: Opaque
		// `

		// 		deploymentYAML = `apiVersion: apps/v1
		// kind: Deployment
		// metadata:
		//   annotations:
		//     ` + references.AnnotationKey(references.KindSecret, SecretName) + `: ` + SecretName + `
		//   creationTimestamp: null
		//   labels:
		//     gardener.cloud/role: system-component
		// 	app: vpn-shoot
		//     origin: gardener
		// spec:
		//   revisionHistoryLimit: 1
		//   replicas: 1
		//   strategy:
		//     rollingUpdate:
		// 	  maxSurge: 100%
		// 	  maxUnavailable: 0%
		// 	type: RollingUpdate
		//   selector:
		//     matchLabels:
		//       app: vpn-shoot
		//   template:
		//     metadata:
		//       annotations:
		// 	    ` + references.AnnotationKey(references.KindSecret, SecretName) + `: ` + SecretName + `
		// 	  creationTimestamp: null
		//       labels:
		//         origin: gardener
		//         gardener.cloud/role: system-component
		//         app: vpn-shoot
		//         type: tunnel
		// `
		clusterRoleYAML = `apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata:
  creationTimestamp: null
  name: system:gardener.cloud:vpn-seed
rules:
- apiGroups:
  - ""
  resourceNames:
  - vpn-shoot
  resources:
  - services
  verbs:
  - get
`
		clusterRoleBindingYAML = `apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRoleBinding
metadata:
  annotations:
    resources.gardener.cloud/delete-on-invalid-update: "true"
  creationTimestamp: null
  name: system:gardener.cloud:vpn-seed
roleRef:
  apiGroup: rbac.authorization.k8s.io
  kind: ClusterRole
  name: system:gardener.cloud:vpn-seed
subjects:
- kind: User
  name: vpn-seed
`
		networkPolicyYAML = `apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  annotations:
    gardener.cloud/description: Allows the VPN to communicate with shoot components
      and makes the VPN reachable from the seed.
  creationTimestamp: null
  name: gardener.cloud--allow-vpn
  namespace: kube-system
spec:
  egress:
  - {}
  ingress:
  - {}
  podSelector:
    matchLabels:
      app: vpn-shoot
  policyTypes:
  - Egress
  - Ingress
`
		serviceAccountYAML = `apiVersion: v1
kind: ServiceAccount
metadata:
  creationTimestamp: null
  labels:
    app: vpn-shoot
  name: vpn-shoot
  namespace: kube-system
`
		serviceYAML = `apiVersion: v1
kind: Service
metadata:
  creationTimestamp: null
  labels:
    app: vpn-shoot
  name: vpn-shoot
  namespace: kube-system
spec:
  ports:
  - name: openvpn
    port: 4314
    protocol: TCP
    targetPort: 1194
  selector:
    app: vpn-shoot
  type: LoadBalancer
status:
  loadBalancer: {}
`
		vpaYAML = `apiVersion: autoscaling.k8s.io/v1beta2
kind: VerticalPodAutoscaler
metadata:
  creationTimestamp: null
  name: vpn-shoot
  namespace: kube-system
spec:
  resourcePolicy:
    containerPolicies:
    - containerName: '*'
      minAllowed:
        cpu: 10m
        memory: 10Mi
  targetRef:
    apiVersion: apps/v1
    kind: Deployment
    name: vpn-shoot
  updatePolicy:
    updateMode: Auto
status: {}
`
	)

	BeforeEach(func() {
		c = fakeclient.NewClientBuilder().WithScheme(kubernetes.SeedScheme).Build()
		values := Values{
			Image:      image,
			VPAEnabled: true,
		}
		vpnShoot = New(c, namespace, values)

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

	//TODO(shafeeqes): Add test for w/0 VPA case
	Describe("#Deploy", func() {
		It("should succesfully deploy all resources", func() {

			Expect(c.Get(ctx, client.ObjectKeyFromObject(managedResource), managedResource)).To(MatchError(apierrors.NewNotFound(schema.GroupResource{
				Group:    resourcesv1alpha1.SchemeGroupVersion.Group,
				Resource: "managedresources",
			}, managedResource.Name)))

			Expect(c.Get(ctx, client.ObjectKeyFromObject(managedResourceSecret), managedResourceSecret)).To(MatchError(apierrors.NewNotFound(schema.GroupResource{
				Group:    corev1.SchemeGroupVersion.Group,
				Resource: "secrets",
			}, managedResourceSecret.Name)))

			Expect(vpnShoot.Deploy(ctx)).To(Succeed())

			Expect(c.Get(ctx, client.ObjectKeyFromObject(managedResource), managedResource)).To(Succeed())

			Expect(managedResource).To(DeepEqual(&resourcesv1alpha1.ManagedResource{
				TypeMeta: metav1.TypeMeta{
					APIVersion: resourcesv1alpha1.SchemeGroupVersion.String(),
					Kind:       "ManagedResource",
				},
				ObjectMeta: metav1.ObjectMeta{
					Name:            managedResource.Name,
					Namespace:       managedResource.Namespace,
					ResourceVersion: "1",
					Labels:          map[string]string{"origin": "gardener"},
				},
				Spec: resourcesv1alpha1.ManagedResourceSpec{
					InjectLabels: map[string]string{"shoot.gardener.cloud/no-cleanup": "true"},
					SecretRefs: []corev1.LocalObjectReference{{
						Name: managedResourceSecret.Name,
					}},
					KeepObjects: pointer.BoolPtr(false),
				},
			}))

			Expect(c.Get(ctx, client.ObjectKeyFromObject(managedResourceSecret), managedResourceSecret)).To(Succeed())
			Expect(managedResourceSecret.Type).To(Equal(corev1.SecretTypeOpaque))
			Expect(managedResourceSecret.Data).To(HaveLen(10))

			Expect(string(managedResourceSecret.Data["clusterrole____system_gardener.cloud_vpn-seed.yaml"])).To(Equal(clusterRoleYAML))
			Expect(string(managedResourceSecret.Data["clusterrolebinding____system_gardener.cloud_vpn-seed.yaml"])).To(Equal(clusterRoleBindingYAML))
			Expect(string(managedResourceSecret.Data["networkpolicy__kube-system__gardener.cloud--allow-vpn.yaml"])).To(Equal(networkPolicyYAML))
			Expect(string(managedResourceSecret.Data["serviceaccount__kube-system__vpn-shoot.yaml"])).To(Equal(serviceAccountYAML))
			Expect(string(managedResourceSecret.Data["service__kube-system__vpn-shoot.yaml"])).To(Equal(serviceYAML))
			Expect(string(managedResourceSecret.Data["verticalpodautoscaler__kube-system__vpn-shoot.yaml"])).To(Equal(vpaYAML))
			//Expect(string(managedResourceSecret.Data["secret__kube-system__"+SecretNameTLSAuth+".yaml"])).To(Equal(secretTLSAuthYAML))
			//Expect(string(managedResourceSecret.Data["deployment__kube-system__vpn-shoot.yaml"])).To(Equal(deploymentYAML))

		})
	})

	Describe("#Destroy", func() {
		It("should successfully destroy all resources", func() {
			Expect(c.Create(ctx, managedResource)).To(Succeed())
			Expect(c.Create(ctx, managedResourceSecret)).To(Succeed())

			Expect(c.Get(ctx, client.ObjectKeyFromObject(managedResource), managedResource)).To(Succeed())
			Expect(c.Get(ctx, client.ObjectKeyFromObject(managedResourceSecret), managedResourceSecret)).To(Succeed())

			Expect(vpnShoot.Destroy(ctx)).To(Succeed())

			Expect(c.Get(ctx, client.ObjectKeyFromObject(managedResource), managedResource)).To(MatchError(apierrors.NewNotFound(schema.GroupResource{Group: resourcesv1alpha1.SchemeGroupVersion.Group, Resource: "managedresources"}, managedResource.Name)))
			Expect(c.Get(ctx, client.ObjectKeyFromObject(managedResourceSecret), managedResourceSecret)).To(MatchError(apierrors.NewNotFound(schema.GroupResource{Group: corev1.SchemeGroupVersion.Group, Resource: "secrets"}, managedResourceSecret.Name)))
		})
	})

	Context("waiting functions", func() {
		var (
			fakeOps   *retryfake.Ops
			resetVars func()
		)

		BeforeEach(func() {
			fakeOps = &retryfake.Ops{MaxAttempts: 1}
			resetVars = test.WithVars(
				&retry.Until, fakeOps.Until,
				&retry.UntilTimeout, fakeOps.UntilTimeout,
			)
		})

		AfterEach(func() {
			resetVars()
		})

		Describe("#Wait", func() {
			It("should fail because reading the ManagedResource fails", func() {
				Expect(vpnShoot.Wait(ctx)).To(MatchError(ContainSubstring("not found")))
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
				}))

				Expect(vpnShoot.Wait(ctx)).To(MatchError(ContainSubstring("is not healthy")))
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
				}))

				Expect(vpnShoot.Wait(ctx)).To(Succeed())
			})
		})

		Describe("#WaitCleanup", func() {
			It("should fail when the wait for the managed resource deletion times out", func() {
				fakeOps.MaxAttempts = 2

				Expect(c.Create(ctx, managedResource)).To(Succeed())

				Expect(vpnShoot.WaitCleanup(ctx)).To(MatchError(ContainSubstring("still exists")))
			})

			It("should not return an error when it's already removed", func() {
				Expect(vpnShoot.WaitCleanup(ctx)).To(Succeed())
			})
		})
	})

})
