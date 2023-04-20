// Copyright 2020 SAP SE or an SAP affiliate company. All rights reserved. This file is licensed under the Apache Software License, v. 2 except as noted otherwise in the LICENSE file
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

package kubecontrollermanager

import (
	"context"
	"fmt"
	"time"

	"github.com/Masterminds/semver"
	"github.com/go-logr/logr"
	"github.com/golang/mock/gomock"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	appsv1 "k8s.io/api/apps/v1"
	coordinationv1 "k8s.io/api/coordination/v1"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"sigs.k8s.io/controller-runtime/pkg/client"

	"github.com/gardener/gardener/pkg/client/kubernetes"
	kubernetesfake "github.com/gardener/gardener/pkg/client/kubernetes/fake"
	mockclient "github.com/gardener/gardener/pkg/mock/controller-runtime/client"
	kubernetesutils "github.com/gardener/gardener/pkg/utils/kubernetes"
	"github.com/gardener/gardener/pkg/utils/retry"
	retryfake "github.com/gardener/gardener/pkg/utils/retry/fake"
	"github.com/gardener/gardener/pkg/utils/test"
)

var _ = Describe("WaiterTest", func() {
	var (
		ctx                   = context.TODO()
		testLogger            = logr.Discard()
		errorMsg              = "fake error"
		fakeErr               = fmt.Errorf(errorMsg)
		kubeControllerManager Interface
		namespace             = "shoot--foo--bar"
		version               = semver.MustParse("v1.21.8")
		isWorkerless          = false

		// mock
		ctrl              *gomock.Controller
		fakeSeedInterface kubernetes.Interface
		seedClient        *mockclient.MockClient
		shootClient       *mockclient.MockClient
		waiter            *retryfake.Ops
		cleanupFunc       func()

		listOptions = []client.ListOption{
			client.InNamespace(namespace),
			client.MatchingLabels(map[string]string{
				"app":  "kubernetes",
				"role": "controller-manager",
			}),
		}
	)

	BeforeEach(func() {
		ctrl = gomock.NewController(GinkgoT())
		seedClient = mockclient.NewMockClient(ctrl)
		fakeSeedInterface = kubernetesfake.NewClientSetBuilder().WithAPIReader(seedClient).WithClient(seedClient).Build()
		shootClient = mockclient.NewMockClient(ctrl)
	})

	AfterEach(func() {
		ctrl.Finish()
		cleanupFunc()
	})

	Describe("#WaitForControllerToBeActive", func() {
		BeforeEach(func() {
			kubeControllerManager = New(
				testLogger,
				fakeSeedInterface,
				namespace,
				nil,
				version,
				"",
				nil,
				isWorkerless,
				nil,
				nil,
				nil,
				semver.MustParse("1.25.0"),
			)

			kubeControllerManager.SetShootClient(shootClient)

			waiter = &retryfake.Ops{MaxAttempts: 1}
			cleanupFunc = test.WithVars(
				&retry.Until, waiter.Until,
				&retry.UntilTimeout, waiter.UntilTimeout,
			)
		})

		It("should fail if the seed client cannot talk to the Seed API Server", func() {
			gomock.InOrder(
				seedClient.EXPECT().Get(ctx, kubernetesutils.Key(namespace, "kube-controller-manager"), gomock.AssignableToTypeOf(&appsv1.Deployment{})).Return(fakeErr),
			)

			Expect(kubeControllerManager.WaitForControllerToBeActive(ctx)).To(MatchError(fakeErr))
		})

		It("should fail if the kube controller manager deployment does not exist", func() {
			notFoundError := apierrors.NewNotFound(schema.GroupResource{}, "kube-controller-manager")
			gomock.InOrder(
				seedClient.EXPECT().Get(ctx, kubernetesutils.Key(namespace, "kube-controller-manager"), gomock.AssignableToTypeOf(&appsv1.Deployment{})).Return(notFoundError),
			)

			Expect(kubeControllerManager.WaitForControllerToBeActive(ctx)).To(MatchError("kube controller manager deployment not found:  \"kube-controller-manager\" not found"))
		})

		It("should fail if it fails to list pods in the shoot namespace in the Seed", func() {
			gomock.InOrder(
				seedClient.EXPECT().Get(ctx, kubernetesutils.Key(namespace, "kube-controller-manager"), gomock.AssignableToTypeOf(&appsv1.Deployment{})),
				seedClient.EXPECT().List(gomock.Any(), gomock.AssignableToTypeOf(&corev1.PodList{}), listOptions).Return(fakeErr),
			)

			Expect(kubeControllerManager.WaitForControllerToBeActive(ctx)).To(MatchError(fmt.Sprintf("could not check whether controller kube-controller-manager is active: %s", errorMsg)))
		})

		It("should fail if no kube controller manager pod can be found", func() {
			gomock.InOrder(
				seedClient.EXPECT().Get(ctx, kubernetesutils.Key(namespace, "kube-controller-manager"), gomock.AssignableToTypeOf(&appsv1.Deployment{})),
				seedClient.EXPECT().List(gomock.Any(), gomock.AssignableToTypeOf(&corev1.PodList{}), listOptions).DoAndReturn(func(_ context.Context, list *corev1.PodList, _ ...client.ListOption) error {
					*list = corev1.PodList{Items: []corev1.Pod{}}
					return nil
				}),
			)

			Expect(kubeControllerManager.WaitForControllerToBeActive(ctx)).To(MatchError(Equal("retry failed with max attempts reached, last error: controller kube-controller-manager is not active")))
		})

		It("should fail if one of the existing kube controller manager pods has a deletion timestamp", func() {
			gomock.InOrder(
				seedClient.EXPECT().Get(ctx, kubernetesutils.Key(namespace, "kube-controller-manager"), gomock.AssignableToTypeOf(&appsv1.Deployment{})),
				seedClient.EXPECT().List(gomock.Any(), gomock.AssignableToTypeOf(&corev1.PodList{}), listOptions).DoAndReturn(func(_ context.Context, list *corev1.PodList, _ ...client.ListOption) error {
					now := metav1.Now()
					*list = corev1.PodList{Items: []corev1.Pod{
						{ObjectMeta: metav1.ObjectMeta{Name: "pod1"}},
						{ObjectMeta: metav1.ObjectMeta{Name: "pod2", DeletionTimestamp: &now}},
					}}
					return nil
				}),
			)

			Expect(kubeControllerManager.WaitForControllerToBeActive(ctx)).To(MatchError(Equal("retry failed with max attempts reached, last error: controller kube-controller-manager is not active")))
		})

		It("should fail if the existing kube controller manager fails to acquire leader election", func() {
			gomock.InOrder(
				seedClient.EXPECT().Get(ctx, kubernetesutils.Key(namespace, "kube-controller-manager"), gomock.AssignableToTypeOf(&appsv1.Deployment{})),
				seedClient.EXPECT().List(gomock.Any(), gomock.AssignableToTypeOf(&corev1.PodList{}), listOptions).DoAndReturn(func(_ context.Context, list *corev1.PodList, _ ...client.ListOption) error {
					*list = corev1.PodList{Items: []corev1.Pod{
						{ObjectMeta: metav1.ObjectMeta{Name: "pod1"}},
					}}
					return nil
				}),
				shootClient.EXPECT().Get(ctx, kubernetesutils.Key(metav1.NamespaceSystem, "kube-controller-manager"), gomock.AssignableToTypeOf(&coordinationv1.Lease{})).DoAndReturn(func(_ context.Context, _ client.ObjectKey, actual *coordinationv1.Lease, _ ...client.GetOption) error {
					*actual = coordinationv1.Lease{
						Spec: coordinationv1.LeaseSpec{
							RenewTime: &metav1.MicroTime{Time: time.Now().UTC().Add(-10 * time.Second)},
						},
					}
					return nil
				}),
			)

			Expect(kubeControllerManager.WaitForControllerToBeActive(ctx)).To(MatchError(Equal("retry failed with max attempts reached, last error: controller kube-controller-manager is not active")))
		})

		It("should succeed", func() {
			gomock.InOrder(
				seedClient.EXPECT().Get(ctx, kubernetesutils.Key(namespace, "kube-controller-manager"), gomock.AssignableToTypeOf(&appsv1.Deployment{})),
				seedClient.EXPECT().List(gomock.Any(), gomock.AssignableToTypeOf(&corev1.PodList{}), listOptions).DoAndReturn(func(_ context.Context, list *corev1.PodList, _ ...client.ListOption) error {
					*list = corev1.PodList{Items: []corev1.Pod{
						{ObjectMeta: metav1.ObjectMeta{Name: "pod1"}},
					}}
					return nil
				}),
				shootClient.EXPECT().Get(ctx, kubernetesutils.Key(metav1.NamespaceSystem, "kube-controller-manager"), gomock.AssignableToTypeOf(&coordinationv1.Lease{})).DoAndReturn(func(_ context.Context, _ client.ObjectKey, actual *coordinationv1.Lease, _ ...client.GetOption) error {
					*actual = coordinationv1.Lease{
						Spec: coordinationv1.LeaseSpec{
							RenewTime: &metav1.MicroTime{Time: time.Now().UTC()},
						},
					}
					return nil
				}),
			)

			Expect(kubeControllerManager.WaitForControllerToBeActive(ctx)).To(Succeed())
		})
	})
})
