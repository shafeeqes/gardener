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

package controller_test

import (
	"context"
	"fmt"
	"strings"

	. "github.com/gardener/gardener/extensions/pkg/controller"
	gardencorev1beta1 "github.com/gardener/gardener/pkg/apis/core/v1beta1"
	extensionsv1alpha1 "github.com/gardener/gardener/pkg/apis/extensions/v1alpha1"
	mockclient "github.com/gardener/gardener/pkg/mock/controller-runtime/client"
	kutil "github.com/gardener/gardener/pkg/utils/kubernetes"

	"github.com/go-logr/logr"
	"github.com/golang/mock/gomock"
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"
	logzap "sigs.k8s.io/controller-runtime/pkg/log/zap"
)

var _ = Describe("Status", func() {
	var (
		ctx     = context.TODO()
		fakeErr = fmt.Errorf("fake")

		generation int64 = 1337
		lastOpType       = gardencorev1beta1.LastOperationTypeCreate
		lastOpDesc       = "foo"

		ctrl   *gomock.Controller
		logger logr.Logger
		c      *mockclient.MockClient

		statusUpdater StatusUpdater
		obj           extensionsv1alpha1.Object
	)

	BeforeEach(func() {
		ctrl = gomock.NewController(GinkgoT())
		logger = logzap.New(logzap.WriteTo(GinkgoWriter))
		c = mockclient.NewMockClient(ctrl)

		statusUpdater = NewStatusUpdater(logger)
		statusUpdater.InjectClient(c)

		obj = &extensionsv1alpha1.Infrastructure{
			ObjectMeta: metav1.ObjectMeta{
				Generation: generation,
			},
		}
	})

	AfterEach(func() {
		ctrl.Finish()
	})

	Describe("#Processing", func() {
		It("should return an error if the Get() call fails", func() {
			gomock.InOrder(
				c.EXPECT().Status().Return(c),
				c.EXPECT().Get(ctx, kutil.Key(obj.GetNamespace(), obj.GetName()), gomock.AssignableToTypeOf(&extensionsv1alpha1.Infrastructure{})).Return(fakeErr),
			)

			Expect(statusUpdater.Processing(ctx, obj, lastOpType, lastOpDesc)).To(MatchError(fakeErr))
		})

		It("should return an error if the Update() call fails", func() {
			gomock.InOrder(
				c.EXPECT().Status().Return(c),
				c.EXPECT().Get(ctx, kutil.Key(obj.GetNamespace(), obj.GetName()), gomock.AssignableToTypeOf(&extensionsv1alpha1.Infrastructure{})),
				c.EXPECT().Update(ctx, gomock.AssignableToTypeOf(&extensionsv1alpha1.Infrastructure{})).Return(fakeErr),
			)

			Expect(statusUpdater.Processing(ctx, obj, lastOpType, lastOpDesc)).To(MatchError(fakeErr))
		})

		It("should update the last operation as expected", func() {
			gomock.InOrder(
				c.EXPECT().Status().Return(c),
				c.EXPECT().Get(ctx, kutil.Key(obj.GetNamespace(), obj.GetName()), gomock.AssignableToTypeOf(&extensionsv1alpha1.Infrastructure{})),
				c.EXPECT().Update(ctx, gomock.AssignableToTypeOf(&extensionsv1alpha1.Infrastructure{})).Do(func(ctx context.Context, obj extensionsv1alpha1.Object, opts ...client.UpdateOption) {
					lastOperation := obj.GetExtensionStatus().GetLastOperation()

					Expect(lastOperation.Type).To(Equal(lastOpType))
					Expect(lastOperation.State).To(Equal(gardencorev1beta1.LastOperationStateProcessing))
					Expect(lastOperation.Progress).To(Equal(int32(1)))
					Expect(lastOperation.Description).To(Equal(lastOpDesc))
				}),
			)

			Expect(statusUpdater.Processing(ctx, obj, lastOpType, lastOpDesc)).To(Succeed())
		})
	})

	Describe("#Error", func() {
		It("should return an error if the Get() call fails", func() {
			gomock.InOrder(
				c.EXPECT().Status().Return(c),
				c.EXPECT().Get(ctx, kutil.Key(obj.GetNamespace(), obj.GetName()), gomock.AssignableToTypeOf(&extensionsv1alpha1.Infrastructure{})).Return(fakeErr),
			)

			Expect(statusUpdater.Error(ctx, obj, fakeErr, lastOpType, lastOpDesc)).To(MatchError(fakeErr))
		})

		It("should return an error if the Update() call fails", func() {
			gomock.InOrder(
				c.EXPECT().Status().Return(c),
				c.EXPECT().Get(ctx, kutil.Key(obj.GetNamespace(), obj.GetName()), gomock.AssignableToTypeOf(&extensionsv1alpha1.Infrastructure{})),
				c.EXPECT().Update(ctx, gomock.AssignableToTypeOf(&extensionsv1alpha1.Infrastructure{})).Return(fakeErr),
			)

			Expect(statusUpdater.Error(ctx, obj, fakeErr, lastOpType, lastOpDesc)).To(MatchError(fakeErr))
		})

		It("should update the last operation as expected (w/o error codes)", func() {
			gomock.InOrder(
				c.EXPECT().Status().Return(c),
				c.EXPECT().Get(ctx, kutil.Key(obj.GetNamespace(), obj.GetName()), gomock.AssignableToTypeOf(&extensionsv1alpha1.Infrastructure{})),
				c.EXPECT().Update(ctx, gomock.AssignableToTypeOf(&extensionsv1alpha1.Infrastructure{})).Do(func(ctx context.Context, obj extensionsv1alpha1.Object, opts ...client.UpdateOption) {
					var (
						description = strings.Title(lastOpDesc) + ": " + fakeErr.Error()

						lastOperation      = obj.GetExtensionStatus().GetLastOperation()
						lastError          = obj.GetExtensionStatus().GetLastError()
						observedGeneration = obj.GetExtensionStatus().GetObservedGeneration()
					)

					Expect(observedGeneration).To(Equal(generation))

					Expect(lastOperation.Type).To(Equal(lastOpType))
					Expect(lastOperation.State).To(Equal(gardencorev1beta1.LastOperationStateError))
					Expect(lastOperation.Progress).To(Equal(int32(50)))
					Expect(lastOperation.Description).To(Equal(description))

					Expect(lastError.Description).To(Equal(description))
					Expect(lastError.TaskID).To(BeNil())
					Expect(lastError.Codes).To(BeEmpty())
				}),
			)

			Expect(statusUpdater.Error(ctx, obj, fakeErr, lastOpType, lastOpDesc)).To(Succeed())
		})

		It("should update the last operation as expected (w/ error codes)", func() {
			err := fmt.Errorf("foo unauthorized foo")

			gomock.InOrder(
				c.EXPECT().Status().Return(c),
				c.EXPECT().Get(ctx, kutil.Key(obj.GetNamespace(), obj.GetName()), gomock.AssignableToTypeOf(&extensionsv1alpha1.Infrastructure{})),
				c.EXPECT().Update(ctx, gomock.AssignableToTypeOf(&extensionsv1alpha1.Infrastructure{})).Do(func(ctx context.Context, obj extensionsv1alpha1.Object, opts ...client.UpdateOption) {
					var (
						description = strings.Title(lastOpDesc) + ": " + err.Error()

						lastOperation      = obj.GetExtensionStatus().GetLastOperation()
						lastError          = obj.GetExtensionStatus().GetLastError()
						observedGeneration = obj.GetExtensionStatus().GetObservedGeneration()
					)

					Expect(observedGeneration).To(Equal(generation))

					Expect(lastOperation.Type).To(Equal(lastOpType))
					Expect(lastOperation.State).To(Equal(gardencorev1beta1.LastOperationStateError))
					Expect(lastOperation.Progress).To(Equal(int32(50)))
					Expect(lastOperation.Description).To(Equal(description))

					Expect(lastError.Description).To(Equal(description))
					Expect(lastError.TaskID).To(BeNil())
					Expect(lastError.Codes).To(ConsistOf(gardencorev1beta1.ErrorInfraUnauthenticated))
				}),
			)

			Expect(statusUpdater.Error(ctx, obj, err, lastOpType, lastOpDesc)).To(Succeed())
		})
	})

	Describe("#Success", func() {
		It("should return an error if the Get() call fails", func() {
			gomock.InOrder(
				c.EXPECT().Status().Return(c),
				c.EXPECT().Get(ctx, kutil.Key(obj.GetNamespace(), obj.GetName()), gomock.AssignableToTypeOf(&extensionsv1alpha1.Infrastructure{})).Return(fakeErr),
			)

			Expect(statusUpdater.Success(ctx, obj, lastOpType, lastOpDesc)).To(MatchError(fakeErr))
		})

		It("should return an error if the Update() call fails", func() {
			gomock.InOrder(
				c.EXPECT().Status().Return(c),
				c.EXPECT().Get(ctx, kutil.Key(obj.GetNamespace(), obj.GetName()), gomock.AssignableToTypeOf(&extensionsv1alpha1.Infrastructure{})),
				c.EXPECT().Update(ctx, gomock.AssignableToTypeOf(&extensionsv1alpha1.Infrastructure{})).Return(fakeErr),
			)

			Expect(statusUpdater.Success(ctx, obj, lastOpType, lastOpDesc)).To(MatchError(fakeErr))
		})

		It("should update the last operation as expected", func() {
			gomock.InOrder(
				c.EXPECT().Status().Return(c),
				c.EXPECT().Get(ctx, kutil.Key(obj.GetNamespace(), obj.GetName()), gomock.AssignableToTypeOf(&extensionsv1alpha1.Infrastructure{})),
				c.EXPECT().Update(ctx, gomock.AssignableToTypeOf(&extensionsv1alpha1.Infrastructure{})).Do(func(ctx context.Context, obj extensionsv1alpha1.Object, opts ...client.UpdateOption) {
					var (
						lastOperation      = obj.GetExtensionStatus().GetLastOperation()
						lastError          = obj.GetExtensionStatus().GetLastError()
						observedGeneration = obj.GetExtensionStatus().GetObservedGeneration()
					)

					Expect(observedGeneration).To(Equal(generation))

					Expect(lastOperation.Type).To(Equal(lastOpType))
					Expect(lastOperation.State).To(Equal(gardencorev1beta1.LastOperationStateSucceeded))
					Expect(lastOperation.Progress).To(Equal(int32(100)))
					Expect(lastOperation.Description).To(Equal(lastOpDesc))

					Expect(lastError).To(BeNil())
				}),
			)

			Expect(statusUpdater.Success(ctx, obj, lastOpType, lastOpDesc)).To(Succeed())
		})
	})
})
