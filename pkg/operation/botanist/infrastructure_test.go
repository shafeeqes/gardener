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

package botanist_test

import (
	"context"
	"fmt"

	"github.com/golang/mock/gomock"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/utils/pointer"
	"sigs.k8s.io/controller-runtime/pkg/client"
	fakeclient "sigs.k8s.io/controller-runtime/pkg/client/fake"

	gardencorev1beta1 "github.com/gardener/gardener/pkg/apis/core/v1beta1"
	"github.com/gardener/gardener/pkg/client/kubernetes"
	kubernetesmock "github.com/gardener/gardener/pkg/client/kubernetes/mock"
	mockclient "github.com/gardener/gardener/pkg/mock/controller-runtime/client"
	"github.com/gardener/gardener/pkg/operation"
	. "github.com/gardener/gardener/pkg/operation/botanist"
	mockinfrastructure "github.com/gardener/gardener/pkg/operation/botanist/component/extensions/infrastructure/mock"
	shootpkg "github.com/gardener/gardener/pkg/operation/shoot"
	secretsmanager "github.com/gardener/gardener/pkg/utils/secrets/manager"
	fakesecretsmanager "github.com/gardener/gardener/pkg/utils/secrets/manager/fake"
	"github.com/gardener/gardener/pkg/utils/test"
)

var _ = Describe("Infrastructure", func() {
	var (
		ctrl           *gomock.Controller
		infrastructure *mockinfrastructure.MockInterface

		fakeClient client.Client
		sm         secretsmanager.Interface
		botanist   *Botanist

		ctx        = context.TODO()
		namespace  = "namespace"
		fakeErr    = fmt.Errorf("fake")
		shootState = &gardencorev1beta1.ShootState{}
	)

	BeforeEach(func() {
		ctrl = gomock.NewController(GinkgoT())
		infrastructure = mockinfrastructure.NewMockInterface(ctrl)

		fakeClient = fakeclient.NewClientBuilder().WithScheme(kubernetes.SeedScheme).Build()
		sm = fakesecretsmanager.New(fakeClient, namespace)

		By("Create secrets managed outside of this function for whose secretsmanager.Get() will be called")
		Expect(fakeClient.Create(ctx, &corev1.Secret{ObjectMeta: metav1.ObjectMeta{Name: "ssh-keypair", Namespace: namespace}})).To(Succeed())

		botanist = &Botanist{
			Operation: &operation.Operation{
				SecretsManager: sm,
				Shoot: &shootpkg.Shoot{
					Components: &shootpkg.Components{
						Extensions: &shootpkg.Extensions{
							Infrastructure: infrastructure,
						},
					},
				},
			},
		}
		botanist.SetShootState(shootState)
		botanist.Shoot.SetInfo(&gardencorev1beta1.Shoot{
			Spec: gardencorev1beta1.ShootSpec{
				Provider: gardencorev1beta1.Provider{
					Workers: []gardencorev1beta1.Worker{
						{Name: "foo"},
					},
				},
			},
		})
	})

	AfterEach(func() {
		ctrl.Finish()
	})

	Describe("#DeployInfrastructure", func() {
		BeforeEach(func() {
			infrastructure.EXPECT().SetSSHPublicKey(gomock.Any())
		})

		Context("deploy", func() {
			It("should deploy successfully", func() {
				infrastructure.EXPECT().Deploy(ctx)
				Expect(botanist.DeployInfrastructure(ctx)).To(Succeed())
			})

			It("should return the error during deployment", func() {
				infrastructure.EXPECT().Deploy(ctx).Return(fakeErr)
				Expect(botanist.DeployInfrastructure(ctx)).To(MatchError(fakeErr))
			})
		})

		Context("restore", func() {
			BeforeEach(func() {
				shoot := botanist.Shoot.GetInfo()
				shoot.Status = gardencorev1beta1.ShootStatus{
					LastOperation: &gardencorev1beta1.LastOperation{
						Type: gardencorev1beta1.LastOperationTypeRestore,
					},
				}
				botanist.Shoot.SetInfo(shoot)
			})

			It("should restore successfully", func() {
				infrastructure.EXPECT().Restore(ctx, shootState)
				Expect(botanist.DeployInfrastructure(ctx)).To(Succeed())
			})

			It("should return the error during restoration", func() {
				infrastructure.EXPECT().Restore(ctx, shootState).Return(fakeErr)
				Expect(botanist.DeployInfrastructure(ctx)).To(MatchError(fakeErr))
			})
		})
	})

	Describe("#WaitForInfrastructure", func() {
		var (
			gardenClient  *mockclient.MockClient
			seedClient    *mockclient.MockClient
			seedClientSet *kubernetesmock.MockInterface

			namespace = "namespace"
			name      = "name"
			nodesCIDR = pointer.String("1.2.3.4/5")
			shoot     = &gardencorev1beta1.Shoot{
				ObjectMeta: metav1.ObjectMeta{
					Name:      name,
					Namespace: namespace,
				},
				Spec: gardencorev1beta1.ShootSpec{
					Networking: &gardencorev1beta1.Networking{},
				},
			}
		)

		BeforeEach(func() {
			gardenClient = mockclient.NewMockClient(ctrl)
			seedClient = mockclient.NewMockClient(ctrl)
			seedClientSet = kubernetesmock.NewMockInterface(ctrl)

			botanist.GardenClient = gardenClient
			botanist.SeedClientSet = seedClientSet
			botanist.Shoot.SetInfo(shoot)
		})

		It("should successfully wait (w/ provider status, w/ nodes cidr)", func() {
			infrastructure.EXPECT().Wait(ctx)
			infrastructure.EXPECT().NodesCIDR().Return(nodesCIDR)

			updatedShoot := shoot.DeepCopy()
			updatedShoot.Spec.Networking.Nodes = nodesCIDR
			test.EXPECTPatch(ctx, gardenClient, updatedShoot, shoot, types.StrategicMergePatchType)

			seedClientSet.EXPECT().Client().Return(seedClient)

			Expect(botanist.WaitForInfrastructure(ctx)).To(Succeed())
			Expect(botanist.Shoot.GetInfo()).To(Equal(updatedShoot))
		})

		It("should successfully wait (w/o provider status, w/o nodes cidr)", func() {
			infrastructure.EXPECT().Wait(ctx)
			infrastructure.EXPECT().NodesCIDR()

			Expect(botanist.WaitForInfrastructure(ctx)).To(Succeed())
			Expect(botanist.Shoot.GetInfo()).To(Equal(shoot))
		})

		It("should return the error during wait", func() {
			infrastructure.EXPECT().Wait(ctx).Return(fakeErr)

			Expect(botanist.WaitForInfrastructure(ctx)).To(MatchError(fakeErr))
			Expect(botanist.Shoot.GetInfo()).To(Equal(shoot))
		})

		It("should return the error during nodes cidr update", func() {
			infrastructure.EXPECT().Wait(ctx)
			infrastructure.EXPECT().NodesCIDR().Return(nodesCIDR)

			updatedShoot := shoot.DeepCopy()
			updatedShoot.Spec.Networking.Nodes = nodesCIDR
			test.EXPECTPatch(ctx, gardenClient, updatedShoot, shoot, types.StrategicMergePatchType, fakeErr)

			Expect(botanist.WaitForInfrastructure(ctx)).To(MatchError(fakeErr))
			Expect(botanist.Shoot.GetInfo()).To(Equal(shoot))
		})
	})
})
