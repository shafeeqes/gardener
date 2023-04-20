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

package botanist_test

import (
	"context"
	"fmt"
	"net"
	"time"

	"github.com/golang/mock/gomock"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"
	fakeclient "sigs.k8s.io/controller-runtime/pkg/client/fake"

	gardencorev1beta1 "github.com/gardener/gardener/pkg/apis/core/v1beta1"
	"github.com/gardener/gardener/pkg/client/kubernetes"
	kubernetesmock "github.com/gardener/gardener/pkg/client/kubernetes/mock"
	"github.com/gardener/gardener/pkg/features"
	"github.com/gardener/gardener/pkg/operation"
	. "github.com/gardener/gardener/pkg/operation/botanist"
	mockcoredns "github.com/gardener/gardener/pkg/operation/botanist/component/coredns/mock"
	"github.com/gardener/gardener/pkg/operation/garden"
	shootpkg "github.com/gardener/gardener/pkg/operation/shoot"
	"github.com/gardener/gardener/pkg/utils/imagevector"
	"github.com/gardener/gardener/pkg/utils/test"
)

var _ = Describe("CoreDNS", func() {
	var (
		ctrl     *gomock.Controller
		botanist *Botanist
	)

	BeforeEach(func() {
		ctrl = gomock.NewController(GinkgoT())
		botanist = &Botanist{Operation: &operation.Operation{}}
		botanist.Shoot = &shootpkg.Shoot{}
		botanist.Shoot.SetInfo(&gardencorev1beta1.Shoot{
			Spec: gardencorev1beta1.ShootSpec{
				Kubernetes: gardencorev1beta1.Kubernetes{
					Version: "1.22.1",
				},
				Networking: &gardencorev1beta1.Networking{},
			},
		})
	})

	AfterEach(func() {
		ctrl.Finish()
	})

	Describe("#DefaultCoreDNS", func() {
		var kubernetesClient *kubernetesmock.MockInterface

		BeforeEach(func() {
			kubernetesClient = kubernetesmock.NewMockInterface(ctrl)

			botanist.SeedClientSet = kubernetesClient
			botanist.Shoot.Networks = &shootpkg.Networks{
				CoreDNS: net.ParseIP("18.19.20.21"),
				Pods:    &net.IPNet{IP: net.ParseIP("22.23.24.25")},
			}
			botanist.Garden = &garden.Garden{}
		})

		It("should successfully create a coredns interface", func() {
			defer test.WithFeatureGate(features.DefaultFeatureGate, features.APIServerSNI, true)()

			kubernetesClient.EXPECT().Client()
			botanist.ImageVector = imagevector.ImageVector{{Name: "coredns"}}

			coreDNS, err := botanist.DefaultCoreDNS()
			Expect(coreDNS).NotTo(BeNil())
			Expect(err).NotTo(HaveOccurred())
		})

		It("should return an error because the image cannot be found", func() {
			botanist.ImageVector = imagevector.ImageVector{}

			coreDNS, err := botanist.DefaultCoreDNS()
			Expect(coreDNS).To(BeNil())
			Expect(err).To(HaveOccurred())
		})

		Describe("#WithClusterProportionalAutoscaler", func() {
			BeforeEach(func() {
				botanist.Shoot.SetInfo(&gardencorev1beta1.Shoot{
					Spec: gardencorev1beta1.ShootSpec{
						SystemComponents: &gardencorev1beta1.SystemComponents{
							CoreDNS: &gardencorev1beta1.CoreDNS{
								Autoscaling: &gardencorev1beta1.CoreDNSAutoscaling{
									Mode: gardencorev1beta1.CoreDNSAutoscalingModeClusterProportional,
								},
							},
						},
						Kubernetes: gardencorev1beta1.Kubernetes{
							Version: "1.22.1",
						},
						Networking: &gardencorev1beta1.Networking{},
					},
				})
			})

			It("should successfully create a coredns interface with cluster-proportional autoscaling enabled", func() {
				defer test.WithFeatureGate(features.DefaultFeatureGate, features.APIServerSNI, true)()

				kubernetesClient.EXPECT().Client()
				botanist.ImageVector = imagevector.ImageVector{{Name: "coredns"}, {Name: "cluster-proportional-autoscaler"}}

				coreDNS, err := botanist.DefaultCoreDNS()
				Expect(coreDNS).NotTo(BeNil())
				Expect(err).NotTo(HaveOccurred())
			})

			It("should return an error because the cluster-proportional autoscaler image cannot be found", func() {
				botanist.ImageVector = imagevector.ImageVector{{Name: "coredns"}}
				botanist.APIServerAddress = "coredns-test"

				coreDNS, err := botanist.DefaultCoreDNS()
				Expect(coreDNS).To(BeNil())
				Expect(err).To(HaveOccurred())
			})
		})
	})

	Describe("#DeployCoreDNS", func() {
		var (
			coreDNS          *mockcoredns.MockInterface
			kubernetesClient *kubernetesmock.MockInterface
			c                client.Client

			ctx     = context.TODO()
			fakeErr = fmt.Errorf("fake err")
		)

		BeforeEach(func() {
			coreDNS = mockcoredns.NewMockInterface(ctrl)
			kubernetesClient = kubernetesmock.NewMockInterface(ctrl)
			c = fakeclient.NewClientBuilder().WithScheme(kubernetes.SeedScheme).Build()

			botanist.ShootClientSet = kubernetesClient
			botanist.Shoot.Components = &shootpkg.Components{
				SystemComponents: &shootpkg.SystemComponents{
					CoreDNS: coreDNS,
				},
			}
		})

		It("should fail when the deploy function fails", func() {
			kubernetesClient.EXPECT().Client().Return(c)

			coreDNS.EXPECT().SetPodAnnotations(nil)
			coreDNS.EXPECT().Deploy(ctx).Return(fakeErr)

			Expect(botanist.DeployCoreDNS(ctx)).To(MatchError(fakeErr))
		})

		It("should successfully deploy (coredns deployment not yet found)", func() {
			kubernetesClient.EXPECT().Client().Return(c)

			coreDNS.EXPECT().SetPodAnnotations(nil)
			coreDNS.EXPECT().Deploy(ctx)

			Expect(botanist.DeployCoreDNS(ctx)).To(Succeed())
		})

		It("should successfully deploy (restart task annotation found)", func() {
			nowFunc := func() time.Time {
				return time.Date(1, 1, 1, 1, 1, 1, 1, time.UTC)
			}
			defer test.WithVar(&NowFunc, nowFunc)()

			shoot := botanist.Shoot.GetInfo()
			shoot.Annotations = map[string]string{"shoot.gardener.cloud/tasks": "restartCoreAddons"}
			botanist.Shoot.SetInfo(shoot)

			coreDNS.EXPECT().SetPodAnnotations(map[string]string{"gardener.cloud/restarted-at": nowFunc().Format(time.RFC3339)})
			coreDNS.EXPECT().Deploy(ctx)

			Expect(botanist.DeployCoreDNS(ctx)).To(Succeed())
		})

		It("should successfully deploy (existing annotation found)", func() {
			annotations := map[string]string{"gardener.cloud/restarted-at": "2014-02-13T10:36:36Z"}

			kubernetesClient.EXPECT().Client().Return(c)
			Expect(c.Create(ctx, &appsv1.Deployment{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "coredns",
					Namespace: "kube-system",
				},
				Spec: appsv1.DeploymentSpec{
					Template: corev1.PodTemplateSpec{
						ObjectMeta: metav1.ObjectMeta{
							Annotations: annotations,
						},
					},
				},
			})).To(Succeed())

			coreDNS.EXPECT().SetPodAnnotations(annotations)
			coreDNS.EXPECT().Deploy(ctx)

			Expect(botanist.DeployCoreDNS(ctx)).To(Succeed())
		})
	})
})
