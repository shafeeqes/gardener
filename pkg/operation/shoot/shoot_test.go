// Copyright 2019 SAP SE or an SAP affiliate company. All rights reserved. This file is licensed under the Apache Software License, v. 2 except as noted otherwise in the LICENSE file
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

package shoot_test

import (
	"net"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	. "github.com/onsi/gomega/gstruct"
	"k8s.io/utils/pointer"

	gardencorev1beta1 "github.com/gardener/gardener/pkg/apis/core/v1beta1"
	v1beta1constants "github.com/gardener/gardener/pkg/apis/core/v1beta1/constants"
	. "github.com/gardener/gardener/pkg/operation/shoot"
)

var _ = Describe("shoot", func() {
	Context("shoot", func() {
		var shoot *Shoot

		BeforeEach(func() {
			shoot = &Shoot{}
			shoot.SetInfo(&gardencorev1beta1.Shoot{})
		})

		Describe("#ToNetworks", func() {
			var shoot *gardencorev1beta1.Shoot

			BeforeEach(func() {
				shoot = &gardencorev1beta1.Shoot{
					Spec: gardencorev1beta1.ShootSpec{
						Networking: &gardencorev1beta1.Networking{
							Pods:     pointer.String("10.0.0.0/24"),
							Services: pointer.String("20.0.0.0/24"),
						},
					},
				}
			})

			It("returns correct network", func() {
				result, err := ToNetworks(shoot)

				Expect(err).ToNot(HaveOccurred())
				Expect(result).To(PointTo(Equal(Networks{
					Pods: &net.IPNet{
						IP:   []byte{10, 0, 0, 0},
						Mask: []byte{255, 255, 255, 0},
					},
					Services: &net.IPNet{
						IP:   []byte{20, 0, 0, 0},
						Mask: []byte{255, 255, 255, 0},
					},
					APIServer: []byte{20, 0, 0, 1},
					CoreDNS:   []byte{20, 0, 0, 10},
				})))
			})

			DescribeTable("#ConstructInternalClusterDomain", func(mutateFunc func(s *gardencorev1beta1.Shoot)) {
				mutateFunc(shoot)
				result, err := ToNetworks(shoot)

				Expect(err).To(HaveOccurred())
				Expect(result).To(BeNil())
			},

				Entry("services is nil", func(s *gardencorev1beta1.Shoot) { s.Spec.Networking.Services = nil }),
				Entry("pods is nil", func(s *gardencorev1beta1.Shoot) { s.Spec.Networking.Pods = nil }),
				Entry("services is invalid", func(s *gardencorev1beta1.Shoot) {
					s.Spec.Networking.Services = pointer.String("foo")
				}),
				Entry("pods is invalid", func(s *gardencorev1beta1.Shoot) { s.Spec.Networking.Pods = pointer.String("foo") }),
				Entry("apiserver cannot be calculated", func(s *gardencorev1beta1.Shoot) {
					s.Spec.Networking.Services = pointer.String("10.0.0.0/32")
				}),
				Entry("coreDNS cannot be calculated", func(s *gardencorev1beta1.Shoot) {
					s.Spec.Networking.Services = pointer.String("10.0.0.0/29")
				}),
			)
		})

		Describe("#IPVSEnabled", func() {
			It("should return false when KubeProxy is null", func() {
				shoot.GetInfo().Spec.Kubernetes.KubeProxy = nil
				Expect(shoot.IPVSEnabled()).To(BeFalse())
			})

			It("should return false when KubeProxy.Mode is null", func() {
				shoot.GetInfo().Spec.Kubernetes.KubeProxy = &gardencorev1beta1.KubeProxyConfig{}
				Expect(shoot.IPVSEnabled()).To(BeFalse())
			})

			It("should return false when KubeProxy.Mode is not IPVS", func() {
				mode := gardencorev1beta1.ProxyModeIPTables
				shoot.GetInfo().Spec.Kubernetes.KubeProxy = &gardencorev1beta1.KubeProxyConfig{
					Mode: &mode,
				}
				Expect(shoot.IPVSEnabled()).To(BeFalse())
			})

			It("should return true when KubeProxy.Mode is IPVS", func() {
				mode := gardencorev1beta1.ProxyModeIPVS
				shoot.GetInfo().Spec.Kubernetes.KubeProxy = &gardencorev1beta1.KubeProxyConfig{
					Mode: &mode,
				}
				Expect(shoot.IPVSEnabled()).To(BeTrue())
			})
		})

		Describe("#ComputeInClusterAPIServerAddress", func() {
			seedNamespace := "foo"
			s := &Shoot{SeedNamespace: seedNamespace}

			It("should return <service-name>", func() {
				Expect(s.ComputeInClusterAPIServerAddress(true)).To(Equal(v1beta1constants.DeploymentNameKubeAPIServer))
			})

			It("should return <service-name>.<namespace>.svc", func() {
				Expect(s.ComputeInClusterAPIServerAddress(false)).To(Equal(v1beta1constants.DeploymentNameKubeAPIServer + "." + seedNamespace + ".svc"))
			})
		})

		Describe("#ComputeOutOfClusterAPIServerAddress", func() {
			It("should return the internal domain as shoot's external domain is unmanaged", func() {
				unmanaged := "unmanaged"
				internalDomain := "foo"
				s := &Shoot{
					InternalClusterDomain: internalDomain,
				}
				s.SetInfo(&gardencorev1beta1.Shoot{
					Spec: gardencorev1beta1.ShootSpec{
						DNS: &gardencorev1beta1.DNS{
							Providers: []gardencorev1beta1.DNSProvider{
								{Type: &unmanaged},
							},
						},
					},
				})

				Expect(s.ComputeOutOfClusterAPIServerAddress("", false)).To(Equal("api." + internalDomain))
			})

			It("should return the internal domain as requested (shoot's external domain is not unmanaged)", func() {
				internalDomain := "foo"
				s := &Shoot{
					InternalClusterDomain: internalDomain,
				}
				s.SetInfo(&gardencorev1beta1.Shoot{})

				Expect(s.ComputeOutOfClusterAPIServerAddress("", true)).To(Equal("api." + internalDomain))
			})

			It("should return the external domain as requested (shoot's external domain is not unmanaged)", func() {
				externalDomain := "foo"
				s := &Shoot{
					ExternalClusterDomain: &externalDomain,
				}
				s.SetInfo(&gardencorev1beta1.Shoot{})

				Expect(s.ComputeOutOfClusterAPIServerAddress("", false)).To(Equal("api." + externalDomain))
			})
		})
	})
})
