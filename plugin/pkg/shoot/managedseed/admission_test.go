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

package managedseed_test

import (
	"context"
	"errors"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apiserver/pkg/admission"
	"k8s.io/client-go/testing"
	"k8s.io/utils/pointer"

	"github.com/gardener/gardener/pkg/apis/core"
	gardencorev1beta1 "github.com/gardener/gardener/pkg/apis/core/v1beta1"
	seedmanagementv1alpha1 "github.com/gardener/gardener/pkg/apis/seedmanagement/v1alpha1"
	corefake "github.com/gardener/gardener/pkg/client/core/clientset/internalversion/fake"
	fakeseedmanagement "github.com/gardener/gardener/pkg/client/seedmanagement/clientset/versioned/fake"
	gardenletv1alpha1 "github.com/gardener/gardener/pkg/gardenlet/apis/config/v1alpha1"
	. "github.com/gardener/gardener/pkg/utils/test/matchers"
	. "github.com/gardener/gardener/plugin/pkg/shoot/managedseed"
)

const (
	name      = "foo"
	namespace = "garden"
)

var _ = Describe("ManagedSeed", func() {
	Describe("#Validate", func() {
		var (
			shoot                *core.Shoot
			managedSeed          *seedmanagementv1alpha1.ManagedSeed
			gardenletConfig      *gardenletv1alpha1.GardenletConfiguration
			coreClient           *corefake.Clientset
			seedManagementClient *fakeseedmanagement.Clientset
			admissionHandler     *ManagedSeed

			worker1Zones, worker2Zones []string
		)

		BeforeEach(func() {
			worker1Zones = []string{"1", "2", "3"}
			worker2Zones = []string{"4", "5", "6"}

			shoot = &core.Shoot{
				ObjectMeta: metav1.ObjectMeta{
					Name:      name,
					Namespace: namespace,
				},
				Spec: core.ShootSpec{
					Addons: &core.Addons{
						NginxIngress: &core.NginxIngress{
							Addon: core.Addon{
								Enabled: false,
							},
						},
					},
					Kubernetes: core.Kubernetes{
						VerticalPodAutoscaler: &core.VerticalPodAutoscaler{
							Enabled: true,
						},
					},
					Networking: &core.Networking{
						Type:  pointer.String("foo"),
						Nodes: pointer.String("10.181.0.0/18"),
					},
					Provider: core.Provider{
						Workers: []core.Worker{
							{
								Name:  "worker-1",
								Zones: worker1Zones,
							},
							{
								Name:  "worker-2",
								Zones: worker2Zones,
							},
						},
					},
				},
			}

			gardenletConfig = &gardenletv1alpha1.GardenletConfiguration{
				SeedConfig: &gardenletv1alpha1.SeedConfig{
					SeedTemplate: gardencorev1beta1.SeedTemplate{
						Spec: gardencorev1beta1.SeedSpec{
							Provider: gardencorev1beta1.SeedProvider{
								Zones: append(worker1Zones, worker2Zones...),
							},
						},
					},
				},
			}

			managedSeed = &seedmanagementv1alpha1.ManagedSeed{
				ObjectMeta: metav1.ObjectMeta{
					Name:      name,
					Namespace: namespace,
				},
				Spec: seedmanagementv1alpha1.ManagedSeedSpec{
					Shoot: &seedmanagementv1alpha1.Shoot{
						Name: name,
					},
					Gardenlet: &seedmanagementv1alpha1.Gardenlet{
						Config: runtime.RawExtension{
							Object: gardenletConfig,
						},
					},
				},
			}

			admissionHandler, _ = New()
			admissionHandler.AssignReadyFunc(func() bool { return true })

			coreClient = &corefake.Clientset{}
			admissionHandler.SetInternalCoreClientset(coreClient)

			seedManagementClient = &fakeseedmanagement.Clientset{}
			admissionHandler.SetSeedManagementClientset(seedManagementClient)
		})

		It("should do nothing if the resource is not a Shoot", func() {
			attrs := admission.NewAttributesRecord(nil, nil, core.Kind("Foo").WithVersion("version"), shoot.Namespace, shoot.Name, core.Resource("foos").WithVersion("version"), "", admission.Delete, &metav1.DeleteOptions{}, false, nil)

			err := admissionHandler.Validate(context.TODO(), attrs, nil)
			Expect(err).NotTo(HaveOccurred())
		})

		Context("update", func() {
			It("should forbid Shoot update if the Shoot enables the nginx-ingress addon", func() {
				seedManagementClient.AddReactor("list", "managedseeds", func(action testing.Action) (bool, runtime.Object, error) {
					return true, &seedmanagementv1alpha1.ManagedSeedList{Items: []seedmanagementv1alpha1.ManagedSeed{*managedSeed}}, nil
				})
				oldShoot := shoot.DeepCopy()
				shoot.Spec.Addons.NginxIngress.Enabled = true
				attrs := getShootAttributes(shoot, oldShoot, admission.Update, &metav1.UpdateOptions{})
				err := admissionHandler.Validate(context.TODO(), attrs, nil)
				Expect(err).To(BeInvalidError())
				Expect(err.Error()).To(ContainSubstring("shoot ingress addon is not supported for managed seeds - use the managed seed ingress controller"))
			})

			It("should forbid Shoot update if the Shoot does not enable VPA", func() {
				seedManagementClient.AddReactor("list", "managedseeds", func(action testing.Action) (bool, runtime.Object, error) {
					return true, &seedmanagementv1alpha1.ManagedSeedList{Items: []seedmanagementv1alpha1.ManagedSeed{*managedSeed}}, nil
				})
				oldShoot := shoot.DeepCopy()
				shoot.Spec.Kubernetes.VerticalPodAutoscaler.Enabled = false
				attrs := getShootAttributes(shoot, oldShoot, admission.Update, &metav1.UpdateOptions{})
				err := admissionHandler.Validate(context.TODO(), attrs, nil)
				Expect(err).To(BeInvalidError())
				Expect(err.Error()).To(ContainSubstring("shoot VPA has to be enabled for managed seeds"))
			})

			It("should allow Shoot update if the spec is valid", func() {
				seedManagementClient.AddReactor("list", "managedseeds", func(action testing.Action) (bool, runtime.Object, error) {
					return true, &seedmanagementv1alpha1.ManagedSeedList{Items: []seedmanagementv1alpha1.ManagedSeed{*managedSeed}}, nil
				})
				oldShoot := shoot.DeepCopy()
				attrs := getShootAttributes(shoot, oldShoot, admission.Update, &metav1.UpdateOptions{})
				err := admissionHandler.Validate(context.TODO(), attrs, nil)
				Expect(err).NotTo(HaveOccurred())
			})

			It("should fail with an error different from Invalid if retrieving the ManagedSeed fails with an error different from NotFound", func() {
				seedManagementClient.AddReactor("list", "managedseeds", func(action testing.Action) (bool, runtime.Object, error) {
					return true, nil, apierrors.NewInternalError(errors.New("Internal Server Error"))
				})
				oldShoot := shoot.DeepCopy()
				attrs := getShootAttributes(shoot, oldShoot, admission.Update, &metav1.UpdateOptions{})
				err := admissionHandler.Validate(context.TODO(), attrs, nil)
				Expect(err).To(HaveOccurred())
				Expect(err).ToNot(BeInvalidError())
			})

			It("should forbid Shoot if the spec.Networking.Nodes is changes", func() {
				seedManagementClient.AddReactor("list", "managedseeds", func(action testing.Action) (bool, runtime.Object, error) {
					return true, &seedmanagementv1alpha1.ManagedSeedList{Items: []seedmanagementv1alpha1.ManagedSeed{*managedSeed}}, nil
				})
				oldShoot := shoot.DeepCopy()
				shoot.Spec.Networking.Nodes = pointer.String("10.181.0.0/16")
				attrs := getShootAttributes(shoot, oldShoot, admission.Update, &metav1.UpdateOptions{})
				err := admissionHandler.Validate(context.TODO(), attrs, nil)
				Expect(err).To(HaveOccurred())
				Expect(err).To(BeInvalidError())
				Expect(err).To(MatchError(ContainSubstring("field is immutable for managed seeds")))
			})

			It("should forbid Shoot update if the seedTemplate is not specified", func() {
				managedSeed.Spec.Gardenlet = &seedmanagementv1alpha1.Gardenlet{
					Config: runtime.RawExtension{
						Object: &gardenletv1alpha1.GardenletConfiguration{},
					},
				}
				seedManagementClient.AddReactor("list", "managedseeds", func(action testing.Action) (bool, runtime.Object, error) {
					return true, &seedmanagementv1alpha1.ManagedSeedList{Items: []seedmanagementv1alpha1.ManagedSeed{*managedSeed}}, nil
				})
				oldShoot := shoot.DeepCopy()
				attrs := getShootAttributes(shoot, oldShoot, admission.Update, &metav1.UpdateOptions{})
				err := admissionHandler.Validate(context.TODO(), attrs, nil)
				Expect(err).To(HaveOccurred())
				Expect(err).To(BeInternalServerError())
				Expect(err).To(MatchError(ContainSubstring("cannot extract the seed template")))
			})

			It("should forbid Shoot update if shoot static token kubeconfig gets disabled and seed secretRef is set", func() {
				seedConfig := &gardenletv1alpha1.SeedConfig{
					SeedTemplate: gardencorev1beta1.SeedTemplate{
						Spec: gardencorev1beta1.SeedSpec{
							SecretRef: &corev1.SecretReference{
								Name:      "foo",
								Namespace: "garden",
							},
						},
					},
				}
				managedSeed.Spec.Gardenlet = &seedmanagementv1alpha1.Gardenlet{
					Config: runtime.RawExtension{
						Object: &gardenletv1alpha1.GardenletConfiguration{
							SeedConfig: seedConfig,
						},
					},
				}
				seedManagementClient.AddReactor("list", "managedseeds", func(action testing.Action) (bool, runtime.Object, error) {
					return true, &seedmanagementv1alpha1.ManagedSeedList{Items: []seedmanagementv1alpha1.ManagedSeed{*managedSeed}}, nil
				})
				shoot.Spec.Kubernetes.EnableStaticTokenKubeconfig = pointer.Bool(true)
				oldShoot := shoot.DeepCopy()
				shoot.Spec.Kubernetes.EnableStaticTokenKubeconfig = pointer.Bool(false)
				attrs := getShootAttributes(shoot, oldShoot, admission.Update, &metav1.UpdateOptions{})
				err := admissionHandler.Validate(context.TODO(), attrs, nil)
				Expect(err).To(HaveOccurred())
				Expect(err).To(BeInvalidError())
				Expect(err).To(MatchError(ContainSubstring("shoot static token kubeconfig cannot be disabled when the seed secretRef is set")))
			})

			It("should forbid Shoot update when zones have changed but still configured in ManagedSeed", func() {
				seedManagementClient.AddReactor("list", "managedseeds", func(action testing.Action) (bool, runtime.Object, error) {
					return true, &seedmanagementv1alpha1.ManagedSeedList{Items: []seedmanagementv1alpha1.ManagedSeed{*managedSeed}}, nil
				})

				oldShoot := shoot.DeepCopy()
				shoot.Spec.Provider.Workers[0].Zones = []string{"new-zone"}
				attrs := getShootAttributes(shoot, oldShoot, admission.Update, &metav1.UpdateOptions{})
				err := admissionHandler.Validate(context.TODO(), attrs, nil)
				Expect(err).To(HaveOccurred())
				Expect(err).To(BeInvalidError())
				Expect(err).To(MatchError(ContainSubstring("shoot worker zone(s) must not be removed as long as registered in managedseed")))
			})

			It("should allow Shoot update when zones were not changed", func() {
				// Create zone name mismatch between ManagedSeed and Shoot which was once tolerated, see https://github.com/gardener/gardener/pull/7024.
				gardenletConfig.SeedConfig.Spec.Provider.Zones = []string{"zone-a", "zone-b", "2"}
				seedManagementClient.AddReactor("list", "managedseeds", func(action testing.Action) (bool, runtime.Object, error) {
					return true, &seedmanagementv1alpha1.ManagedSeedList{Items: []seedmanagementv1alpha1.ManagedSeed{*managedSeed}}, nil
				})

				oldShoot := shoot.DeepCopy()
				attrs := getShootAttributes(shoot, oldShoot, admission.Update, &metav1.UpdateOptions{})
				Expect(admissionHandler.Validate(context.TODO(), attrs, nil)).To(Succeed())
			})

			It("should allow Shoot update when zones have changed which are not registered in seed", func() {
				gardenletConfig.SeedConfig.Spec.Provider.Zones = worker2Zones
				seedManagementClient.AddReactor("list", "managedseeds", func(action testing.Action) (bool, runtime.Object, error) {
					return true, &seedmanagementv1alpha1.ManagedSeedList{Items: []seedmanagementv1alpha1.ManagedSeed{*managedSeed}}, nil
				})

				oldShoot := shoot.DeepCopy()
				shoot.Spec.Provider.Workers[0].Zones = []string{"new-zone"}
				attrs := getShootAttributes(shoot, oldShoot, admission.Update, &metav1.UpdateOptions{})
				Expect(admissionHandler.Validate(context.TODO(), attrs, nil)).To(Succeed())
			})

			It("should allow Shoot update when new zone is added", func() {
				gardenletConfig.SeedConfig.Spec.Provider.Zones = worker2Zones
				seedManagementClient.AddReactor("list", "managedseeds", func(action testing.Action) (bool, runtime.Object, error) {
					return true, &seedmanagementv1alpha1.ManagedSeedList{Items: []seedmanagementv1alpha1.ManagedSeed{*managedSeed}}, nil
				})

				oldShoot := shoot.DeepCopy()
				shoot.Spec.Provider.Workers[0].Zones = append(shoot.Spec.Provider.Workers[0].Zones, "new-zone")
				attrs := getShootAttributes(shoot, oldShoot, admission.Update, &metav1.UpdateOptions{})
				Expect(admissionHandler.Validate(context.TODO(), attrs, nil)).To(Succeed())
			})

			It("should allow Shoot update", func() {
				seedManagementClient.AddReactor("list", "managedseeds", func(action testing.Action) (bool, runtime.Object, error) {
					return true, &seedmanagementv1alpha1.ManagedSeedList{Items: []seedmanagementv1alpha1.ManagedSeed{*managedSeed}}, nil
				})
				oldShoot := shoot.DeepCopy()
				attrs := getShootAttributes(shoot, oldShoot, admission.Update, &metav1.UpdateOptions{})
				Expect(admissionHandler.Validate(context.TODO(), attrs, nil)).To(Succeed())
			})
		})

		Context("delete", func() {
			It("should forbid the Shoot deletion if a ManagedSeed referencing the Shoot exists", func() {
				seedManagementClient.AddReactor("list", "managedseeds", func(action testing.Action) (bool, runtime.Object, error) {
					return true, &seedmanagementv1alpha1.ManagedSeedList{Items: []seedmanagementv1alpha1.ManagedSeed{*managedSeed}}, nil
				})

				attrs := getShootAttributes(shoot, nil, admission.Delete, &metav1.DeleteOptions{})
				err := admissionHandler.Validate(context.TODO(), attrs, nil)
				Expect(err).To(BeForbiddenError())
			})

			It("should allow the Shoot deletion if a ManagedSeed referencing the Shoot does not exist", func() {
				seedManagementClient.AddReactor("list", "managedseeds", func(action testing.Action) (bool, runtime.Object, error) {
					return true, &seedmanagementv1alpha1.ManagedSeedList{Items: []seedmanagementv1alpha1.ManagedSeed{}}, nil
				})

				attrs := getShootAttributes(shoot, nil, admission.Delete, &metav1.DeleteOptions{})
				err := admissionHandler.Validate(context.TODO(), attrs, nil)
				Expect(err).NotTo(HaveOccurred())
			})

			It("should fail with an error different from Forbidden if retrieving the ManagedSeed fails with an error different from NotFound", func() {
				seedManagementClient.AddReactor("list", "managedseeds", func(action testing.Action) (bool, runtime.Object, error) {
					return true, nil, apierrors.NewInternalError(errors.New("Internal Server Error"))
				})

				attrs := getShootAttributes(shoot, nil, admission.Delete, &metav1.DeleteOptions{})
				err := admissionHandler.Validate(context.TODO(), attrs, nil)
				Expect(err).To(HaveOccurred())
				Expect(err).ToNot(BeForbiddenError())
			})
		})

		Context("delete collection", func() {
			var (
				anotherShoot *core.Shoot
			)

			BeforeEach(func() {
				anotherShoot = &core.Shoot{
					ObjectMeta: metav1.ObjectMeta{
						Name:      "bar",
						Namespace: "garden",
					},
				}
			})

			It("should forbid multiple Shoots deletion if a ManagedSeed referencing any of the Shoots exists", func() {
				coreClient.AddReactor("list", "shoots", func(action testing.Action) (bool, runtime.Object, error) {
					return true, &core.ShootList{Items: []core.Shoot{*shoot, *anotherShoot}}, nil
				})
				seedManagementClient.AddReactor("list", "managedseeds", func(action testing.Action) (bool, runtime.Object, error) {
					return true, &seedmanagementv1alpha1.ManagedSeedList{Items: []seedmanagementv1alpha1.ManagedSeed{*managedSeed}}, nil
				})

				err := admissionHandler.Validate(context.TODO(), getAllShootsAttributes(shoot.Namespace), nil)
				Expect(err).To(BeForbiddenError())
			})

			It("should allow multiple Shoots deletion if no ManagedSeeds referencing the Shoots exist", func() {
				coreClient.AddReactor("list", "shoots", func(action testing.Action) (bool, runtime.Object, error) {
					return true, &core.ShootList{Items: []core.Shoot{*shoot, *anotherShoot}}, nil
				})
				seedManagementClient.AddReactor("list", "managedseeds", func(action testing.Action) (bool, runtime.Object, error) {
					return true, &seedmanagementv1alpha1.ManagedSeedList{Items: []seedmanagementv1alpha1.ManagedSeed{}}, nil
				})

				err := admissionHandler.Validate(context.TODO(), getAllShootsAttributes(shoot.Namespace), nil)
				Expect(err).NotTo(HaveOccurred())
			})
		})
	})

	Describe("#Register", func() {
		It("should register the plugin", func() {
			plugins := admission.NewPlugins()
			Register(plugins)

			registered := plugins.Registered()
			Expect(registered).To(HaveLen(1))
			Expect(registered).To(ContainElement(PluginName))
		})
	})

	Describe("#New", func() {
		It("should only handle UPDATE and DELETE operations", func() {
			admissionHandler, err := New()
			Expect(err).ToNot(HaveOccurred())
			Expect(admissionHandler.Handles(admission.Create)).NotTo(BeTrue())
			Expect(admissionHandler.Handles(admission.Connect)).NotTo(BeTrue())
			Expect(admissionHandler.Handles(admission.Update)).To(BeTrue())
			Expect(admissionHandler.Handles(admission.Delete)).To(BeTrue())
		})
	})

	Describe("#ValidateInitialization", func() {
		It("should fail if the required clients are not set", func() {
			admissionHandler, _ := New()

			err := admissionHandler.ValidateInitialization()
			Expect(err).To(HaveOccurred())
		})

		It("should not fail if the required clients are set", func() {
			admissionHandler, _ := New()
			admissionHandler.SetInternalCoreClientset(&corefake.Clientset{})
			admissionHandler.SetSeedManagementClientset(&fakeseedmanagement.Clientset{})

			err := admissionHandler.ValidateInitialization()
			Expect(err).ToNot(HaveOccurred())
		})
	})
})

func getShootAttributes(shoot *core.Shoot, oldShoot *core.Shoot, operation admission.Operation, operationOptions runtime.Object) admission.Attributes {
	return admission.NewAttributesRecord(shoot, oldShoot, gardencorev1beta1.Kind("Shoot").WithVersion("v1beta1"), shoot.Namespace, shoot.Name, gardencorev1beta1.Resource("shoots").WithVersion("v1beta1"), "", operation, operationOptions, false, nil)
}

func getAllShootsAttributes(namespace string) admission.Attributes {
	return admission.NewAttributesRecord(nil, nil, gardencorev1beta1.Kind("Shoot").WithVersion("v1beta1"), namespace, "", gardencorev1beta1.Resource("shoots").WithVersion("v1beta1"), "", admission.Delete, &metav1.DeleteOptions{}, false, nil)
}
