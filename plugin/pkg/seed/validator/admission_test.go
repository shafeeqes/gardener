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

package validator_test

import (
	"context"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apiserver/pkg/admission"
	"k8s.io/utils/pointer"

	"github.com/gardener/gardener/pkg/apis/core"
	gardencoreinformers "github.com/gardener/gardener/pkg/client/core/informers/internalversion"
	. "github.com/gardener/gardener/pkg/utils/test/matchers"
	. "github.com/gardener/gardener/plugin/pkg/seed/validator"
)

var _ = Describe("validator", func() {
	Describe("#Admit", func() {
		var (
			admissionHandler    *ValidateSeed
			coreInformerFactory gardencoreinformers.SharedInformerFactory
			backupBucket        core.BackupBucket
			seed                core.Seed
			shoot               core.Shoot

			backupBucketName = "backupbucket"
			seedName         = "seed"
			namespaceName    = "garden-my-project"

			seedBase = core.Seed{
				ObjectMeta: metav1.ObjectMeta{
					Name: seedName,
				},
			}
			shootBase = core.Shoot{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "shoot",
					Namespace: namespaceName,
				},
				Spec: core.ShootSpec{
					CloudProfileName:  "profile",
					Region:            "europe",
					SecretBindingName: pointer.String("my-secret"),
					SeedName:          &seedName,
				},
			}

			backupBucketBase = core.BackupBucket{
				ObjectMeta: metav1.ObjectMeta{
					Name: backupBucketName,
				},
			}
		)

		BeforeEach(func() {
			backupBucket = backupBucketBase
			seed = seedBase
			shoot = *shootBase.DeepCopy()

			admissionHandler, _ = New()
			admissionHandler.AssignReadyFunc(func() bool { return true })
			coreInformerFactory = gardencoreinformers.NewSharedInformerFactory(nil, 0)
			admissionHandler.SetInternalCoreInformerFactory(coreInformerFactory)
		})

		Context("Seed Update", func() {
			var oldSeed, newSeed *core.Seed

			BeforeEach(func() {
				oldSeed = seedBase.DeepCopy()
				newSeed = seedBase.DeepCopy()

				oldSeed.Spec.Provider.Zones = []string{"1", "2"}
				newSeed.Spec.Provider.Zones = []string{"2"}
			})

			It("should allow zone removal when there are no shoots", func() {
				attrs := admission.NewAttributesRecord(newSeed, oldSeed, core.Kind("Seed").WithVersion("version"), "", seed.Name, core.Resource("seeds").WithVersion("version"), "", admission.Update, &metav1.UpdateOptions{}, false, nil)

				Expect(admissionHandler.Validate(context.TODO(), attrs, nil)).To(Succeed())
			})

			It("should forbid zone removal when there are shoots", func() {
				Expect(coreInformerFactory.Core().InternalVersion().Shoots().Informer().GetStore().Add(&shoot)).To(Succeed())
				attrs := admission.NewAttributesRecord(newSeed, oldSeed, core.Kind("Seed").WithVersion("version"), "", seed.Name, core.Resource("seeds").WithVersion("version"), "", admission.Update, &metav1.UpdateOptions{}, false, nil)

				Expect(admissionHandler.Validate(context.TODO(), attrs, nil)).To(BeForbiddenError())
			})
		})

		// The verification of protection is independent of the Cloud Provider (being checked before).
		Context("Seed deletion", func() {
			BeforeEach(func() {
				shoot.Spec.SeedName = &seedName
			})

			It("should disallow seed deletion because it still hosts shoot clusters", func() {
				Expect(coreInformerFactory.Core().InternalVersion().Shoots().Informer().GetStore().Add(&shoot)).To(Succeed())
				attrs := admission.NewAttributesRecord(&seed, nil, core.Kind("Seed").WithVersion("version"), "", seed.Name, core.Resource("seeds").WithVersion("version"), "", admission.Delete, &metav1.DeleteOptions{}, false, nil)

				err := admissionHandler.Validate(context.TODO(), attrs, nil)

				Expect(err).To(HaveOccurred())
				Expect(err).To(BeForbiddenError())
			})

			It("should allow seed deletion even though it is still referenced by a backupbucket (will be cleaned up during Seed reconciliation)", func() {
				backupBucket.Spec.SeedName = &seedName
				Expect(coreInformerFactory.Core().InternalVersion().BackupBuckets().Informer().GetStore().Add(&backupBucket)).To(Succeed())
				attrs := admission.NewAttributesRecord(&seed, nil, core.Kind("Seed").WithVersion("version"), "", seed.Name, core.Resource("seeds").WithVersion("version"), "", admission.Delete, &metav1.DeleteOptions{}, false, nil)

				err := admissionHandler.Validate(context.TODO(), attrs, nil)

				Expect(err).ToNot(HaveOccurred())
			})

			It("should disallow seed deletion because shoot migration is yet not finished", func() {
				shoot.Spec.SeedName = pointer.String(seedName + "-1")
				shoot.Status.SeedName = &seedName

				Expect(coreInformerFactory.Core().InternalVersion().Shoots().Informer().GetStore().Add(&shoot)).To(Succeed())
				attrs := admission.NewAttributesRecord(&seed, nil, core.Kind("Seed").WithVersion("version"), "", seed.Name, core.Resource("seeds").WithVersion("version"), "", admission.Delete, &metav1.DeleteOptions{}, false, nil)

				err := admissionHandler.Validate(context.TODO(), attrs, nil)

				Expect(err).To(HaveOccurred())
				Expect(err).To(BeForbiddenError())
			})

			It("should allow deletion of empty seed", func() {
				shoot.Spec.SeedName = pointer.String(seedName + "-1")
				Expect(coreInformerFactory.Core().InternalVersion().Shoots().Informer().GetStore().Add(&shoot)).To(Succeed())
				attrs := admission.NewAttributesRecord(&seed, nil, core.Kind("Seed").WithVersion("version"), "", seed.Name, core.Resource("seeds").WithVersion("version"), "", admission.Delete, &metav1.DeleteOptions{}, false, nil)

				err := admissionHandler.Validate(context.TODO(), attrs, nil)

				Expect(err).ToNot(HaveOccurred())
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
		It("should handle only DELETE and Update operations", func() {
			dr, err := New()
			Expect(err).ToNot(HaveOccurred())
			Expect(dr.Handles(admission.Create)).NotTo(BeTrue())
			Expect(dr.Handles(admission.Update)).To(BeTrue())
			Expect(dr.Handles(admission.Connect)).NotTo(BeTrue())
			Expect(dr.Handles(admission.Delete)).To(BeTrue())
		})
	})

	Describe("#ValidateInitialization", func() {
		It("should return error if no ShootLister or SeedLister is set", func() {
			dr, _ := New()

			err := dr.ValidateInitialization()

			Expect(err).To(HaveOccurred())
		})

		It("should not return error if ShootLister and SeedLister are set", func() {
			dr, _ := New()
			dr.SetInternalCoreInformerFactory(gardencoreinformers.NewSharedInformerFactory(nil, 0))

			err := dr.ValidateInitialization()

			Expect(err).ToNot(HaveOccurred())
		})
	})

})
