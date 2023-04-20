// Copyright 2022 SAP SE or an SAP affiliate company. All rights reserved. This file is licensed under the Apache Software License, v. 2 except as noted otherwise in the LICENSE file
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

package project_test

import (
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	corev1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/rest"
	"k8s.io/utils/pointer"
	"sigs.k8s.io/controller-runtime/pkg/client"

	gardencorev1beta1 "github.com/gardener/gardener/pkg/apis/core/v1beta1"
	v1beta1constants "github.com/gardener/gardener/pkg/apis/core/v1beta1/constants"
	"github.com/gardener/gardener/pkg/utils"
	kubernetesutils "github.com/gardener/gardener/pkg/utils/kubernetes"
	. "github.com/gardener/gardener/pkg/utils/test/matchers"
)

var _ = Describe("Project controller tests", func() {
	var (
		projectNamespaceKey client.ObjectKey

		project          *gardencorev1beta1.Project
		projectNamespace *corev1.Namespace
		shoot            *gardencorev1beta1.Shoot
	)

	BeforeEach(func() {
		projectName := "test-" + utils.ComputeSHA256Hex([]byte(testRunID + CurrentSpecReport().LeafNodeLocation.String()))[:5]

		project = &gardencorev1beta1.Project{
			ObjectMeta: metav1.ObjectMeta{
				Name:   projectName,
				Labels: map[string]string{testID: testRunID},
			},
			Spec: gardencorev1beta1.ProjectSpec{
				Namespace: pointer.String("garden-" + projectName),
			},
		}

		projectNamespace = nil
		projectNamespaceKey = client.ObjectKey{Name: *project.Spec.Namespace}

		shoot = &gardencorev1beta1.Shoot{
			ObjectMeta: metav1.ObjectMeta{
				GenerateName: "test-",
				Namespace:    projectNamespaceKey.Name,
				Labels:       map[string]string{testID: testRunID},
			},
			Spec: gardencorev1beta1.ShootSpec{
				SecretBindingName: pointer.String("mysecretbinding"),
				CloudProfileName:  "cloudprofile1",
				Region:            "europe-central-1",
				Provider: gardencorev1beta1.Provider{
					Type: "foo-provider",
					Workers: []gardencorev1beta1.Worker{
						{
							Name:    "cpu-worker",
							Minimum: 3,
							Maximum: 3,
							Machine: gardencorev1beta1.Machine{
								Type: "large",
							},
						},
					},
				},
				DNS: &gardencorev1beta1.DNS{
					Domain: pointer.String("some-domain.example.com"),
				},
				Kubernetes: gardencorev1beta1.Kubernetes{
					Version: "1.20.1",
				},
				Networking: gardencorev1beta1.Networking{
					Type: "foo-networking",
				},
			},
		}
	})

	JustBeforeEach(func() {
		if projectNamespace != nil {
			By("Create project Namespace")
			Expect(testClient.Create(ctx, projectNamespace)).To(Succeed())
			log.Info("Created project namespace", "projectNamespace", projectNamespace)

			DeferCleanup(func() {
				By("Delete project namespace")
				Expect(testClient.Delete(ctx, projectNamespace)).To(Or(Succeed(), BeNotFoundError()))
			})
		} else {
			projectNamespace = &corev1.Namespace{}
		}

		By("Create Project")
		Expect(testClient.Create(ctx, project)).To(Succeed())
		log.Info("Created Project", "project", client.ObjectKeyFromObject(project))

		DeferCleanup(func() {
			By("Delete Project")
			Expect(client.IgnoreNotFound(testClient.Delete(ctx, project))).To(Succeed())

			By("Wait for Project to be gone")
			Eventually(func() error {
				return testClient.Get(ctx, client.ObjectKeyFromObject(project), project)
			}).Should(BeNotFoundError())
		})
	})

	triggerAndWaitForReconciliation := func(project *gardencorev1beta1.Project) {
		By("Trigger Project Reconciliation")
		patch := client.MergeFrom(project.DeepCopy())
		project.Spec.Description = pointer.String(time.Now().UTC().Format(time.RFC3339Nano))
		Expect(testClient.Patch(ctx, project, patch)).To(Succeed())

		By("Wait for Project to be reconciled")
		Eventually(func(g Gomega) {
			g.Expect(testClient.Get(ctx, client.ObjectKeyFromObject(project), project)).To(Succeed())
			g.Expect(project.Status.ObservedGeneration).To(Equal(project.Generation), "project controller should observe generation %d", project.Generation)
		}).Should(Succeed())
	}

	waitForProjectPhase := func(project *gardencorev1beta1.Project, phase gardencorev1beta1.ProjectPhase) {
		By("Wait for Project to be reconciled")
		Eventually(func(g Gomega) {
			g.Expect(testClient.Get(ctx, client.ObjectKeyFromObject(project), project)).To(Succeed())
			g.Expect(project.Status.ObservedGeneration).To(Equal(project.Generation), "project controller should observe generation %d", project.Generation)
			g.Expect(project.Status.Phase).To(Equal(phase), "project should transition to phase %s", phase)
		}).Should(Succeed())
	}

	It("should add the finalizer and release it on deletion", func() {
		waitForProjectPhase(project, gardencorev1beta1.ProjectReady)
		Expect(project.Finalizers).To(ConsistOf("gardener"))

		By("Delete Project")
		Expect(testClient.Delete(ctx, project)).To(Succeed())

		By("Wait for Project to be gone")
		Eventually(func() error {
			return testClient.Get(ctx, client.ObjectKeyFromObject(project), project)
		}).Should(BeNotFoundError())
	})

	It("should not release the project as long as it still contains shoots", func() {
		waitForProjectPhase(project, gardencorev1beta1.ProjectReady)

		By("Create Shoot")
		Expect(testClient.Create(ctx, shoot)).To(Succeed())
		log.Info("Created Shoot for test", "shoot", client.ObjectKeyFromObject(shoot))

		By("Wait until manager has observed Shoot creation")
		Eventually(func() error {
			return mgrClient.Get(ctx, client.ObjectKeyFromObject(shoot), shoot)
		}).Should(Succeed())

		DeferCleanup(func() {
			By("Cleanup Shoot")
			Expect(client.IgnoreNotFound(testClient.Delete(ctx, shoot))).To(Succeed())
			Eventually(func() error {
				return testClient.Get(ctx, client.ObjectKeyFromObject(shoot), shoot)
			}).Should(BeNotFoundError())
		})

		By("Delete Project")
		Expect(testClient.Delete(ctx, project)).To(Succeed())

		waitForProjectPhase(project, gardencorev1beta1.ProjectTerminating)

		By("Ensure Project is not released")
		Consistently(func(g Gomega) {
			g.Expect(testClient.Get(ctx, client.ObjectKeyFromObject(project), project)).To(Succeed())
		}).Should(Succeed())

		By("Delete Shoot")
		Expect(testClient.Delete(ctx, shoot)).To(Succeed())
		Eventually(func() error {
			return testClient.Get(ctx, client.ObjectKeyFromObject(shoot), shoot)
		}).Should(BeNotFoundError())

		By("Wait for Project to be gone")
		Eventually(func() error {
			return testClient.Get(ctx, client.ObjectKeyFromObject(project), project)
		}).Should(BeNotFoundError())
	})

	Describe("Project Namespace", func() {
		testNamespaceLifecycle := func(text string) {
			It(text, Offset(1), func() {
				waitForProjectPhase(project, gardencorev1beta1.ProjectReady)

				By("Wait for project namespace to be created")
				Eventually(func(g Gomega) {
					g.Expect(testClient.Get(ctx, projectNamespaceKey, projectNamespace)).To(Succeed())
					g.Expect(projectNamespace.OwnerReferences).To(ConsistOf(metav1.OwnerReference{
						APIVersion:         "core.gardener.cloud/v1beta1",
						Kind:               "Project",
						Name:               project.Name,
						UID:                project.UID,
						Controller:         pointer.Bool(true),
						BlockOwnerDeletion: pointer.Bool(true),
					}))
				}).Should(Succeed())

				By("Delete Project")
				Expect(testClient.Delete(ctx, project)).To(Succeed())

				By("Wait for project namespace to be gone")
				Eventually(func() error {
					return testClient.Get(ctx, projectNamespaceKey, projectNamespace)
				}).Should(BeNotFoundError())
			})
		}

		Context("namespace specified for creation", func() {
			testNamespaceLifecycle("should create and delete the specified namespace")

			It("should keep the namespace if it has the annotation", func() {
				waitForProjectPhase(project, gardencorev1beta1.ProjectReady)

				By("Wait for project namespace to be created")
				Eventually(func(g Gomega) {
					g.Expect(testClient.Get(ctx, projectNamespaceKey, projectNamespace)).To(Succeed())
				}).Should(Succeed())

				By("Annotate project namespace to be kept after Project deletion")
				patch := client.MergeFrom(projectNamespace.DeepCopy())
				metav1.SetMetaDataAnnotation(&projectNamespace.ObjectMeta, "namespace.gardener.cloud/keep-after-project-deletion", "true")
				Expect(testClient.Patch(ctx, projectNamespace, patch)).To(Succeed())

				DeferCleanup(func() {
					By("Delete project namespace")
					Expect(testClient.Delete(ctx, projectNamespace)).To(Or(Succeed(), BeNotFoundError()))
				})

				By("Wait until manager has observed annotation")
				Eventually(func(g Gomega) {
					g.Expect(mgrClient.Get(ctx, projectNamespaceKey, projectNamespace)).To(Succeed())
					g.Expect(projectNamespace.Annotations).To(HaveKey("namespace.gardener.cloud/keep-after-project-deletion"))
				}).Should(Succeed())

				By("Delete Project")
				Expect(testClient.Delete(ctx, project)).To(Succeed())

				By("Wait for Project to be gone")
				Eventually(func() error {
					return testClient.Get(ctx, client.ObjectKeyFromObject(project), project)
				}).Should(BeNotFoundError())

				By("Ensure project namespace is released but not deleted")
				Consistently(func(g Gomega) {
					g.Expect(testClient.Get(ctx, projectNamespaceKey, projectNamespace)).To(Succeed())
					g.Expect(projectNamespace.OwnerReferences).To(BeEmpty())
					g.Expect(projectNamespace.Labels).NotTo(Or(
						HaveKey("project.gardener.cloud/name"),
						HaveKey("gardener.cloud/role"),
					))
				}).Should(Succeed())
			})
		})

		Context("existing namespace specified for adoption", func() {
			BeforeEach(func() {
				projectNamespace = &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{
					Name: projectNamespaceKey.Name,
				}}
			})

			Context("namespace without proper project labels", func() {
				It("should fail to adopt existing namespace", func() {
					waitForProjectPhase(project, gardencorev1beta1.ProjectFailed)

					By("Delete Project")
					Expect(testClient.Delete(ctx, project)).To(Succeed())

					By("Wait for Project to be gone")
					Eventually(func() error {
						return testClient.Get(ctx, client.ObjectKeyFromObject(project), project)
					}).Should(BeNotFoundError())

					By("Ensure project namespace is not deleted")
					Consistently(func() error {
						return testClient.Get(ctx, projectNamespaceKey, projectNamespace)
					}).Should(Succeed())
				})
			})

			Context("namespace correctly labeled", func() {
				BeforeEach(func() {
					metav1.SetMetaDataLabel(&projectNamespace.ObjectMeta, v1beta1constants.GardenRole, v1beta1constants.GardenRoleProject)
					metav1.SetMetaDataLabel(&projectNamespace.ObjectMeta, v1beta1constants.ProjectName, project.Name)
				})

				It("should adopt existing namespace but not delete it", func() {
					waitForProjectPhase(project, gardencorev1beta1.ProjectReady)

					By("Delete Project")
					Expect(testClient.Delete(ctx, project)).To(Succeed())

					By("Wait for Project to be gone")
					Eventually(func() error {
						return testClient.Get(ctx, client.ObjectKeyFromObject(project), project)
					}).Should(BeNotFoundError())

					By("Ensure project namespace is released but not deleted")
					Consistently(func(g Gomega) {
						g.Expect(testClient.Get(ctx, projectNamespaceKey, projectNamespace)).To(Succeed())
						g.Expect(projectNamespace.OwnerReferences).To(BeEmpty())
						g.Expect(projectNamespace.Labels).NotTo(Or(
							HaveKey("project.gardener.cloud/name"),
							HaveKey("gardener.cloud/role"),
						))
					}).Should(Succeed())
				})
			})

			Context("namespace belongs to another project", func() {
				BeforeEach(func() {
					metav1.SetMetaDataLabel(&projectNamespace.ObjectMeta, v1beta1constants.GardenRole, v1beta1constants.GardenRoleProject)
					metav1.SetMetaDataLabel(&projectNamespace.ObjectMeta, v1beta1constants.ProjectName, "foo")
				})

				It("should fail to adopt existing namespace", func() {
					waitForProjectPhase(project, gardencorev1beta1.ProjectFailed)

					By("Delete Project")
					Expect(testClient.Delete(ctx, project)).To(Succeed())

					By("Wait for Project to be gone")
					Eventually(func() error {
						return testClient.Get(ctx, client.ObjectKeyFromObject(project), project)
					}).Should(BeNotFoundError())

					By("Ensure project namespace is not deleted")
					Consistently(func() error {
						return testClient.Get(ctx, projectNamespaceKey, projectNamespace)
					}).Should(Succeed())
				})
			})
		})

		Context("no namespace specified", func() {
			BeforeEach(func() {
				project.Spec.Namespace = nil
			})

			JustBeforeEach(func() {
				waitForProjectPhase(project, gardencorev1beta1.ProjectReady)
				projectNamespaceKey = client.ObjectKey{Name: *project.Spec.Namespace}
				log.Info("Project uses generated project namespace", "projectNamespace", projectNamespaceKey)
			})

			testNamespaceLifecycle("should create and delete a generated project namespace")
		})
	})

	Describe("Default ResourceQuota", func() {
		var resourceQuota *corev1.ResourceQuota

		BeforeEach(func() {
			resourceQuota = &corev1.ResourceQuota{ObjectMeta: metav1.ObjectMeta{
				Name:      "gardener",
				Namespace: projectNamespaceKey.Name,
			}}
		})

		JustBeforeEach(func() {
			waitForProjectPhase(project, gardencorev1beta1.ProjectReady)
		})

		waitForQuota := func(resourceQuota *corev1.ResourceQuota) {
			By("Wait for quota to be created")
			Eventually(func(g Gomega) {
				g.Expect(testClient.Get(ctx, client.ObjectKeyFromObject(resourceQuota), resourceQuota)).To(Succeed())
				g.Expect(resourceQuota.Spec).To(DeepEqual(defaultResourceQuota.Spec))
				g.Expect(resourceQuota.Labels).To(DeepEqual(defaultResourceQuota.Labels))
				g.Expect(resourceQuota.Annotations).To(DeepEqual(defaultResourceQuota.Annotations))
			}).Should(Succeed())
		}

		It("should maintain the configured default quota", func() {
			waitForQuota(resourceQuota)

			By("Modify quota metadata")
			patch := client.MergeFrom(resourceQuota.DeepCopy())
			metav1.SetMetaDataLabel(&resourceQuota.ObjectMeta, "bar", testRunID)
			metav1.SetMetaDataAnnotation(&resourceQuota.ObjectMeta, "bar", testRunID)
			Expect(testClient.Patch(ctx, resourceQuota, patch)).To(Succeed())

			expectedLabels := resourceQuota.DeepCopy().Labels
			expectedAnnotations := resourceQuota.DeepCopy().Annotations

			triggerAndWaitForReconciliation(project)

			By("Ensure quota metadata is not overwritten")
			Consistently(func(g Gomega) {
				g.Expect(testClient.Get(ctx, client.ObjectKeyFromObject(resourceQuota), resourceQuota)).To(Succeed())
				g.Expect(resourceQuota.Labels).To(DeepEqual(expectedLabels))
				g.Expect(resourceQuota.Annotations).To(DeepEqual(expectedAnnotations))
			}).Should(Succeed())
		})

		It("should not overwrite increased quota settings", func() {
			waitForQuota(resourceQuota)

			By("Increase quota")
			patch := client.MergeFrom(resourceQuota.DeepCopy())
			for resourceName, quantity := range resourceQuota.Spec.Hard {
				quantity.Add(resource.MustParse("1"))
				resourceQuota.Spec.Hard[resourceName] = quantity
			}
			Expect(testClient.Patch(ctx, resourceQuota, patch)).To(Succeed())
			increasedQuota := resourceQuota.DeepCopy()

			triggerAndWaitForReconciliation(project)

			By("Ensure increased quota is not overwritten")
			Consistently(func(g Gomega) {
				g.Expect(testClient.Get(ctx, client.ObjectKeyFromObject(resourceQuota), resourceQuota)).To(Succeed())
				g.Expect(resourceQuota.Spec).To(DeepEqual(increasedQuota.Spec))
			}).Should(Succeed())
		})

		It("should add new resources to existing quotas", func() {
			waitForQuota(resourceQuota)

			By("Add new resource to quota config")
			defaultResourceQuota.Spec.Hard["count/secrets"] = resource.MustParse("42")

			triggerAndWaitForReconciliation(project)

			By("Ensure new resource is added")
			expectedQuota := defaultResourceQuota.DeepCopy()
			Eventually(func(g Gomega) {
				g.Expect(testClient.Get(ctx, client.ObjectKeyFromObject(resourceQuota), resourceQuota)).To(Succeed())
				g.Expect(resourceQuota.Spec).To(DeepEqual(expectedQuota.Spec))
			}).Should(Succeed())
		})
	})

	Describe("Member RBAC", func() {
		var (
			testUserName   string
			testUserClient client.Client
		)

		BeforeEach(func() {
			testUserName = project.Name
			testUserConfig := rest.CopyConfig(restConfig)
			// envtest.Environment.AddUser doesn't work when running against an existing cluster
			// use impersonation instead to simulate different user
			testUserConfig.Impersonate = rest.ImpersonationConfig{
				UserName: testUserName,
			}

			var err error
			testUserClient, err = client.New(testUserConfig, client.Options{})
			Expect(err).NotTo(HaveOccurred())
		})

		JustBeforeEach(func() {
			waitForProjectPhase(project, gardencorev1beta1.ProjectReady)
		})

		It("should allow admins to access the project namespace", func() {
			By("Ensure non-member doesn't have access to project")
			Consistently(func(g Gomega) {
				g.Expect(testUserClient.Get(ctx, projectNamespaceKey, &corev1.Namespace{})).To(BeForbiddenError())
			}).Should(Succeed())

			By("Add admin to project")
			patch := client.MergeFrom(project.DeepCopy())
			project.Spec.Members = append(project.Spec.Members, gardencorev1beta1.ProjectMember{
				Subject: rbacv1.Subject{
					APIGroup: rbacv1.GroupName,
					Kind:     rbacv1.UserKind,
					Name:     testUserName,
				},
				Role: "admin",
			})
			Expect(testClient.Patch(ctx, project, patch)).To(Succeed())

			By("Ensure new admin has access to project")
			Eventually(func(g Gomega) {
				g.Expect(testUserClient.Get(ctx, projectNamespaceKey, &corev1.Namespace{})).To(Succeed())
			}).Should(Succeed())
		})

		It("should recreate deleted well-known RoleBindings", func() {
			By("Delete RoleBindings")
			var roleBindings []client.Object
			for _, name := range []string{"gardener.cloud:system:project-member", "gardener.cloud:system:project-viewer", "gardener.cloud:system:project-serviceaccountmanager"} {
				roleBindings = append(roleBindings, &rbacv1.RoleBinding{ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: projectNamespaceKey.Name}})
			}
			Expect(kubernetesutils.DeleteObjects(ctx, testClient, roleBindings...)).To(Succeed())

			By("Ensure RoleBindings are recreated")
			Eventually(func(g Gomega) {
				for _, roleBinding := range roleBindings {
					g.Expect(testClient.Get(ctx, client.ObjectKeyFromObject(roleBinding), roleBinding)).To(Succeed(), "should recreate RoleBinding %s", roleBinding.GetName())
				}
			}).Should(Succeed())
		})

		It("should recreate deleted extension RoleBinding", func() {
			By("Add new member with extension role")
			patch := client.MergeFrom(project.DeepCopy())
			project.Spec.Members = append(project.Spec.Members, gardencorev1beta1.ProjectMember{
				Subject: rbacv1.Subject{
					APIGroup: rbacv1.GroupName,
					Kind:     rbacv1.UserKind,
					Name:     testUserName,
				},
				Role: "extension:test",
			})
			Expect(testClient.Patch(ctx, project, patch)).To(Succeed())

			By("Wait until RoleBinding is created")
			roleBinding := &rbacv1.RoleBinding{ObjectMeta: metav1.ObjectMeta{Name: "gardener.cloud:extension:project:" + project.Name + ":test", Namespace: projectNamespaceKey.Name}}
			Eventually(func(g Gomega) {
				g.Expect(testClient.Get(ctx, client.ObjectKeyFromObject(roleBinding), roleBinding)).To(Succeed())
			}).Should(Succeed())

			By("Delete RoleBinding")
			Expect(testClient.Delete(ctx, roleBinding)).To(Succeed())

			By("Ensure RoleBinding is recreated")
			Eventually(func(g Gomega) {
				g.Expect(testClient.Get(ctx, client.ObjectKeyFromObject(roleBinding), roleBinding)).To(Succeed(), "should recreate RoleBinding %s", roleBinding.GetName())
			}).Should(Succeed())
		})
	})
})
