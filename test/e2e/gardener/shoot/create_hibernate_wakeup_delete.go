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

package shoot

import (
	"context"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	e2e "github.com/gardener/gardener/test/e2e/gardener"
	"github.com/gardener/gardener/test/e2e/gardener/shoot/internal/node"
)

var _ = Describe("Shoot Tests", Label("Shoot", "default", "workerless"), func() {
	var (
		f          = defaultShootCreationFramework()
		workerless = e2e.IsTestForWorkerlessShoot()
	)

	f.Shoot = e2e.DefaultShoot("e2e-wake-up", workerless)

	It("Create, Hibernate, Wake up and Delete Shoot", func() {
		By("Create Shoot")
		ctx, cancel := context.WithTimeout(parentCtx, 15*time.Minute)
		defer cancel()
		Expect(f.CreateShootAndWaitForCreation(ctx, false)).To(Succeed())
		f.Verify()

		if !workerless {
			By("Verify Bootstrapping of Nodes with node-critical components")
			// We verify the node readiness feature in this specific e2e test because it uses a single-node shoot cluster.
			// The default shoot e2e test deals with multiple nodes, deleting all of them and waiting for them to be recreated
			// might increase the test duration undesirably.
			ctx, cancel = context.WithTimeout(parentCtx, 15*time.Minute)
			defer cancel()
			node.VerifyNodeCriticalComponentsBootstrapping(ctx, f.ShootFramework)
		}

		By("Hibernate Shoot")
		ctx, cancel = context.WithTimeout(parentCtx, 10*time.Minute)
		defer cancel()
		Expect(f.HibernateShoot(ctx, f.Shoot)).To(Succeed())

		if !workerless {
			verifyNoPodsRunning(ctx, f)
		}

		By("Wake up Shoot")
		ctx, cancel = context.WithTimeout(parentCtx, 15*time.Minute)
		defer cancel()
		Expect(f.WakeUpShoot(ctx, f.Shoot)).To(Succeed())

		By("Delete Shoot")
		ctx, cancel = context.WithTimeout(parentCtx, 15*time.Minute)
		defer cancel()
		Expect(f.DeleteShootAndWaitForDeletion(ctx, f.Shoot)).To(Succeed())
	})
})
