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

package care

import (
	"context"
	"fmt"
	"sync"
	"time"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/utils/clock"
	"k8s.io/utils/pointer"
	"sigs.k8s.io/controller-runtime/pkg/client"
	logf "sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	gardencorev1beta1 "github.com/gardener/gardener/pkg/apis/core/v1beta1"
	v1beta1helper "github.com/gardener/gardener/pkg/apis/core/v1beta1/helper"
	"github.com/gardener/gardener/pkg/client/kubernetes"
	"github.com/gardener/gardener/pkg/client/kubernetes/clientmap"
	"github.com/gardener/gardener/pkg/controllerutils"
	"github.com/gardener/gardener/pkg/gardenlet/apis/config"
	gardenlethelper "github.com/gardener/gardener/pkg/gardenlet/apis/config/helper"
	"github.com/gardener/gardener/pkg/operation"
	"github.com/gardener/gardener/pkg/utils/flow"
	gardenerutils "github.com/gardener/gardener/pkg/utils/gardener"
	"github.com/gardener/gardener/pkg/utils/imagevector"
)

var (
	// NewOperation is used to create a new `operation.Operation` instance.
	NewOperation = defaultNewOperationFunc
	// NewHealthCheck is used to create a new Health check instance.
	NewHealthCheck = defaultNewHealthCheck
	// NewConstraintCheck is used to create a new Constraint check instance.
	NewConstraintCheck = defaultNewConstraintCheck
	// NewGarbageCollector is used to create a new garbage collection instance.
	NewGarbageCollector = defaultNewGarbageCollector
	// NewWebhookRemediator is used to create a new webhook remediation instance.
	NewWebhookRemediator = defaultNewWebhookRemediator
)

// Reconciler reconciles Shoot resources and executes care operations, e.g. health checks or garbage collection.
type Reconciler struct {
	GardenClient          client.Client
	SeedClientSet         kubernetes.Interface
	ShootClientMap        clientmap.ClientMap
	Config                config.GardenletConfiguration
	Clock                 clock.Clock
	ImageVector           imagevector.ImageVector
	Identity              *gardencorev1beta1.Gardener
	GardenClusterIdentity string
	SeedName              string

	gardenSecrets map[string]*corev1.Secret
}

// Reconcile executes care operations, e.g. health checks or garbage collection.
func (r *Reconciler) Reconcile(ctx context.Context, req reconcile.Request) (reconcile.Result, error) {
	log := logf.FromContext(ctx)

	// Timeout for all calls (e.g. status updates), give status updates a bit of headroom if health checks
	// themselves run into timeouts, so that we will still update the status with that timeout error.
	ctx, cancel := controllerutils.GetMainReconciliationContext(ctx, r.Config.Controllers.ShootCare.SyncPeriod.Duration)
	defer cancel()

	shoot := &gardencorev1beta1.Shoot{}
	if err := r.GardenClient.Get(ctx, req.NamespacedName, shoot); err != nil {
		if apierrors.IsNotFound(err) {
			log.V(1).Info("Object is gone, stop reconciling")
			return reconcile.Result{}, nil
		}
		return reconcile.Result{}, fmt.Errorf("error retrieving object from store: %w", err)
	}

	// if shoot has not been scheduled, requeue
	if shoot.Spec.SeedName == nil {
		requeueAfter := 30 * time.Second
		log.V(1).Info("Shoot has not been scheduled yet, requeue", "requeueAfter", requeueAfter)
		return reconcile.Result{RequeueAfter: requeueAfter}, nil
	}

	// if shoot is no longer managed by this gardenlet (e.g., due to migration to another seed) then don't requeue.
	if pointer.StringDeref(shoot.Spec.SeedName, "") != r.SeedName {
		return reconcile.Result{}, nil
	}

	careCtx, cancel := controllerutils.GetChildReconciliationContext(ctx, r.Config.Controllers.ShootCare.SyncPeriod.Duration)
	defer cancel()

	// Initialize conditions based on the current status.
	conditionTypes := []gardencorev1beta1.ConditionType{
		gardencorev1beta1.ShootAPIServerAvailable,
		gardencorev1beta1.ShootControlPlaneHealthy,
		gardencorev1beta1.ShootObservabilityComponentsHealthy,
	}

	if !shoot.IsWorkerless() {
		conditionTypes = append(conditionTypes,
			gardencorev1beta1.ShootEveryNodeReady,
			gardencorev1beta1.ShootSystemComponentsHealthy,
		)
	}

	var conditions []gardencorev1beta1.Condition
	for _, cond := range conditionTypes {
		conditions = append(conditions, v1beta1helper.GetOrInitConditionWithClock(r.Clock, shoot.Status.Conditions, cond))
	}

	// Initialize constraints
	constraintTypes := []gardencorev1beta1.ConditionType{
		gardencorev1beta1.ShootHibernationPossible,
		gardencorev1beta1.ShootMaintenancePreconditionsSatisfied,
		gardencorev1beta1.ShootCACertificateValiditiesAcceptable,
	}
	var constraints []gardencorev1beta1.Condition
	for _, constr := range constraintTypes {
		constraints = append(constraints, v1beta1helper.GetOrInitConditionWithClock(r.Clock, shoot.Status.Constraints, constr))
	}

	// Only read Garden secrets once because we don't rely on up-to-date secrets for health checks.
	if r.gardenSecrets == nil {
		secrets, err := gardenerutils.ReadGardenSecrets(careCtx, log, r.GardenClient, gardenerutils.ComputeGardenNamespace(*shoot.Spec.SeedName), true)
		if err != nil {
			return reconcile.Result{}, fmt.Errorf("error reading Garden secrets: %w", err)
		}
		r.gardenSecrets = secrets
	}

	o, err := NewOperation(
		careCtx,
		log,
		r.GardenClient,
		r.SeedClientSet,
		r.ShootClientMap,
		&r.Config,
		r.Identity,
		r.GardenClusterIdentity,
		r.gardenSecrets,
		r.ImageVector,
		shoot,
	)
	if err != nil {
		if err := r.patchStatusToUnknown(ctx, shoot, "Precondition failed: operation could not be initialized", conditions, constraints); err != nil {
			log.Error(err, "Error when trying to update the shoot status after failed operation initialization")
		}
		return reconcile.Result{}, err
	}

	var (
		staleExtensionHealthCheckThreshold    = gardenlethelper.StaleExtensionHealthChecksThreshold(r.Config.Controllers.ShootCare.StaleExtensionHealthChecks)
		initializeShootClients                = shootClientInitializer(careCtx, o)
		updatedConditions, updatedConstraints []gardencorev1beta1.Condition
	)

	if err := flow.Parallel(
		// Trigger health check
		func(ctx context.Context) error {
			shootHealth := NewHealthCheck(o, initializeShootClients, r.Clock)
			updatedConditions = shootHealth.Check(
				ctx,
				r.conditionThresholdsToProgressingMapping(),
				staleExtensionHealthCheckThreshold,
				conditions,
			)
			return nil
		},
		// Trigger constraint checks
		func(ctx context.Context) error {
			constraint := NewConstraintCheck(clock.RealClock{}, o, initializeShootClients)
			updatedConstraints = constraint.Check(
				ctx,
				constraints,
			)
			return nil
		},
		// Trigger garbage collection
		func(ctx context.Context) error {
			garbageCollector := NewGarbageCollector(o, initializeShootClients)
			garbageCollector.Collect(ctx)
			// errors during garbage collection are only being logged and do not cause the care operation to fail
			return nil
		},
		// Trigger webhook remediation
		func(ctx context.Context) error {
			if pointer.BoolDeref(r.Config.Controllers.ShootCare.WebhookRemediatorEnabled, false) {
				webhookRemediator := NewWebhookRemediator(o, initializeShootClients)
				_ = webhookRemediator.Remediate(ctx)
				// errors during webhook remediation are only being logged and do not cause the care operation to fail
			}
			return nil
		},
	)(careCtx); err != nil {
		return reconcile.Result{}, err
	}

	// Update Shoot status (conditions, constraints) if necessary
	if v1beta1helper.ConditionsNeedUpdate(conditions, updatedConditions) || v1beta1helper.ConditionsNeedUpdate(constraints, updatedConstraints) {
		log.V(1).Info("Updating status conditions and constraints")
		// Rebuild shoot conditions and constraints to ensure that only the conditions and constraints with the
		// correct types will be updated, and any other conditions will remain intact
		conditions = buildShootConditions(shoot.Status.Conditions, updatedConditions, conditionTypes)
		constraints = buildShootConditions(shoot.Status.Constraints, updatedConstraints, constraintTypes)

		if err := r.patchStatus(ctx, shoot, conditions, constraints); err != nil {
			log.Error(err, "Error when trying to update the shoot status")
			return reconcile.Result{}, err
		}
	}

	return reconcile.Result{RequeueAfter: r.Config.Controllers.ShootCare.SyncPeriod.Duration}, nil
}

func (r *Reconciler) conditionThresholdsToProgressingMapping() map[gardencorev1beta1.ConditionType]time.Duration {
	out := make(map[gardencorev1beta1.ConditionType]time.Duration)
	for _, threshold := range r.Config.Controllers.ShootCare.ConditionThresholds {
		out[gardencorev1beta1.ConditionType(threshold.Type)] = threshold.Duration.Duration
	}
	return out
}

func (r *Reconciler) patchStatus(ctx context.Context, shoot *gardencorev1beta1.Shoot, conditions, constraints []gardencorev1beta1.Condition) error {
	patch := client.StrategicMergeFrom(shoot.DeepCopy())
	shoot.Status.Conditions = conditions
	shoot.Status.Constraints = constraints
	return r.GardenClient.Status().Patch(ctx, shoot, patch)
}

func (r *Reconciler) patchStatusToUnknown(ctx context.Context, shoot *gardencorev1beta1.Shoot, message string, conditions, constraints []gardencorev1beta1.Condition) error {
	updatedConditions := make([]gardencorev1beta1.Condition, 0, len(conditions))
	for _, cond := range conditions {
		updatedConditions = append(updatedConditions, v1beta1helper.UpdatedConditionUnknownErrorMessageWithClock(r.Clock, cond, message))
	}

	updatedConstraints := make([]gardencorev1beta1.Condition, 0, len(constraints))
	for _, constr := range constraints {
		updatedConstraints = append(updatedConstraints, v1beta1helper.UpdatedConditionUnknownErrorMessageWithClock(r.Clock, constr, message))
	}

	if !v1beta1helper.ConditionsNeedUpdate(conditions, updatedConditions) && !v1beta1helper.ConditionsNeedUpdate(constraints, updatedConstraints) {
		return nil
	}

	return r.patchStatus(ctx, shoot, updatedConditions, updatedConstraints)
}

// buildShootConditions builds and returns the shoot conditions using the given shoot conditions as a base,
// by first removing all conditions with the given types and then merging the given conditions (which must be of the same types).
func buildShootConditions(shootConditions []gardencorev1beta1.Condition, conditions []gardencorev1beta1.Condition, conditionTypes []gardencorev1beta1.ConditionType) []gardencorev1beta1.Condition {
	result := v1beta1helper.RemoveConditions(shootConditions, conditionTypes...)
	result = v1beta1helper.MergeConditions(result, conditions...)
	return result
}

func shootClientInitializer(ctx context.Context, o *operation.Operation) func() (kubernetes.Interface, bool, error) {
	var (
		once             sync.Once
		apiServerRunning bool
		err              error
	)
	return func() (kubernetes.Interface, bool, error) {
		once.Do(func() {
			// Don't initialize clients for Shoots, for which the API server is not running
			apiServerRunning, err = o.IsAPIServerRunning(ctx)
			if err != nil || !apiServerRunning {
				return
			}

			err = o.InitializeShootClients(ctx)

			// b.InitializeShootClients might not initialize b.ShootClientSet in case the Shoot is being hibernated
			// and the API server has just been scaled down. So, double-check if b.ShootClientSet is set/initialized,
			// otherwise we cannot execute health and constraint checks and garbage collection
			// This is done to prevent a race between the two calls to b.IsAPIServerRunning which would cause the care
			// controller to use a nil shoot client (panic)
			if o.ShootClientSet == nil {
				apiServerRunning = false
			}
		})
		return o.ShootClientSet, apiServerRunning, err
	}
}
