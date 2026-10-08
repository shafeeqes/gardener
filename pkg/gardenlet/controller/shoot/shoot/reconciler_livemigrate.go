// SPDX-FileCopyrightText: Contributors to the Gardener project
//
// SPDX-License-Identifier: Apache-2.0

package shoot

import (
	"context"
	"fmt"
	"time"

	"sigs.k8s.io/controller-runtime/pkg/client"

	v1beta1helper "github.com/gardener/gardener/pkg/api/core/v1beta1/helper"
	gardencorev1beta1 "github.com/gardener/gardener/pkg/apis/core/v1beta1"
	v1beta1constants "github.com/gardener/gardener/pkg/apis/core/v1beta1/constants"
	"github.com/gardener/gardener/pkg/gardenlet/operation"
	botanistpkg "github.com/gardener/gardener/pkg/gardenlet/operation/botanist"
	"github.com/gardener/gardener/pkg/gardenlet/operation/shoot"
	errorsutils "github.com/gardener/gardener/pkg/utils/errors"
	"github.com/gardener/gardener/pkg/utils/flow"
	shootstate "github.com/gardener/gardener/pkg/utils/gardener/shootstate"
	retryutils "github.com/gardener/gardener/pkg/utils/retry"
)

const (
	liveMigrationStepInterval = 10 * time.Second
	liveMigrationStepTimeout  = 10 * time.Minute
)

// liveMigrationStepOwners maps each live control plane migration condition to the gardenlet role responsible for
// executing that step. The flow graph looks up each step's owner here to decide to perform the step or wait for the peer gardenlet.
var liveMigrationStepOwners = map[gardencorev1beta1.ConditionType]v1beta1helper.LiveMigrationRole{
	gardencorev1beta1.ShootLiveMigrationSourceEtcdPreparedForPeerJoin:              v1beta1helper.LiveMigrationRoleSource,
	gardencorev1beta1.ShootLiveMigrationDestinationEtcdPeersJoined:                 v1beta1helper.LiveMigrationRoleDestination,
	gardencorev1beta1.ShootLiveMigrationMigrateExtensionsNeededBeforeKubeAPIServer: v1beta1helper.LiveMigrationRoleSource,
	gardencorev1beta1.ShootLiveMigrationDestinationKubeAPIServerReady:              v1beta1helper.LiveMigrationRoleDestination,
	gardencorev1beta1.ShootLiveMigrationMigrateDNSRecords:                          v1beta1helper.LiveMigrationRoleSource,
	gardencorev1beta1.ShootLiveMigrationEtcdMigrationComplete:                      v1beta1helper.LiveMigrationRoleDestination,
	gardencorev1beta1.ShootLiveMigrationSourceSeedCleanup:                          v1beta1helper.LiveMigrationRoleSource,
	gardencorev1beta1.ShootLiveMigrationMigrationCompleted:                         v1beta1helper.LiveMigrationRoleDestination,
}

func (r *Reconciler) runLiveMigrateShootFlow(ctx context.Context, o *operation.Operation, role v1beta1helper.LiveMigrationRole) *v1beta1helper.WrappedLastErrors {
	var (
		botanist        *botanistpkg.Botanist
		err             error
		tasksWithErrors []string
	)

	for _, lastError := range o.Shoot.GetInfo().Status.LastErrors {
		if lastError.TaskID != nil {
			tasksWithErrors = append(tasksWithErrors, *lastError.TaskID)
		}
	}

	errorContext := errorsutils.NewErrorContext("Shoot control plane live migration", tasksWithErrors)

	if err = errorsutils.HandleErrors(errorContext,
		func(errorID string) error {
			o.CleanShootTaskError(ctx, errorID)
			return nil
		},
		nil,
		errorsutils.ToExecute("Create botanist", func() error {
			return retryutils.UntilTimeout(ctx, 10*time.Second, 10*time.Minute, func(context.Context) (done bool, err error) {
				botanist, err = botanistpkg.New(ctx, o)
				if err != nil {
					return retryutils.MinorError(err)
				}
				return retryutils.Ok()
			})
		}),
	); err != nil {
		return v1beta1helper.NewWrappedLastErrors(v1beta1helper.FormatLastErrDescription(err), err)
	}

	// The live migration flow deploys the shoot control plane on the destination seed without running the
	// infrastructure reconciliation that normally populates o.Shoot.Networks (see WaitForInfrastructure). Compute
	// the networks here from the shoot's spec and status so control plane components (e.g. kube-apiserver, VPN) can
	// read the CIDRs. This mirrors the regular reconcile and migrate flows.
	if o.Shoot.GetInfo().Spec.Networking != nil && o.Shoot.GetInfo().Spec.Networking.Nodes != nil {
		networks, err := shoot.ToNetworks(o.Shoot.GetInfo(), o.Shoot.IsWorkerless)
		if err != nil {
			return v1beta1helper.NewWrappedLastErrors(v1beta1helper.FormatLastErrDescription(err), err)
		}
		o.Shoot.Networks = networks
	}

	var (
		g = flow.NewGraph("Shoot control plane live migration")

		sourceEtcdReadyForPeerJoin = g.Add(flow.Task{
			Name: "Making source etcd ready for peer join",
			Fn: r.executeStepOrWait(botanist, role, gardencorev1beta1.ShootLiveMigrationSourceEtcdPreparedForPeerJoin,
				flow.Task{
					Name: "Persisting shoot state",
					Fn: func(ctx context.Context) error {
						return shootstate.Deploy(ctx, botanist.Clock, botanist.GardenClient, botanist.SeedClientSet.Client(), botanist.Shoot.GetInfo(), botanist.Shoot.ControlPlaneNamespace, false)
					},
				},
				flow.Task{
					Name: "Deploying etcd peer exposure",
					Fn:   botanist.DeployEtcdPeerExposure,
				},
				flow.Task{
					Name: "Initializing secrets management",
					Fn:   botanist.InitializeSecretsManagement,
				},
				flow.Task{
					Name: "Deploying etcd",
					Fn:   botanist.DeployEtcd,
				},
				flow.Task{
					Name: "Waiting until etcds are ready",
					Fn:   botanist.WaitUntilEtcdsReady,
				},
				flow.Task{
					Name: "Migrating backup entry",
					Fn:   botanist.Shoot.Components.BackupEntry.Migrate,
				},
				flow.Task{
					Name: "Waiting until backup entry has been migrated",
					Fn:   botanist.Shoot.Components.BackupEntry.WaitMigrate,
				},
			),
		})

		destinationEtcdJoined = g.Add(flow.Task{
			Name: "Joining destination etcd to the source cluster",
			Fn: r.executeStepOrWait(botanist, role, gardencorev1beta1.ShootLiveMigrationDestinationEtcdPeersJoined,
				flow.Task{
					Name: "Deploying control plane namespace",
					Fn:   botanist.DeployControlPlaneNamespace,
				},
				flow.Task{
					Name: "Initializing secrets management",
					Fn:   botanist.InitializeSecretsManagement,
				},
				flow.Task{
					Name: "Deploying etcd peer exposure",
					Fn:   botanist.DeployEtcdPeerExposure,
				},
				// The source backup entry is deployed to ensure that the data in the source seed's backup bucket
				// is properly cleaned up at a later stage of the flow.
				flow.Task{
					Name: "Deploying source backup entry",
					Fn:   botanist.DeploySourceBackupEntry,
				},
				flow.Task{
					Name: "Waiting until source backup entry is ready",
					Fn:   botanist.Shoot.Components.SourceBackupEntry.Wait,
				},
				flow.Task{
					Name: "Restoring backup entry",
					Fn: func(ctx context.Context) error {
						return botanist.Shoot.Components.BackupEntry.Restore(ctx, nil)
					},
				},
				flow.Task{
					Name: "Waiting until backup entry is ready",
					Fn:   botanist.Shoot.Components.BackupEntry.Wait,
				},
				flow.Task{
					Name: "Deploying etcd",
					Fn:   botanist.DeployEtcd,
				},
				flow.Task{
					Name: "Waiting until etcds are ready",
					Fn:   botanist.WaitUntilEtcdsReady,
				},
			),
			Dependencies: flow.NewTaskIDs(sourceEtcdReadyForPeerJoin),
		})

		destinationKubeAPIServerReady = g.Add(flow.Task{
			Name: "Deploying destination control plane and temporary VPN",
			Fn: r.executeStepOrWait(botanist, role, gardencorev1beta1.ShootLiveMigrationDestinationKubeAPIServerReady,
				destinationControlPlaneSteps(botanist)...),
			Dependencies: flow.NewTaskIDs(destinationEtcdJoined),
		})

		dnsRecordsMigrated = g.Add(flow.Task{
			Name: "Migrating DNS records to the destination seed",
			Fn: r.executeStepOrWait(botanist, role, gardencorev1beta1.ShootLiveMigrationMigrateDNSRecords,
				// The source seed releases its internal and external DNSRecords (the cloud entries are kept in place)
				// so the destination can take them over in the next step and re-point api.<domain> to its own Istio
				// load balancer.
				flow.Task{
					Name: "Migrating internal DNS record",
					Fn:   botanist.MigrateInternalDNSRecord,
				},
				flow.Task{
					Name: "Migrating external DNS record",
					Fn:   botanist.MigrateExternalDNSRecord,
				},
			),
			Dependencies: flow.NewTaskIDs(destinationKubeAPIServerReady),
		})

		liveMigrationCompletion = g.Add(flow.Task{
			Name: "Completing live migration",
			Fn: r.executeStepOrWait(botanist, role, gardencorev1beta1.ShootLiveMigrationMigrationCompleted,
				// The kube-apiserver Service's Wait (in destinationControlPlaneSteps) already pointed the internal and
				// external DNSRecord components at the destination's Istio load balancer (b.APIServerAddress) via its
				// ingress callback. Deploy them now - after the source released them in the preceding
				// dnsRecordsMigrated step - so api.<domain> resolves to the destination before the regular vpn-shoot
				// (whose endpoint is api.<internalDomain>) is brought up.
				flow.Task{
					Name: "Deploying internal DNS record targeting the destination",
					Fn:   botanist.DeployOrDestroyInternalDNSRecord,
				},
				flow.Task{
					Name: "Deploying external DNS record targeting the destination",
					Fn:   botanist.DeployOrDestroyExternalDNSRecord,
				},
				// Deploy the regular vpn-shoot first so the permanent tunnel to the destination is established before
				// the temporary one is torn down, ensuring uninterrupted connectivity.
				flow.Task{
					Name: "Deploying VPN shoot client to destination",
					Fn:   botanist.DeployVPNShoot,
				},
				flow.Task{
					Name: "Destroying temporary VPN shoot client",
					Fn:   botanist.DestroyTemporaryVPNShoot,
				},
				flow.Task{
					Name: "Destroying live migration VPN DNS record",
					Fn:   botanist.DestroyLiveMigrationVPNDNSRecord,
				},
			),
			Dependencies: flow.NewTaskIDs(dnsRecordsMigrated),
		})

		_ = g.Add(flow.Task{
			Fn: func(ctx context.Context) error {
				return fmt.Errorf("reached end of flow")
			},
			Dependencies: flow.NewTaskIDs(liveMigrationCompletion),
		})
		// TODO(GEP-39): Future PRs will add the remaining steps (extension migration, source cleanup) as the topic progresses.
	)

	f := g.Compile()
	if err := f.Run(ctx, flow.Opts{
		Log:              botanist.Logger,
		ProgressReporter: r.newProgressReporter(botanist.ReportShootProgress),
		ErrorContext:     errorContext,
		ErrorCleaner:     botanist.CleanShootTaskError,
	}); err != nil {
		return v1beta1helper.NewWrappedLastErrors(v1beta1helper.FormatLastErrDescription(err), flow.Errors(err))
	}

	return nil
}

// destinationControlPlaneSteps returns the ordered tasks that bring up the destination control plane and the
// temporary VPN during live migration. It reuses the regular reconcile task groups, flattened into a sequential
// list, so the live migration mirrors the normal control plane bring-up ordering: extensions needed before the
// kube-apiserver, the kube-apiserver itself (service, apiserver, SNI), gardener-resource-manager, and finally
// kube-controller-manager and the temporary VPN. skipReadiness is false here because the destination must be fully
// ready before the DNS cutover.
func destinationControlPlaneSteps(b *botanistpkg.Botanist) []flow.Task {
	// The istio-internal-load-balancing ConfigMap gates the pod-kube-apiserver-load-balancing webhook, which injects
	// the hostAlias redirecting api.<internalDomain> to the local istio-ingressgateway. Without it, control plane pods
	// that use the generic-token-kubeconfig (e.g. gardener-resource-manager) resolve api.<internalDomain> to the
	// source seed's apiserver and fail authentication (401). The regular reconcile/migrate/delete flows reconcile it
	// up front; mirror that here so it exists before any such pod is created.
	steps := []flow.Task{{
		Name: "Reconciling istio internal load balancing configmap",
		Fn:   b.ReconcileIstioInternalLoadBalancingConfigMap,
	}}
	steps = append(steps, b.ReconcileExtensionsBeforeKubeAPIServerTaskGroup(false).Tasks()...)
	// The kube-apiserver Service is not part of ReconcileKubeAPIServerTaskGroup (in reconcile its readiness gates
	// other interleaved tasks), so deploy it inline first. It provides the in-cluster "kube-apiserver" endpoint the
	// control plane components connect to, and its Wait resolves the Istio load balancer address into
	// b.APIServerAddress, which the live migration VPN DNS record relies on.
	steps = append(steps,
		flow.Task{Name: "Deploying kube-apiserver service", Fn: b.Shoot.Components.ControlPlane.KubeAPIServerService.Deploy},
		flow.Task{Name: "Waiting until kube-apiserver service is ready", Fn: b.Shoot.Components.ControlPlane.KubeAPIServerService.Wait},
	)
	steps = append(steps, b.ReconcileKubeAPIServerTaskGroup(false, defaultTimeout).Tasks()...)
	steps = append(steps, b.ReconcileGardenerResourceManagerTaskGroup(true, false).Tasks()...)
	steps = append(steps,
		flow.Task{Name: "Deploying kube-controller-manager", Fn: b.DeployKubeControllerManager},
		// Deploy the temporary VPN so admission webhooks can reach the destination from the shoot cluster
		// before the DNS cutover. Routing to the (per-index, in HA) vpn-seed-server is handled by the global
		// http-proxy EnvoyFilter on the ingress gateway via the X-Gardener-Destination header, so only the
		// vpn-tmp DNS record (pointing at the destination's Istio load balancer) and the vpn-shoot client are
		// needed - no per-shoot Istio exposure.
		flow.Task{Name: "Deploying destination VPN server", Fn: b.DeployVPNServer},
		flow.Task{Name: "Deploying live migration VPN DNS record", Fn: b.DeployLiveMigrationVPNDNSRecord},
		flow.Task{Name: "Deploying temporary VPN shoot client", Fn: b.DeployTemporaryVPNShoot},
	)
	return steps
}

// executeStepOrWait returns a TaskFn that either executes the given steps sequentially (if this gardenlet owns the
// step) or waits for the peer gardenlet to complete it. The task names serve as documentation of the individual steps.
func (r *Reconciler) executeStepOrWait(botanist *botanistpkg.Botanist, role v1beta1helper.LiveMigrationRole, conditionType gardencorev1beta1.ConditionType, steps ...flow.Task) flow.TaskFn {
	owner := liveMigrationStepOwners[conditionType]

	fns := make([]flow.TaskFn, 0, len(steps))
	for _, step := range steps {
		// SkipIf is honored here because the flattened reconcile task groups carry per-task SkipIf conditions
		// (e.g. readiness waits). flow.Sequential has no notion of SkipIf, so drop skipped tasks up front.
		if step.SkipIf {
			continue
		}
		fns = append(fns, step.Fn)
	}
	fn := flow.Sequential(fns...)

	return flow.TaskFn(func(ctx context.Context) error {
		if role != owner {
			return r.waitForLiveMigrationPeerStep(ctx, botanist, conditionType)
		}
		if err := r.setLiveMigrationStepCondition(ctx, botanist.Shoot.GetInfo(), conditionType, false); err != nil {
			return err
		}
		if err := fn(ctx); err != nil {
			if conditionErr := r.setLiveMigrationStepConditionError(ctx, botanist.Shoot.GetInfo(), conditionType, err); conditionErr != nil {
				botanist.Logger.Error(conditionErr, "Failed to set error condition for live migration step", "step", conditionType)
			}
			return err
		}
		return r.setLiveMigrationStepCondition(ctx, botanist.Shoot.GetInfo(), conditionType, true)
	}).RetryUntilTimeout(liveMigrationStepInterval, liveMigrationStepTimeout)
}

func (r *Reconciler) waitForLiveMigrationPeerStep(ctx context.Context, botanist *botanistpkg.Botanist, conditionType gardencorev1beta1.ConditionType) error {
	shoot := &gardencorev1beta1.Shoot{}
	if err := r.GardenClient.Get(ctx, client.ObjectKeyFromObject(botanist.Shoot.GetInfo()), shoot); err != nil {
		return fmt.Errorf("failed to read shoot while waiting for peer gardenlet to complete live migration step %q: %w", conditionType, err)
	}

	if !v1beta1helper.IsLiveMigrationConditionTrue(shoot, conditionType) {
		return fmt.Errorf("waiting for peer gardenlet to complete live migration step %q", conditionType)
	}

	return nil
}

func (r *Reconciler) setLiveMigrationStepCondition(ctx context.Context, shoot *gardencorev1beta1.Shoot, conditionType gardencorev1beta1.ConditionType, done bool) error {
	condition := v1beta1helper.GetOrInitConditionWithClock(r.Clock, v1beta1helper.GetLiveMigrationConditions(shoot), conditionType)
	if done {
		condition = v1beta1helper.UpdatedConditionWithClock(r.Clock, condition, gardencorev1beta1.ConditionTrue, "StepCompleted", "The live migration step has been completed.")
	} else {
		condition = v1beta1helper.UpdatedConditionWithClock(r.Clock, condition, gardencorev1beta1.ConditionProgressing, "StepInProgress", "The live migration step is in progress.")
	}
	return r.patchLiveMigrationConditions(ctx, shoot, condition)
}

func (r *Reconciler) setLiveMigrationStepConditionError(ctx context.Context, shoot *gardencorev1beta1.Shoot, conditionType gardencorev1beta1.ConditionType, err error) error {
	condition := v1beta1helper.GetOrInitConditionWithClock(r.Clock, v1beta1helper.GetLiveMigrationConditions(shoot), conditionType)
	condition = v1beta1helper.UpdatedConditionWithClock(r.Clock, condition, gardencorev1beta1.ConditionFalse, "StepFailed", err.Error())
	return r.patchLiveMigrationConditions(ctx, shoot, condition)
}

// finalizeLiveMigration switches the shoot's status.seedName to the destination seed and clears the live-migration
// state and intent annotation, returning the shoot to normal reconciliation on the destination seed.
func (r *Reconciler) finalizeLiveMigration(ctx context.Context, shoot *gardencorev1beta1.Shoot) error {
	patch := client.MergeFrom(shoot.DeepCopy())
	delete(shoot.Annotations, v1beta1constants.AnnotationMigrationLiveMigrate)
	if err := r.GardenClient.Patch(ctx, shoot, patch); err != nil {
		return fmt.Errorf("failed to remove live migration annotation: %w", err)
	}

	statusPatch := client.StrategicMergeFrom(shoot.DeepCopy())
	shoot.Status.SeedName = shoot.Spec.SeedName
	shoot.Status.LiveMigration = nil
	shoot.Status.MigrationStartTime = nil
	return r.GardenClient.Status().Patch(ctx, shoot, statusPatch)
}

func (r *Reconciler) patchLiveMigrationConditions(ctx context.Context, shoot *gardencorev1beta1.Shoot, conditions ...gardencorev1beta1.Condition) error {
	patch := client.StrategicMergeFrom(shoot.DeepCopy())

	if shoot.Status.LiveMigration == nil {
		shoot.Status.LiveMigration = &gardencorev1beta1.LiveMigration{}
	}
	shoot.Status.LiveMigration.Conditions = v1beta1helper.MergeConditions(shoot.Status.LiveMigration.Conditions, conditions...)

	return r.GardenClient.Status().Patch(ctx, shoot, patch)
}
