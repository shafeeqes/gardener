// SPDX-FileCopyrightText: 2024 SAP SE or an SAP affiliate company and Gardener contributors
//
// SPDX-License-Identifier: Apache-2.0

package node

import (
	"context"
	"fmt"
	"path/filepath"
	"strings"

	"github.com/go-logr/logr"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/client-go/tools/record"
	"sigs.k8s.io/controller-runtime/pkg/client"
	logf "sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	extensionsv1alpha1 "github.com/gardener/gardener/pkg/apis/extensions/v1alpha1"
	"github.com/gardener/gardener/pkg/controllerutils"
	nodeagentv1alpha1 "github.com/gardener/gardener/pkg/nodeagent/apis/config/v1alpha1"
	"github.com/gardener/gardener/pkg/nodeagent/controller/operatingsystemconfig"
	"github.com/gardener/gardener/pkg/nodeagent/dbus"
)

const annotationRestartSystemdServices = "worker.gardener.cloud/restart-systemd-services"
const annotationUpdateOSVersion = "worker.gardener.cloud/update-os-version"

// Reconciler checks for node annotation changes and restarts the specified systemd services.
type Reconciler struct {
	Client   client.Client
	Recorder record.EventRecorder
	DBus     dbus.DBus
}

// Reconcile checks for node annotation changes and restarts the specified systemd services.
func (r *Reconciler) Reconcile(ctx context.Context, request reconcile.Request) (reconcile.Result, error) {
	log := logf.FromContext(ctx)

	ctx, cancel := controllerutils.GetMainReconciliationContext(ctx, controllerutils.DefaultReconciliationTimeout)
	defer cancel()

	log.Info("Inside the node reconciler")

	node := &corev1.Node{}
	if err := r.Client.Get(ctx, request.NamespacedName, node); err != nil {
		if apierrors.IsNotFound(err) {
			log.V(1).Info("Object is gone, stop reconciling")
			return reconcile.Result{}, nil
		}

		return reconcile.Result{}, fmt.Errorf("error retrieving object from store: %w", err)
	}

	services, ok1 := node.Annotations[annotationRestartSystemdServices]
	_, ok2 := node.Annotations[annotationUpdateOSVersion]
	if !ok1 && !ok2 {
		return reconcile.Result{}, nil
	}

	var restartGardenerNodeAgent bool

	for _, serviceName := range strings.Split(services, ",") {
		if !strings.HasSuffix(serviceName, ".service") {
			serviceName = serviceName + ".service"
		}
		// If the gardener-node-agent itself should be restarted, we have to first remove the annotation from the node.
		// Otherwise, the annotation is never removed and it restarts itself indefinitely.
		if serviceName == nodeagentv1alpha1.UnitName {
			restartGardenerNodeAgent = true
			continue
		}

		r.restartService(ctx, log, node, serviceName)
	}

	log.Info("Removing annotation from node", "annotation", annotationRestartSystemdServices)
	patch := client.MergeFrom(node.DeepCopy())
	delete(node.Annotations, annotationRestartSystemdServices)
	if err := r.Client.Patch(ctx, node, patch); err != nil {
		return reconcile.Result{}, err
	}

	if restartGardenerNodeAgent {
		r.restartService(ctx, log, node, nodeagentv1alpha1.UnitName)
	}

	if version, ok := node.Annotations[annotationUpdateOSVersion]; ok {
		log.Info("Removing annotation from node", "annotation", annotationUpdateOSVersion)
		patch := client.MergeFrom(node.DeepCopy())
		delete(node.Annotations, annotationUpdateOSVersion)
		if err := r.Client.Patch(ctx, node, patch); err != nil {
			return reconcile.Result{}, err
		}

		updateFilePath := filepath.Join(extensionsv1alpha1.PathForInPlaceOSUpdate, extensionsv1alpha1.ScriptName)
		output, err := operatingsystemconfig.Exec(ctx, "/bin/bash", updateFilePath, version)
		log.Info("Output of update script", "output", output)
		if err != nil {
			return reconcile.Result{}, err
		}
	}

	return reconcile.Result{}, nil
}

func (r *Reconciler) restartService(ctx context.Context, log logr.Logger, node client.Object, serviceName string) {
	log.Info("Restarting systemd service", "serviceName", serviceName)
	if err := r.DBus.Restart(ctx, r.Recorder, node, serviceName); err != nil {
		// We don't return the error here since we don't want to repeatedly try to restart services again and again.
		// In both cases (success or failure), an event will be recorded on the Node so that users can check whether
		// the restart worked.
		log.Error(err, "Failed restarting systemd service", "serviceName", serviceName)
	}
}
