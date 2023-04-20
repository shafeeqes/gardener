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

package vpa

import (
	"context"
	"errors"
	"io"

	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apiserver/pkg/admission"

	"github.com/gardener/gardener/pkg/apis/core"
)

const (
	// PluginName is the name of this admission plugin.
	PluginName = "ShootVPAEnabledByDefault"
)

// Register registers a plugin.
func Register(plugins *admission.Plugins) {
	plugins.Register(PluginName, func(config io.Reader) (admission.Interface, error) {
		return New(), nil
	})
}

// ShootVPA contains required information to process admission requests.
type ShootVPA struct {
	*admission.Handler
}

// New creates a new ShootVPA admission plugin.
func New() admission.MutationInterface {
	return &ShootVPA{
		Handler: admission.NewHandler(admission.Create),
	}
}

// Admit defaults spec.kubernetes.verticalPodAutoscaler.enabled=true for new shoot clusters.
func (c *ShootVPA) Admit(_ context.Context, a admission.Attributes, _ admission.ObjectInterfaces) error {
	switch {
	case a.GetKind().GroupKind() != core.Kind("Shoot"),
		a.GetOperation() != admission.Create,
		a.GetSubresource() != "":
		return nil
	}

	shoot, ok := a.GetObject().(*core.Shoot)
	if !ok {
		return apierrors.NewInternalError(errors.New("could not convert resource into Shoot object"))
	}

	if shoot.Spec.Kubernetes.VerticalPodAutoscaler == nil && !shoot.IsWorkerless() {
		shoot.Spec.Kubernetes.VerticalPodAutoscaler = &core.VerticalPodAutoscaler{Enabled: true}
	}

	return nil
}
