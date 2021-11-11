// Copyright (c) 2021 SAP SE or an SAP affiliate company. All rights reserved. This file is licensed under the Apache Software License, v. 2 except as noted otherwise in the LICENSE file
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

package vpnshoot

import (
	"context"
	"time"

	"github.com/gardener/gardener/pkg/client/kubernetes"
	"github.com/gardener/gardener/pkg/operation/botanist/component"
	"github.com/gardener/gardener/pkg/utils/managedresources"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/intstr"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

const (
	// LabelKey is the key of a label used for the identification of VPNShoot pods.
	LabelKey = "app"
	// LabelValue is the value of a label used for the identification of VPNShoot pods.
	LabelValue = "vpn-shoot"
	// ManagedResourceName is the name of the ManagedResource containing the resource specifications.
	ManagedResourceName = "shoot-core-vpnshoot"
	// servicePort is the service port used for the VPN LoadBalancer.
	servicePort int32 = 4314
	// containerPort is the target port used for the VPN LoadBalancer.
	containerPort int32 = 1194
	//deploymentName is the name of the vpnShoot deployment
	deploymentName = "vpn-shoot"

	containerName = "vpn-shoot"
	serviceName   = "vpn-test"
)

type Interface interface {
	component.DeployWaiter
	component.MonitoringComponent
}

// New creates a new instance of DeployWaiter for vpnshoot
func New(
	client client.Client,
	namespace string,
	image string,
) Interface {
	return &vpnShoot{
		client:    client,
		namespace: namespace,
		image:     image,
	}
}

type vpnShoot struct {
	client    client.Client
	namespace string
	image     string
}

func (v *vpnShoot) Deploy(ctx context.Context) error {
	data, err := v.computeResourcesData()
	if err != nil {
		return err
	}
	return managedresources.CreateForShoot(ctx, v.client, v.namespace, ManagedResourceName, false, data)
}

func (v *vpnShoot) Destroy(ctx context.Context) error {
	return managedresources.DeleteForShoot(ctx, v.client, v.namespace, ManagedResourceName)
}

var TimeoutWaitForManagedResource = 2 * time.Minute

func (v *vpnShoot) Wait(ctx context.Context) error {
	timeoutCtx, cancel := context.WithTimeout(ctx, TimeoutWaitForManagedResource)
	defer cancel()

	return managedresources.WaitUntilHealthy(timeoutCtx, v.client, v.namespace, ManagedResourceName)
}

func (v *vpnShoot) WaitCleanup(ctx context.Context) error {
	timeoutCtx, cancel := context.WithTimeout(ctx, TimeoutWaitForManagedResource)
	defer cancel()

	return managedresources.WaitUntilDeleted(timeoutCtx, v.client, v.namespace, ManagedResourceName)
}

func (v *vpnShoot) computeResourcesData() (map[string][]byte, error) {
	var (
		registry = managedresources.NewRegistry(kubernetes.ShootScheme, kubernetes.ShootCodec, kubernetes.ShootSerializer)

		serviceAccount = &corev1.ServiceAccount{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "vpn-shoot",
				Namespace: metav1.NamespaceSystem,
				Labels:    map[string]string{LabelKey: LabelValue},
			},
		}

		service = &corev1.Service{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "vpn-shoot",
				Namespace: metav1.NamespaceSystem,
				Labels:    map[string]string{LabelKey: LabelValue},
			},
			Spec: corev1.ServiceSpec{
				Selector: map[string]string{LabelKey: LabelValue},
				Type:     corev1.ServiceTypeLoadBalancer,
				Ports: []corev1.ServicePort{
					{
						Name:       "openvpn",
						Port:       servicePort,
						TargetPort: intstr.FromInt(int(containerPort)),
						Protocol:   corev1.ProtocolTCP,
					},
				},
			},
		}
	)
	return registry.AddAllAndSerialize(
		serviceAccount,
		service,
	)
}
