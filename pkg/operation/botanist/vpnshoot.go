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

package botanist

import (
	"context"

	"github.com/gardener/gardener/charts"
	"github.com/gardener/gardener/pkg/operation/botanist/component"
	"github.com/gardener/gardener/pkg/operation/botanist/component/vpnseedserver"
	"github.com/gardener/gardener/pkg/operation/botanist/component/vpnshoot"
	"github.com/gardener/gardener/pkg/utils/imagevector"
)

// DefaultCoreDNS returns a deployer for the VPNShoot
func (b *Botanist) DefaultVPNShoot() (vpnshoot.Interface, error) {
	var (
		image                  *imagevector.Image
		err                    error
		nodeNetwork            = b.Shoot.GetInfo().Spec.Networking.Nodes
		ReversedVPNHeader      string
		ReversedVPNEndPoint    string
		ReversedVPNOpenVPNPort string
		NodeNetworkCIDR        string
	)
	if nodeNetwork != nil {
		NodeNetworkCIDR = *nodeNetwork
	}
	if b.Shoot.ReversedVPNEnabled {
		image, err = b.ImageVector.FindImage(charts.ImageNameVpnShootClient, imagevector.RuntimeVersion(b.ShootVersion()), imagevector.TargetVersion(b.ShootVersion()))
		if err != nil {
			return nil, err
		}
		ReversedVPNHeader = "outbound|1194||" + vpnseedserver.ServiceName + "." + b.Shoot.SeedNamespace + ".svc.cluster.local"
		ReversedVPNEndPoint = b.outOfClusterAPIServerFQDN()
		ReversedVPNOpenVPNPort = "8132"
	} else {
		image, err = b.ImageVector.FindImage(charts.ImageNameVpnShoot, imagevector.RuntimeVersion(b.ShootVersion()), imagevector.TargetVersion(b.ShootVersion()))
		if err != nil {
			return nil, err
		}
	}

	values := vpnshoot.Values{
		Image:                  image.String(),
		VPAEnabled:             b.Shoot.WantsVerticalPodAutoscaler,
		ReversedVPNEnabled:     b.Shoot.ReversedVPNEnabled,
		PodNetworkCIDR:         b.Shoot.Networks.Pods.String(),
		ServiceNetworkCIDR:     b.Shoot.Networks.Services.String(),
		NodeNetworkCIDR:        NodeNetworkCIDR,
		ReversedVPNHeader:      ReversedVPNHeader,
		ReversedVPNEndPoint:    ReversedVPNEndPoint,
		ReversedVPNOpenVPNPort: ReversedVPNOpenVPNPort,
	}

	return vpnshoot.New(
		b.K8sSeedClient.Client(),
		b.Shoot.SeedNamespace,
		values,
	), nil
}

func (b *Botanist) DeployVPNShoot(ctx context.Context) error {
	if b.Shoot.ReversedVPNEnabled {
		b.Shoot.Components.SystemComponents.VPNShoot.SetSecrets(vpnshoot.Secrets{
			TLSAuth: component.Secret{Name: vpnshoot.SecretNameTLSAuth, Checksum: b.LoadCheckSum(vpnshoot.SecretNameTLSAuth), Data: b.LoadSecret(vpnshoot.SecretNameTLSAuth).Data},
			Server:  component.Secret{Name: vpnshoot.SecretName, Checksum: b.LoadCheckSum(vpnshoot.SecretName), Data: b.LoadSecret(vpnshoot.SecretName).Data},
		})
		b.Shoot.Components.SystemComponents.VPNShoot.SetPodAnnotations(map[string]string{
			"checksum/secret-vpn-shoot-client": b.LoadCheckSum(vpnshoot.SecretName),
		})
	} else {
		b.Shoot.Components.SystemComponents.VPNShoot.SetSecrets(vpnshoot.Secrets{
			TLSAuth: component.Secret{Name: vpnshoot.SecretNameTLSAuth, Checksum: b.LoadCheckSum(vpnshoot.SecretNameTLSAuth), Data: b.LoadSecret(vpnshoot.SecretNameTLSAuth).Data},
			DH:      component.Secret{Name: vpnshoot.SecretNameDH, Checksum: b.LoadCheckSum(vpnshoot.SecretNameDH), Data: b.LoadSecret(vpnshoot.SecretNameDH).Data},
			Server:  component.Secret{Name: "vpn-shoot", Checksum: b.LoadCheckSum("vpn-shoot"), Data: b.LoadSecret("vpn-shoot").Data},
		})
		b.Shoot.Components.SystemComponents.VPNShoot.SetPodAnnotations(map[string]string{
			"checksum/secret-vpn-shoot": b.LoadCheckSum("vpn-shoot"),
		})
	}
	return b.Shoot.Components.SystemComponents.VPNShoot.Deploy(ctx)
}
