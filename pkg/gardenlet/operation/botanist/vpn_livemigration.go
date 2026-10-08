// SPDX-FileCopyrightText: SAP SE or an SAP affiliate company and Gardener contributors
//
// SPDX-License-Identifier: Apache-2.0

package botanist

import (
	"context"

	"github.com/gardener/gardener/imagevector"
	extensionsv1alpha1helper "github.com/gardener/gardener/pkg/api/extensions/v1alpha1/helper"
	v1beta1constants "github.com/gardener/gardener/pkg/apis/core/v1beta1/constants"
	extensionsdnsrecord "github.com/gardener/gardener/pkg/component/extensions/dnsrecord"
	vpnseedserver "github.com/gardener/gardener/pkg/component/networking/vpn/seedserver"
	vpnshoot "github.com/gardener/gardener/pkg/component/networking/vpn/shoot"
	gardenerutils "github.com/gardener/gardener/pkg/utils/gardener"
	imagevectorutils "github.com/gardener/gardener/pkg/utils/imagevector"
)

const dnsRecordLiveMigrationVPNName = "live-migration-vpn"

// LiveMigrationTemporaryVPNDNSName returns the hostname for the temporary VPN DNS record created during live
// control plane migration. It uses the "vpn-tmp" prefix on the shoot's internal cluster domain, mirroring the
// "api." prefix used by GetAPIServerDomain.
func LiveMigrationTemporaryVPNDNSName(internalClusterDomain string) string {
	return "vpn-tmp." + internalClusterDomain
}

// DefaultLiveMigrationVPNDNSRecord returns a DNSRecord deployer for vpn-tmp.<internalDomain>. It is built
// analogously to DefaultInternalDNSRecord but targets the temporary VPN subdomain.
func (b *Botanist) DefaultLiveMigrationVPNDNSRecord() extensionsdnsrecord.Interface {
	values := &extensionsdnsrecord.Values{
		Name:              b.Shoot.GetInfo().Name + "-" + dnsRecordLiveMigrationVPNName,
		SecretName:        DNSRecordSecretPrefix + "-" + b.Shoot.GetInfo().Name + "-" + dnsRecordLiveMigrationVPNName,
		Namespace:         b.Shoot.ControlPlaneNamespace,
		TTL:               b.dnsRecordTTLSeconds(),
		AnnotateOperation: true,
		IPStack:           gardenerutils.GetIPStackForShoot(b.Shoot.GetInfo()),
		Labels: map[string]string{
			v1beta1constants.LabelRole:  "live-migration-vpn",
			v1beta1constants.GardenRole: v1beta1constants.GardenRoleControlPlane,
		},
	}

	var credentialsDeployer extensionsdnsrecord.CredentialsDeployFunc
	if b.NeedsInternalDNS() {
		values.Type = b.Garden.InternalDomain.Provider
		if b.Garden.InternalDomain.Zone != "" {
			values.Zone = &b.Garden.InternalDomain.Zone
		}
		credentialsDeployer = extensionsdnsrecord.CredentialsDeployerFromCredentials(b.Garden.InternalDomain.Credentials, b.Shoot.GetInfo())
		values.DNSName = LiveMigrationTemporaryVPNDNSName(*b.Shoot.InternalClusterDomain)
	}

	return extensionsdnsrecord.New(
		b.Logger,
		b.SeedClientSet.Client(),
		values,
		extensionsdnsrecord.DefaultInterval,
		extensionsdnsrecord.DefaultSevereThreshold,
		extensionsdnsrecord.DefaultTimeout,
		credentialsDeployer,
	)
}

// DeployLiveMigrationVPNDNSRecord sets the record type and value from the destination seed's Istio LB address
// (b.APIServerAddress) and deploys the DNS record.
func (b *Botanist) DeployLiveMigrationVPNDNSRecord(ctx context.Context) error {
	b.Shoot.Components.Extensions.LiveMigrationVPNDNSRecord.SetRecordType(extensionsv1alpha1helper.GetDNSRecordType(b.APIServerAddress))
	b.Shoot.Components.Extensions.LiveMigrationVPNDNSRecord.SetValues([]string{b.APIServerAddress})
	return b.Shoot.Components.Extensions.LiveMigrationVPNDNSRecord.Deploy(ctx)
}

// DestroyLiveMigrationVPNDNSRecord destroys the vpn-tmp DNS record and waits for cleanup.
func (b *Botanist) DestroyLiveMigrationVPNDNSRecord(ctx context.Context) error {
	if err := b.Shoot.Components.Extensions.LiveMigrationVPNDNSRecord.Destroy(ctx); err != nil {
		return err
	}
	return b.Shoot.Components.Extensions.LiveMigrationVPNDNSRecord.WaitCleanup(ctx)
}

// DefaultTemporaryVPNShoot returns a vpn-shoot-tmp component that tunnels to the destination seed via the
// dedicated vpn-tmp.<internalDomain> endpoint. It is deployed on the destination during live migration so
// extension admission webhooks in the shoot cluster are reachable from the destination kube-apiserver. The
// only difference from DefaultVPNShoot is the endpoint (vpn-tmp.<internalDomain> instead of
// api.<internalDomain>) and the "tmp" name suffix; the HA settings mirror the shoot so the temporary tunnel
// matches the destination vpn-seed-server topology. Routing to the right seed server (per-index in HA) is
// handled by the global http-proxy EnvoyFilter on the ingress gateway via the X-Gardener-Destination header,
// exactly as for the regular vpn-shoot, so no per-shoot Istio exposure is required.
func (b *Botanist) DefaultTemporaryVPNShoot() (vpnshoot.Interface, error) {
	endpoint := LiveMigrationTemporaryVPNDNSName(*b.Shoot.InternalClusterDomain)

	image, err := imagevector.Containers().FindImage(imagevector.ContainerImageNameVpnClient, imagevectorutils.RuntimeVersion(b.ShootVersion()), imagevectorutils.TargetVersion(b.ShootVersion()))
	if err != nil {
		return nil, err
	}

	return vpnshoot.New(
		b.SeedClientSet.Client(),
		b.Shoot.ControlPlaneNamespace,
		b.SecretsManager,
		vpnshoot.Values{
			Image: image.String(),
			ReversedVPN: vpnshoot.ReversedVPNValues{
				Header:     "outbound|1194||" + vpnseedserver.ServiceName + "." + b.Shoot.ControlPlaneNamespace + ".svc.cluster.local",
				Endpoint:   endpoint + ".",
				IPFamilies: b.Shoot.GetInfo().Spec.Networking.IPFamilies,
			},
			HighAvailabilityEnabled:              b.Shoot.VPNHighAvailabilityEnabled,
			HighAvailabilityNumberOfSeedServers:  b.Shoot.VPNHighAvailabilityNumberOfSeedServers,
			HighAvailabilityNumberOfShootClients: b.Shoot.VPNHighAvailabilityNumberOfShootClients,
			SeedPodNetwork:                       b.Seed.GetInfo().Spec.Networks.Pods,
			NameSuffix:                           "tmp",
		},
	), nil
}

// DeployTemporaryVPNShoot sets network CIDRs and deploys the vpn-shoot-tmp ManagedResource.
func (b *Botanist) DeployTemporaryVPNShoot(ctx context.Context) error {
	b.Shoot.Components.SystemComponents.TemporaryVPNShoot.SetPodNetworkCIDRs(b.Shoot.Networks.Pods)
	b.Shoot.Components.SystemComponents.TemporaryVPNShoot.SetServiceNetworkCIDRs(b.Shoot.Networks.Services)
	b.Shoot.Components.SystemComponents.TemporaryVPNShoot.SetNodeNetworkCIDRs(b.Shoot.Networks.Nodes)
	return b.Shoot.Components.SystemComponents.TemporaryVPNShoot.Deploy(ctx)
}

// DestroyTemporaryVPNShoot deletes the vpn-shoot-tmp ManagedResource.
func (b *Botanist) DestroyTemporaryVPNShoot(ctx context.Context) error {
	return b.Shoot.Components.SystemComponents.TemporaryVPNShoot.Destroy(ctx)
}
