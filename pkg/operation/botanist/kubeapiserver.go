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

package botanist

import (
	"context"
	"fmt"
	"net"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/sets"

	gardencorev1beta1 "github.com/gardener/gardener/pkg/apis/core/v1beta1"
	v1beta1constants "github.com/gardener/gardener/pkg/apis/core/v1beta1/constants"
	v1beta1helper "github.com/gardener/gardener/pkg/apis/core/v1beta1/helper"
	"github.com/gardener/gardener/pkg/client/kubernetes"
	"github.com/gardener/gardener/pkg/client/kubernetes/clientmap/keys"
	"github.com/gardener/gardener/pkg/features"
	"github.com/gardener/gardener/pkg/operation/botanist/component/kubeapiserver"
	"github.com/gardener/gardener/pkg/operation/botanist/component/shared"
	gardenerutils "github.com/gardener/gardener/pkg/utils/gardener"
	kubernetesutils "github.com/gardener/gardener/pkg/utils/kubernetes"
	secretsutils "github.com/gardener/gardener/pkg/utils/secrets"
)

// DefaultKubeAPIServer returns a deployer for the kube-apiserver.
func (b *Botanist) DefaultKubeAPIServer(ctx context.Context) (kubeapiserver.Interface, error) {
	var (
		pods, services string
		nodes          *string
	)
	if b.Shoot.Networks != nil {
		if b.Shoot.Networks.Pods != nil {
			pods = b.Shoot.Networks.Pods.String()
		}
		if b.Shoot.Networks.Services != nil {
			services = b.Shoot.Networks.Services.String()
		}
	}
	if b.Shoot.GetInfo().Spec.Networking != nil {
		nodes = b.Shoot.GetInfo().Spec.Networking.Nodes
	}

	return shared.NewKubeAPIServer(
		ctx,
		b.SeedClientSet,
		b.GardenClient,
		b.Shoot.SeedNamespace,
		b.Shoot.GetInfo().ObjectMeta,
		b.Seed.KubernetesVersion,
		b.Shoot.KubernetesVersion,
		b.ImageVector,
		b.SecretsManager,
		"",
		b.Shoot.GetInfo().Spec.Kubernetes.KubeAPIServer,
		b.computeKubeAPIServerAutoscalingConfig(),
		services,
		kubeapiserver.VPNConfig{
			Enabled:                              true,
			PodNetworkCIDR:                       pods,
			NodeNetworkCIDR:                      nodes,
			HighAvailabilityEnabled:              b.Shoot.VPNHighAvailabilityEnabled,
			HighAvailabilityNumberOfSeedServers:  b.Shoot.VPNHighAvailabilityNumberOfSeedServers,
			HighAvailabilityNumberOfShootClients: b.Shoot.VPNHighAvailabilityNumberOfShootClients,
		},
		v1beta1constants.PriorityClassNameShootControlPlane500,
		false,
		b.Shoot.GetInfo().Spec.Kubernetes.EnableStaticTokenKubeconfig,
		nil,
		nil,
		nil,
		nil,
	)
}

func (b *Botanist) computeKubeAPIServerAutoscalingConfig() kubeapiserver.AutoscalingConfig {
	var (
		hvpaEnabled               = features.DefaultFeatureGate.Enabled(features.HVPA)
		useMemoryMetricForHvpaHPA = false
		scaleDownDisabledForHvpa  = false
		defaultReplicas           *int32
		minReplicas               int32 = 1
		maxReplicas               int32 = 4
		apiServerResources        corev1.ResourceRequirements
	)

	if b.Shoot.Purpose == gardencorev1beta1.ShootPurposeProduction {
		minReplicas = 2
	}

	if v1beta1helper.IsHAControlPlaneConfigured(b.Shoot.GetInfo()) {
		minReplicas = 3
	}

	if metav1.HasAnnotation(b.Shoot.GetInfo().ObjectMeta, v1beta1constants.ShootAlphaControlPlaneScaleDownDisabled) {
		minReplicas = 4
		scaleDownDisabledForHvpa = true
	}

	nodeCount := b.Shoot.GetMinNodeCount()
	if hvpaEnabled {
		nodeCount = b.Shoot.GetMaxNodeCount()
	}
	apiServerResources = resourcesRequirementsForKubeAPIServer(nodeCount, b.Shoot.GetInfo().Annotations[v1beta1constants.ShootAlphaScalingAPIServerClass])

	if b.ManagedSeed != nil {
		hvpaEnabled = features.DefaultFeatureGate.Enabled(features.HVPAForShootedSeed)
		useMemoryMetricForHvpaHPA = true

		if b.ManagedSeedAPIServer != nil {
			minReplicas = *b.ManagedSeedAPIServer.Autoscaler.MinReplicas
			maxReplicas = b.ManagedSeedAPIServer.Autoscaler.MaxReplicas

			if !hvpaEnabled {
				defaultReplicas = b.ManagedSeedAPIServer.Replicas
				apiServerResources = corev1.ResourceRequirements{
					Requests: corev1.ResourceList{
						corev1.ResourceCPU:    resource.MustParse("1750m"),
						corev1.ResourceMemory: resource.MustParse("2Gi"),
					},
				}
			}
		}
	}

	return kubeapiserver.AutoscalingConfig{
		APIServerResources:        apiServerResources,
		HVPAEnabled:               hvpaEnabled,
		Replicas:                  defaultReplicas,
		MinReplicas:               minReplicas,
		MaxReplicas:               maxReplicas,
		UseMemoryMetricForHvpaHPA: useMemoryMetricForHvpaHPA,
		ScaleDownDisabledForHvpa:  scaleDownDisabledForHvpa,
	}
}

func resourcesRequirementsForKubeAPIServer(nodeCount int32, scalingClass string) corev1.ResourceRequirements {
	var (
		validScalingClasses = sets.New("small", "medium", "large", "xlarge", "2xlarge")
		cpuRequest          string
		memoryRequest       string
	)

	if !validScalingClasses.Has(scalingClass) {
		switch {
		case nodeCount <= 2:
			scalingClass = "small"
		case nodeCount <= 10:
			scalingClass = "medium"
		case nodeCount <= 50:
			scalingClass = "large"
		case nodeCount <= 100:
			scalingClass = "xlarge"
		default:
			scalingClass = "2xlarge"
		}
	}

	switch {
	case scalingClass == "small":
		cpuRequest = "800m"
		memoryRequest = "800Mi"

	case scalingClass == "medium":
		cpuRequest = "1000m"
		memoryRequest = "1100Mi"

	case scalingClass == "large":
		cpuRequest = "1200m"
		memoryRequest = "1600Mi"

	case scalingClass == "xlarge":
		cpuRequest = "2500m"
		memoryRequest = "5200Mi"

	case scalingClass == "2xlarge":
		cpuRequest = "3000m"
		memoryRequest = "5200Mi"
	}

	return corev1.ResourceRequirements{
		Requests: corev1.ResourceList{
			corev1.ResourceCPU:    resource.MustParse(cpuRequest),
			corev1.ResourceMemory: resource.MustParse(memoryRequest),
		},
	}
}

func (b *Botanist) computeKubeAPIServerServerCertificateConfig() kubeapiserver.ServerCertificateConfig {
	var (
		ipAddresses = []net.IP{}
		dnsNames    = []string{
			gardenerutils.GetAPIServerDomain(b.Shoot.InternalClusterDomain),
			b.Shoot.GetInfo().Status.TechnicalID,
		}
	)

	if b.Shoot.Networks != nil {
		ipAddresses = append(ipAddresses, b.Shoot.Networks.APIServer)
	}

	if b.Shoot.ExternalClusterDomain != nil {
		dnsNames = append(dnsNames, *(b.Shoot.GetInfo().Spec.DNS.Domain), gardenerutils.GetAPIServerDomain(*b.Shoot.ExternalClusterDomain))
	}

	return kubeapiserver.ServerCertificateConfig{
		ExtraIPAddresses: ipAddresses,
		ExtraDNSNames:    dnsNames,
	}
}

func (b *Botanist) computeKubeAPIServerSNIConfig() kubeapiserver.SNIConfig {
	var config kubeapiserver.SNIConfig

	if b.APIServerSNIEnabled() {
		config.Enabled = true
		config.AdvertiseAddress = b.APIServerClusterIP

		if b.APIServerSNIPodMutatorEnabled() {
			config.PodMutatorEnabled = true
			config.APIServerFQDN = b.Shoot.ComputeOutOfClusterAPIServerAddress(b.APIServerAddress, true)
		}
	}

	// Add control plane wildcard certificate to TLS SNI config if it is available.
	if b.ControlPlaneWildcardCert != nil {
		config.TLS = append(config.TLS, kubeapiserver.TLSSNIConfig{SecretName: &b.ControlPlaneWildcardCert.Name, DomainPatterns: []string{b.ComputeKubeAPIServerHost()}})
	}

	return config
}

// DeployKubeAPIServer deploys the Kubernetes API server.
func (b *Botanist) DeployKubeAPIServer(ctx context.Context) error {
	externalServer := b.Shoot.ComputeOutOfClusterAPIServerAddress(b.APIServerAddress, false)

	if err := shared.DeployKubeAPIServer(
		ctx,
		b.SeedClientSet.Client(),
		b.Shoot.SeedNamespace,
		b.Shoot.Components.ControlPlane.KubeAPIServer,
		b.Shoot.GetInfo().Spec.Kubernetes.KubeAPIServer,
		b.computeKubeAPIServerServerCertificateConfig(),
		b.computeKubeAPIServerSNIConfig(),
		b.Shoot.ComputeOutOfClusterAPIServerAddress(b.APIServerAddress, true),
		externalServer,
		v1beta1helper.GetShootETCDEncryptionKeyRotationPhase(b.Shoot.GetInfo().Status.Credentials),
		v1beta1helper.GetShootServiceAccountKeyRotationPhase(b.Shoot.GetInfo().Status.Credentials),
		b.Shoot.HibernationEnabled,
	); err != nil {
		return err
	}

	if enableStaticTokenKubeconfig := b.Shoot.GetInfo().Spec.Kubernetes.EnableStaticTokenKubeconfig; enableStaticTokenKubeconfig == nil || *enableStaticTokenKubeconfig {
		userKubeconfigSecret, found := b.SecretsManager.Get(kubeapiserver.SecretNameUserKubeconfig)
		if !found {
			return fmt.Errorf("secret %q not found", kubeapiserver.SecretNameUserKubeconfig)
		}

		// add CA bundle as ca.crt to kubeconfig secret for backwards-compatibility
		caBundleSecret, found := b.SecretsManager.Get(v1beta1constants.SecretNameCACluster)
		if !found {
			return fmt.Errorf("secret %q not found", v1beta1constants.SecretNameCACluster)
		}

		kubeconfigSecretData := userKubeconfigSecret.DeepCopy().Data
		kubeconfigSecretData[secretsutils.DataKeyCertificateCA] = caBundleSecret.Data[secretsutils.DataKeyCertificateBundle]

		if err := b.syncShootCredentialToGarden(
			ctx,
			gardenerutils.ShootProjectSecretSuffixKubeconfig,
			map[string]string{v1beta1constants.GardenRole: v1beta1constants.GardenRoleKubeconfig},
			map[string]string{"url": "https://" + externalServer},
			kubeconfigSecretData,
		); err != nil {
			return err
		}
	} else {
		secretName := gardenerutils.ComputeShootProjectSecretName(b.Shoot.GetInfo().Name, gardenerutils.ShootProjectSecretSuffixKubeconfig)
		if err := kubernetesutils.DeleteObject(ctx, b.GardenClient, &corev1.Secret{ObjectMeta: metav1.ObjectMeta{Name: secretName, Namespace: b.Shoot.GetInfo().Namespace}}); err != nil {
			return err
		}
	}

	// TODO(rfranzke): Remove in a future release.
	if err := b.SaveGardenerResourceDataInShootState(ctx, func(gardenerResourceData *[]gardencorev1beta1.GardenerResourceData) error {
		gardenerResourceDataList := v1beta1helper.GardenerResourceDataList(*gardenerResourceData)
		gardenerResourceDataList.Delete("etcdEncryptionConfiguration")
		gardenerResourceDataList.Delete("service-account-key")
		*gardenerResourceData = gardenerResourceDataList
		return nil
	}); err != nil {
		return err
	}

	return kubernetesutils.DeleteObjects(ctx, b.SeedClientSet.Client(),
		&corev1.Secret{ObjectMeta: metav1.ObjectMeta{Namespace: b.Shoot.SeedNamespace, Name: "etcd-encryption-secret"}},
	)
}

// DeleteKubeAPIServer deletes the kube-apiserver deployment in the Seed cluster which holds the Shoot's control plane.
func (b *Botanist) DeleteKubeAPIServer(ctx context.Context) error {
	// invalidate shoot client here before deleting API server
	if err := b.ShootClientMap.InvalidateClient(keys.ForShoot(b.Shoot.GetInfo())); err != nil {
		return err
	}
	b.ShootClientSet = nil

	return b.Shoot.Components.ControlPlane.KubeAPIServer.Destroy(ctx)
}

// WakeUpKubeAPIServer creates a service and ensures API Server is scaled up
func (b *Botanist) WakeUpKubeAPIServer(ctx context.Context) error {
	sniPhase := b.Shoot.Components.ControlPlane.KubeAPIServerSNIPhase.Done()

	if err := b.DeployKubeAPIService(ctx, sniPhase); err != nil {
		return err
	}
	if err := b.Shoot.Components.ControlPlane.KubeAPIServerService.Wait(ctx); err != nil {
		return err
	}
	if b.APIServerSNIEnabled() {
		if err := b.DeployKubeAPIServerSNI(ctx); err != nil {
			return err
		}
	}
	if err := b.DeployKubeAPIServer(ctx); err != nil {
		return err
	}
	if err := kubernetes.ScaleDeployment(ctx, b.SeedClientSet.Client(), kubernetesutils.Key(b.Shoot.SeedNamespace, v1beta1constants.DeploymentNameKubeAPIServer), 1); err != nil {
		return err
	}
	return b.Shoot.Components.ControlPlane.KubeAPIServer.Wait(ctx)
}

// ScaleKubeAPIServerToOne scales kube-apiserver replicas to one.
func (b *Botanist) ScaleKubeAPIServerToOne(ctx context.Context) error {
	return kubernetes.ScaleDeployment(ctx, b.SeedClientSet.Client(), kubernetesutils.Key(b.Shoot.SeedNamespace, v1beta1constants.DeploymentNameKubeAPIServer), 1)
}
