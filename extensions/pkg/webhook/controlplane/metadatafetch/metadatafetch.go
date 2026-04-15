// SPDX-FileCopyrightText: SAP SE or an SAP affiliate company and Gardener contributors
//
// SPDX-License-Identifier: Apache-2.0

// Package metadatafetch provides a helper for provider extensions to inject a cloud metadata
// fetch script into provision-purpose OperatingSystemConfig resources via their control plane
// mutating webhook. The script is called by the gardener-node-init service to retrieve data
// (e.g. registry CA certificates) from the cloud provider's instance metadata service before
// pulling the gardener-node-agent image.
package metadatafetch

import (
	"k8s.io/utils/ptr"

	extensionsv1alpha1 "github.com/gardener/gardener/pkg/apis/extensions/v1alpha1"
	"github.com/gardener/gardener/pkg/utils"
)

const (
	// PathFetchMetadataScript is the well-known path at which the metadata fetch script is placed
	// by the provider webhook. The gardener-node-init service calls this script to retrieve
	// the registry CA bundle from the cloud provider's instance metadata service.
	// The script must accept a single string argument (the metadata key) and print the
	// corresponding value to stdout, exiting non-zero only on unexpected errors.
	PathFetchMetadataScript = "/opt/gardener/bin/fetch-metadata.sh"

	// KeyRegistryCABundle is the metadata key for the PEM-encoded registry CA certificate(s).
	KeyRegistryCABundle = "gardener.cloud/registry-ca-bundle"
)

// InjectMetadataScript returns an extensionsv1alpha1.File that places the given fetch script
// at PathFetchMetadataScript. Provider extensions call this from their
// EnsureAdditionalProvisionFiles() webhook implementation.
//
// The fetchScriptContent must be a shell script that:
//   - Accepts a single argument: the metadata key name (e.g. "gardener.cloud/registry-ca-bundle")
//   - Prints the corresponding value to stdout
//   - Exits silently (exit 0) when the key is not found or metadata is unavailable
//
// This follows the same pattern as machinecontrollermanager.ProviderSidecarContainer() —
// a generic helper in the extensions library that providers call with provider-specific content.
func InjectMetadataScript(fetchScriptContent string) extensionsv1alpha1.File {
	return extensionsv1alpha1.File{
		Path:        PathFetchMetadataScript,
		Permissions: ptr.To[uint32](0755),
		Content: extensionsv1alpha1.FileContent{
			Inline: &extensionsv1alpha1.FileContentInline{
				Encoding: "b64",
				Data:     utils.EncodeBase64([]byte(fetchScriptContent)),
			},
		},
	}
}
