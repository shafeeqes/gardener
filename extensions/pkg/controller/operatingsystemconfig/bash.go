// SPDX-FileCopyrightText: SAP SE or an SAP affiliate company and Gardener contributors
//
// SPDX-License-Identifier: Apache-2.0

package operatingsystemconfig

import (
	"bytes"
	"compress/gzip"
	"context"
	"fmt"
	"path"
	"strings"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/utils/ptr"
	"sigs.k8s.io/controller-runtime/pkg/client"

	extensionsv1alpha1 "github.com/gardener/gardener/pkg/apis/extensions/v1alpha1"
	extensionsv1alpha1helper "github.com/gardener/gardener/pkg/apis/extensions/v1alpha1/helper"
	"github.com/gardener/gardener/pkg/utils"
)

// FilesToDiskScript is a utility function which generates a bash script for writing the provided files to the disk.
func FilesToDiskScript(ctx context.Context, reader client.Reader, namespace string, files []extensionsv1alpha1.File) (string, error) {
	var out strings.Builder

	for _, file := range files {
		// Skip files with TransmitUnencoded=true, they will be handled separately
		if ptr.Deref(file.Content.TransmitUnencoded, false) {
			continue
		}

		data, err := dataForFileContent(ctx, reader, namespace, &file.Content)
		if err != nil {
			return "", err
		}

		out.WriteString(`
mkdir -p "` + path.Dir(file.Path) + `"
` + catDataIntoFile(file.Path, data, false))

		if file.Permissions != nil {
			out.WriteString(`
` + fmt.Sprintf(`chmod "%04o" "%s"`, *file.Permissions, file.Path))
		}
	}

	return out.String(), nil
}

// UnencodedFilesToDiskScript generates a bash script for writing files with TransmitUnencoded=true to disk.
// These files contain placeholders like <<BOOTSTRAP_TOKEN>> that must remain unencoded so MCM can replace them.
func UnencodedFilesToDiskScript(ctx context.Context, reader client.Reader, namespace string, files []extensionsv1alpha1.File) (string, error) {
	var out strings.Builder

	for _, file := range files {
		// Only process files with TransmitUnencoded=true
		if !ptr.Deref(file.Content.TransmitUnencoded, false) {
			continue
		}

		data, err := dataForFileContent(ctx, reader, namespace, &file.Content)
		if err != nil {
			return "", err
		}

		out.WriteString(`
mkdir -p "` + path.Dir(file.Path) + `"
` + catDataIntoFile(file.Path, data, true))

		if file.Permissions != nil {
			out.WriteString(`
` + fmt.Sprintf(`chmod "%04o" "%s"`, *file.Permissions, file.Path))
		}
	}

	return out.String(), nil
}

// UnitsToDiskScript is a utility function which generates a bash script for writing the provided units and their
// drop-ins to the disk.
func UnitsToDiskScript(units []extensionsv1alpha1.Unit) string {
	var out strings.Builder

	for _, unit := range units {
		unitFilePath := path.Join("/", "etc", "systemd", "system", unit.Name)

		if unit.Content != nil {
			out.WriteString(`
` + catDataIntoFile(unitFilePath, []byte(*unit.Content), false))
		}

		if len(unit.DropIns) > 0 {
			unitDropInsDirectoryPath := unitFilePath + ".d"
			out.WriteString(`
mkdir -p "` + unitDropInsDirectoryPath + `"`)

			for _, dropIn := range unit.DropIns {
				out.WriteString(`
` + catDataIntoFile(path.Join(unitDropInsDirectoryPath, dropIn.Name), []byte(dropIn.Content), false))
			}
		}
	}

	return out.String()
}

// WrapProvisionOSCIntoOneshotScript wraps the given script into an oneshot script which exits early when it is called again after finishing successfully.
// It also compresses the entire script to reduce size for cloud provider userdata limits.
// The unencodedScript parameter contains commands that must not be compressed (e.g., files with placeholders like <<BOOTSTRAP_TOKEN>>).
func WrapProvisionOSCIntoOneshotScript(script, unencodedScript string) string {
	var (
		wrappedLines []string
		nextLine     int
	)

	lines := strings.Split(script, "\n")

	for _, line := range lines {
		if !strings.HasPrefix(line, "#") {
			break
		}

		wrappedLines = append(wrappedLines, line)
		nextLine++
	}

	wrappedLines = append(wrappedLines,
		`if [ -f "/var/lib/osc/provision-osc-applied" ]; then`,
		`  echo "Provision OSC already applied, exiting..."`,
		`  exit 0`,
		`fi`,
		``,
	)

	wrappedLines = append(wrappedLines, lines[nextLine:]...)

	wrappedLines = append(wrappedLines,
		``,
		`mkdir -p /var/lib/osc`,
		`touch /var/lib/osc/provision-osc-applied`,
		``,
	)

	// Compress the entire wrapped script
	fullScript := strings.Join(wrappedLines, "\n")
	compressedScript := compressScript([]byte(fullScript))

	// Extract just the shebang
	var headerLines []string
	for _, line := range wrappedLines {
		if !strings.HasPrefix(line, "#") {
			break
		}
		headerLines = append(headerLines, line)
	}

	// Create minimal wrapper that decompresses and executes
	var finalLines []string
	finalLines = append(finalLines, headerLines...)

	// Add unencoded script first (before decompression) so placeholders are available for MCM
	if unencodedScript != "" {
		finalLines = append(finalLines, unencodedScript)
	}

	finalLines = append(finalLines, "\n",
		`base64 -d <<'COMPRESSED_SCRIPT_EOF' | gunzip | bash`,
		utils.EncodeBase64(compressedScript),
		`COMPRESSED_SCRIPT_EOF`,
	)

	return strings.Join(finalLines, "\n")
}

func compressScript(data []byte) []byte {
	var buf bytes.Buffer
	gw := gzip.NewWriter(&buf)

	if _, err := gw.Write(data); err != nil {
		panic(fmt.Sprintf("failed to write compressed data: %v", err))
	}

	if err := gw.Close(); err != nil {
		panic(fmt.Sprintf("failed to close gzip writer: %v", err))
	}

	return buf.Bytes()
}

func dataForFileContent(ctx context.Context, c client.Reader, namespace string, content *extensionsv1alpha1.FileContent) ([]byte, error) {
	if inline := content.Inline; inline != nil {
		return extensionsv1alpha1helper.Decode(inline.Encoding, []byte(inline.Data))
	}

	secret := &corev1.Secret{}
	if err := c.Get(ctx, client.ObjectKey{Namespace: namespace, Name: content.SecretRef.Name}, secret); err != nil {
		return nil, err
	}

	return secret.Data[content.SecretRef.DataKey], nil
}

func catDataIntoFile(path string, data []byte, transmitUnencoded bool) string {
	if transmitUnencoded {
		return `
cat << EOF > "` + path + `"
` + string(data) + `
EOF`
	}

	return `
cat << EOF | base64 -d > "` + path + `"
` + utils.EncodeBase64(data) + `
EOF`
}
