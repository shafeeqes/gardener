// Copyright 2023 SAP SE or an SAP affiliate company. All rights reserved. This file is licensed under the Apache Software License, v. 2 except as noted otherwise in the LICENSE file
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

package bootstrap

import (
	"bytes"
	_ "embed"
	"fmt"
	"os/exec"
	"text/template"

	"github.com/go-logr/logr"
	"github.com/spf13/afero"
	utilruntime "k8s.io/apimachinery/pkg/util/runtime"
)

var (
	//go:embed templates/scripts/format-kubelet-data-volume.tpl.sh
	formatKubeletDataVolumeTplContent string
	formatKubeletDataVolumeTpl        *template.Template

	// ExecScript is a function for executing the formatting script.
	// Exposed for testing.
	ExecScript = func(scriptPath string) ([]byte, error) {
		return exec.Command("/usr/bin/env", "bash", scriptPath).CombinedOutput()
	}
)

func init() {
	formatKubeletDataVolumeTpl = template.Must(template.New("format-kubelet-data-volume").Parse(formatKubeletDataVolumeTplContent))
}

func formatKubeletDataDevice(log logr.Logger, fs afero.Afero, kubeletDataVolumeSize int64) error {
	log.Info("Rendering script")
	var formatKubeletDataVolumeScript bytes.Buffer
	if err := formatKubeletDataVolumeTpl.Execute(&formatKubeletDataVolumeScript, map[string]interface{}{"kubeletDataVolumeSize": kubeletDataVolumeSize}); err != nil {
		return fmt.Errorf("failed rendering script: %w", err)
	}

	log.Info("Creating temporary file")
	tmpFile, err := fs.TempFile("", "format-kubelet-data-volume-*")
	if err != nil {
		return fmt.Errorf("unable to create temporary directory: %w", err)
	}

	defer func() {
		log.Info("Removing temporary file", "path", tmpFile.Name())
		utilruntime.HandleError(fs.Remove(tmpFile.Name()))
	}()

	log.Info("Writing script into temporary file", "path", tmpFile.Name())
	if err := fs.WriteFile(tmpFile.Name(), formatKubeletDataVolumeScript.Bytes(), 0755); err != nil {
		return fmt.Errorf("unable to write script into temporary file %q: %w", tmpFile.Name(), err)
	}

	log.Info("Executing script")
	output, err := ExecScript(tmpFile.Name())
	if err != nil {
		return fmt.Errorf("failed executing formatter bash script: %w (output: %q)", err, string(output))
	}

	log.Info("Successfully formatted kubelet data volume", "output", string(output))
	return nil
}
