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

package features

import (
	utilruntime "k8s.io/apimachinery/pkg/util/runtime"
	utilfeature "k8s.io/apiserver/pkg/util/feature"
	"k8s.io/component-base/featuregate"

	"github.com/gardener/gardener/pkg/features"
)

var featureGates = map[featuregate.Feature]featuregate.FeatureSpec{
	features.SeedChange:                      {Default: false, PreRelease: featuregate.Alpha},
	features.AdminKubeconfigRequest:          {Default: true, PreRelease: featuregate.Beta},
	features.UseDNSRecords:                   {Default: false, PreRelease: featuregate.Alpha},
	features.WorkerPoolKubernetesVersion:     {Default: false, PreRelease: featuregate.Alpha},
	features.SecretBindingProviderValidation: {Default: false, PreRelease: featuregate.Alpha},
}

// RegisterFeatureGates registers the feature gates of the Gardener API Server.
func RegisterFeatureGates() {
	utilruntime.Must(utilfeature.DefaultMutableFeatureGate.Add(featureGates))
}
