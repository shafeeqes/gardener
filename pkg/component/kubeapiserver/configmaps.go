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

package kubeapiserver

import (
	"context"
	"fmt"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/runtime/serializer"
	"k8s.io/apimachinery/pkg/runtime/serializer/json"
	utilruntime "k8s.io/apimachinery/pkg/util/runtime"
	apiserverv1alpha1 "k8s.io/apiserver/pkg/apis/apiserver/v1alpha1"
	"sigs.k8s.io/controller-runtime/pkg/client"

	"github.com/gardener/gardener/pkg/component/vpnseedserver"
	kubernetesutils "github.com/gardener/gardener/pkg/utils/kubernetes"
	secretsutils "github.com/gardener/gardener/pkg/utils/secrets"
)

var apiServerCodec runtime.Codec

func init() {
	apiServerScheme := runtime.NewScheme()
	utilruntime.Must(apiserverv1alpha1.AddToScheme(apiServerScheme))

	var (
		ser = json.NewSerializerWithOptions(json.DefaultMetaFactory, apiServerScheme, apiServerScheme, json.SerializerOptions{
			Yaml:   true,
			Pretty: false,
			Strict: false,
		})
		versions = schema.GroupVersions([]schema.GroupVersion{apiserverv1alpha1.SchemeGroupVersion})
	)

	apiServerCodec = serializer.NewCodecFactory(apiServerScheme).CodecForVersions(ser, ser, versions, versions)
}

const (
	configMapAdmissionNamePrefix      = "kube-apiserver-admission-config"
	configMapAuditPolicyNamePrefix    = "audit-policy-config"
	configMapEgressSelectorNamePrefix = "kube-apiserver-egress-selector-config"
	configMapEgressSelectorDataKey    = "egress-selector-configuration.yaml"
)

func (k *kubeAPIServer) emptyConfigMap(name string) *corev1.ConfigMap {
	return &corev1.ConfigMap{ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: k.namespace}}
}

func (k *kubeAPIServer) reconcileConfigMapEgressSelector(ctx context.Context, configMap *corev1.ConfigMap) error {
	if !k.values.VPN.Enabled || k.values.VPN.HighAvailabilityEnabled {
		// We don't delete the configmap here as we don't know its name (as it's unique). Instead, we rely on the usual
		// garbage collection for unique secrets/configmaps.
		return nil
	}

	egressSelectorConfig := &apiserverv1alpha1.EgressSelectorConfiguration{
		EgressSelections: []apiserverv1alpha1.EgressSelection{
			{
				Name: "cluster",
				Connection: apiserverv1alpha1.Connection{
					ProxyProtocol: apiserverv1alpha1.ProtocolHTTPConnect,
					Transport: &apiserverv1alpha1.Transport{
						TCP: &apiserverv1alpha1.TCPTransport{
							URL: fmt.Sprintf("https://%s:%d", vpnseedserver.ServiceName, vpnseedserver.EnvoyPort),
							TLSConfig: &apiserverv1alpha1.TLSConfig{
								CABundle:   fmt.Sprintf("%s/%s", volumeMountPathCAVPN, secretsutils.DataKeyCertificateBundle),
								ClientCert: fmt.Sprintf("%s/%s", volumeMountPathHTTPProxy, secretsutils.DataKeyCertificate),
								ClientKey:  fmt.Sprintf("%s/%s", volumeMountPathHTTPProxy, secretsutils.DataKeyPrivateKey),
							},
						},
					},
				},
			},
			{
				Name:       "controlplane",
				Connection: apiserverv1alpha1.Connection{ProxyProtocol: apiserverv1alpha1.ProtocolDirect},
			},
			{
				Name:       "etcd",
				Connection: apiserverv1alpha1.Connection{ProxyProtocol: apiserverv1alpha1.ProtocolDirect},
			},
		},
	}

	data, err := runtime.Encode(apiServerCodec, egressSelectorConfig)
	if err != nil {
		return err
	}

	configMap.Data = map[string]string{configMapEgressSelectorDataKey: string(data)}
	utilruntime.Must(kubernetesutils.MakeUnique(configMap))

	return client.IgnoreAlreadyExists(k.client.Client().Create(ctx, configMap))
}
