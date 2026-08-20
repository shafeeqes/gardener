// SPDX-FileCopyrightText: SAP SE or an SAP affiliate company and Gardener contributors
//
// SPDX-License-Identifier: Apache-2.0

package istio

import (
	_ "embed"

	fluentbitv1alpha2 "github.com/fluent/fluent-operator/v3/apis/fluentbit/v1alpha2"
	fluentbitv1alpha2filter "github.com/fluent/fluent-operator/v3/apis/fluentbit/v1alpha2/plugins/filter"
	fluentbitv1alpha2parser "github.com/fluent/fluent-operator/v3/apis/fluentbit/v1alpha2/plugins/parser"

	v1beta1constants "github.com/gardener/gardener/pkg/apis/core/v1beta1/constants"
	"github.com/gardener/gardener/pkg/component"
)

const (
	istioProxyParserName = "istio-proxy-parser"
)

var (
	//go:embed lua/add_kubernetes_namespace_name_to_record.lua
	add_kubernetes_namespace_name_to_record_lua string
)

// CentralLoggingConfiguration returns a fluent-bit parser and filter for the cluster-autoscaler logs.
func CentralLoggingConfiguration() (component.CentralLoggingConfig, error) {
	return component.CentralLoggingConfig{Filters: generateClusterFilters(), Parsers: generateClusterParsers()}, nil
}

func generateClusterFilters() []*fluentbitv1alpha2.ClusterFilter {
	return []*fluentbitv1alpha2.ClusterFilter{
		{
			Name:   v1beta1constants.DefaultSNIIngressServiceName,
			Labels: map[string]string{v1beta1constants.LabelKeyCustomLoggingResource: v1beta1constants.LabelValueCustomLoggingResource},
			Spec: fluentbitv1alpha2.FilterSpec{
				Match: "kubernetes.*istio-ingressgateway*istio-proxy*",
				FilterItems: []fluentbitv1alpha2.FilterItem{
					{
						Parser: &fluentbitv1alpha2filter.Parser{
							KeyName:     "log",
							Parser:      istioProxyParserName,
							ReserveData: new(true),
							PreserveKey: new(true),
						},
					},
					{
						Lua: &fluentbitv1alpha2filter.Lua{
							Call: "add_kubernetes_namespace_name_to_record",
							Code: add_kubernetes_namespace_name_to_record_lua,
						},
					},
				},
			},
		},
	}
}

func generateClusterParsers() []*fluentbitv1alpha2.ClusterParser {
	return []*fluentbitv1alpha2.ClusterParser{
		{
			Name:   istioProxyParserName,
			Labels: map[string]string{v1beta1constants.LabelKeyCustomLoggingResource: v1beta1constants.LabelValueCustomLoggingResource},
			Spec: fluentbitv1alpha2.ParserSpec{
				Regex: &fluentbitv1alpha2parser.Regex{
					Regex: `^.*\.(?<namespace_name>shoot--[a-zA-Z0-9_-]+)\.svc\.cluster\.local.*$`,
				},
			},
		},
	}
}
