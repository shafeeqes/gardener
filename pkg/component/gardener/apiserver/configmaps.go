// SPDX-FileCopyrightText: SAP SE or an SAP affiliate company and Gardener contributors
//
// SPDX-License-Identifier: Apache-2.0

package apiserver

import (
	corev1 "k8s.io/api/core/v1"
)

const (
	configMapAuditPolicyNamePrefix = "gardener-apiserver-audit-policy-config"
	configMapAdmissionNamePrefix   = "gardener-apiserver-admission-config"
)

func (g *gardenerAPIServer) emptyConfigMap(name string) *corev1.ConfigMap {
	return &corev1.ConfigMap{Name: name, Namespace: g.namespace}
}
