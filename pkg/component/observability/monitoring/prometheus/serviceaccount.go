// SPDX-FileCopyrightText: SAP SE or an SAP affiliate company and Gardener contributors
//
// SPDX-License-Identifier: Apache-2.0

package prometheus

import (
	corev1 "k8s.io/api/core/v1"
)

func (p *prometheus) serviceAccount() *corev1.ServiceAccount {
	return &corev1.ServiceAccount{
		Name:                         p.name(),
		Namespace:                    p.namespace,
		Labels:                       p.getLabels(),
		AutomountServiceAccountToken: new(false),
	}
}
