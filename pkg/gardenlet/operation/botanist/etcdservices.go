// SPDX-FileCopyrightText: 2024 SAP SE or an SAP affiliate company and Gardener contributors
//
// SPDX-License-Identifier: Apache-2.0

package botanist

import (
	"context"
	"fmt"
	"time"

	"github.com/go-logr/logr"
	corev1 "k8s.io/api/core/v1"
	networkingv1 "k8s.io/api/networking/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/util/intstr"
	"k8s.io/utils/ptr"
	"sigs.k8s.io/controller-runtime/pkg/client"

	gardencorev1beta1 "github.com/gardener/gardener/pkg/apis/core/v1beta1"
	v1beta1constants "github.com/gardener/gardener/pkg/apis/core/v1beta1/constants"
	"github.com/gardener/gardener/pkg/controllerutils"
	"github.com/gardener/gardener/pkg/utils"
	gardenerutils "github.com/gardener/gardener/pkg/utils/gardener"
	kubernetesutils "github.com/gardener/gardener/pkg/utils/kubernetes"
)

func (b *Botanist) CreateServicesAndNetpol(ctx context.Context, log logr.Logger, namespace string) error {
	role := v1beta1constants.ETCDRoleMain
	if !b.Shoot.MigrationConfig.IsSourceSeed {
		role = v1beta1constants.ETCDRoleTarget
	}

	svcSpec := corev1.ServiceSpec{
		Ports: []corev1.ServicePort{
			{
				Name:       "client",
				Port:       2379,
				TargetPort: intstr.FromInt(2379),
				Protocol:   corev1.ProtocolTCP,
			},
			{
				Name:       "peer",
				Port:       2380,
				TargetPort: intstr.FromInt(2380),
				Protocol:   corev1.ProtocolTCP,
			},
		},
		Type: corev1.ServiceTypeLoadBalancer,
		Selector: map[string]string{
			"app":  "etcd-statefulset",
			"role": role,
		},
	}

	for i := range 3 {
		svc := &corev1.Service{
			ObjectMeta: metav1.ObjectMeta{
				Name:      fmt.Sprintf("etcd-%s-%d", role, i),
				Namespace: namespace,
			},
		}

		_, err := controllerutils.GetAndCreateOrMergePatch(ctx, b.SeedClientSet.Client(), svc, func() error {
			svc.Spec = svcSpec
			svc.Spec.PublishNotReadyAddresses = true
			svc.Spec.Selector = utils.MergeStringMaps(svc.Spec.Selector, map[string]string{"apps.kubernetes.io/pod-index": fmt.Sprintf("%d", i)})

			return nil
		})

		if err != nil {
			return err
		}

		kubernetesutils.WaitUntilLoadBalancerIsReady(ctx, log, b.SeedClientSet.Client(), svc.Namespace, svc.Name, time.Minute)
	}

	if role == v1beta1constants.ETCDRoleMain {
		svc := &corev1.Service{
			ObjectMeta: metav1.ObjectMeta{
				Name:      fmt.Sprintf("etcd-%s-client-lb", role),
				Namespace: namespace,
			},
		}

		_, err := controllerutils.GetAndCreateOrMergePatch(ctx, b.SeedClientSet.Client(), svc, func() error {
			svc.Spec = svcSpec

			return nil
		})

		if err != nil {
			return err
		}

		kubernetesutils.WaitUntilLoadBalancerIsReady(ctx, log, b.SeedClientSet.Client(), svc.Namespace, svc.Name, time.Minute)
	}

	// create network policy
	netpol := &networkingv1.NetworkPolicy{
		ObjectMeta: metav1.ObjectMeta{
			Name:      fmt.Sprintf("ingress-to-etcd-%s-from-world", role),
			Namespace: namespace,
		},
	}

	_, err := controllerutils.GetAndCreateOrMergePatch(ctx, b.SeedClientSet.Client(), netpol, func() error {
		netpol.Spec = networkingv1.NetworkPolicySpec{
			Ingress: []networkingv1.NetworkPolicyIngressRule{
				{
					Ports: []networkingv1.NetworkPolicyPort{
						{
							Port:     &intstr.IntOrString{Type: intstr.Int, IntVal: 2379},
							Protocol: ptr.To(corev1.ProtocolTCP),
						},
						{
							Port:     &intstr.IntOrString{Type: intstr.Int, IntVal: 2380},
							Protocol: ptr.To(corev1.ProtocolTCP),
						},
					},
				},
			},
			PolicyTypes: []networkingv1.PolicyType{networkingv1.PolicyTypeIngress},
			PodSelector: metav1.LabelSelector{
				MatchLabels: svcSpec.Selector,
			},
		}

		return nil
	})

	return err
}

func (b *Botanist) StoreLoadBalancerIPsOfETCDServices(ctx context.Context, log logr.Logger, namespace string) error {
	role := v1beta1constants.ETCDRoleMain
	if !b.Shoot.MigrationConfig.IsSourceSeed {
		role = v1beta1constants.ETCDRoleTarget
	}

	data := map[string][]byte{}
	for i := range 3 {
		svc := &corev1.Service{
			ObjectMeta: metav1.ObjectMeta{
				Name:      fmt.Sprintf("etcd-%s-%d", role, i),
				Namespace: namespace,
			},
		}

		if err := b.SeedClientSet.Client().Get(ctx, types.NamespacedName{Namespace: svc.Namespace, Name: svc.Name}, svc); err != nil {
			return err
		}

		if len(svc.Status.LoadBalancer.Ingress) == 0 {
			return fmt.Errorf("no load balancer IP found for service %s/%s", svc.Namespace, svc.Name)
		}

		if svc.Status.LoadBalancer.Ingress[0].Hostname == "" {
			return fmt.Errorf("empty hostname found for service %s/%s", svc.Namespace, svc.Name)
		}

		data[fmt.Sprintf("etcd-%s-%d", role, i)] = []byte(svc.Status.LoadBalancer.Ingress[0].Hostname)
	}

	if b.Shoot.MigrationConfig.IsSourceSeed {
		name := fmt.Sprintf("etcd-%s-client-lb", role)

		svc := &corev1.Service{
			ObjectMeta: metav1.ObjectMeta{
				Name:      name,
				Namespace: namespace,
			},
		}

		if err := b.SeedClientSet.Client().Get(ctx, client.ObjectKeyFromObject(svc), svc); err != nil {
			return err
		}

		if len(svc.Status.LoadBalancer.Ingress) == 0 {
			return fmt.Errorf("no load balancer IP found for service %s/%s", svc.Namespace, svc.Name)
		}

		if svc.Status.LoadBalancer.Ingress[0].Hostname == "" {
			return fmt.Errorf("empty hostname found for service %s/%s", svc.Namespace, svc.Name)
		}

		data[name] = []byte(svc.Status.LoadBalancer.Ingress[0].Hostname)
	}

	gardenSecret := getGardenSecret(b.Shoot.GetInfo().Name, b.Shoot.GetInfo().Namespace)
	_, err := controllerutils.GetAndCreateOrStrategicMergePatch(ctx, b.GardenClient, gardenSecret, func() error {
		gardenSecret.OwnerReferences = []metav1.OwnerReference{
			*metav1.NewControllerRef(b.Shoot.GetInfo(), gardencorev1beta1.SchemeGroupVersion.WithKind("Shoot")),
		}
		gardenSecret.Type = corev1.SecretTypeOpaque
		gardenSecret.Data = utils.MergeStringMaps(gardenSecret.Data, data)
		return nil
	})

	return err
}

func getGardenSecret(shootName, shootNamespace string) *corev1.Secret {
	return &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      gardenerutils.ComputeShootProjectResourceName(shootName, "loadbalancer-ips"),
			Namespace: shootNamespace,
		},
	}
}
