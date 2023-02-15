//go:build !ignore_autogenerated
// +build !ignore_autogenerated

/*
Copyright (c) SAP SE or an SAP affiliate company. All rights reserved. This file is licensed under the Apache Software License, v. 2 except as noted otherwise in the LICENSE file

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

     http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

// Code generated by defaulter-gen. DO NOT EDIT.

package v1alpha1

import (
	runtime "k8s.io/apimachinery/pkg/runtime"
)

// RegisterDefaults adds defaulters functions to the given scheme.
// Public to allow building arbitrary schemes.
// All generated defaulters are covering - they call all nested defaulters.
func RegisterDefaults(scheme *runtime.Scheme) error {
	scheme.AddTypeDefaultingFunc(&ResourceManagerConfiguration{}, func(obj interface{}) {
		SetObjectDefaults_ResourceManagerConfiguration(obj.(*ResourceManagerConfiguration))
	})
	return nil
}

func SetObjectDefaults_ResourceManagerConfiguration(in *ResourceManagerConfiguration) {
	SetDefaults_ResourceManagerConfiguration(in)
	SetDefaults_SourceClientConnection(&in.SourceClientConnection)
	SetDefaults_ClientConnectionConfiguration(&in.SourceClientConnection.ClientConnectionConfiguration)
	if in.TargetClientConnection != nil {
		SetDefaults_TargetClientConnection(in.TargetClientConnection)
		SetDefaults_ClientConnectionConfiguration(&in.TargetClientConnection.ClientConnectionConfiguration)
	}
	SetDefaults_LeaderElectionConfiguration(&in.LeaderElection)
	SetDefaults_ServerConfiguration(&in.Server)
	SetDefaults_ResourceManagerControllerConfiguration(&in.Controllers)
	SetDefaults_GarbageCollectorControllerConfig(&in.Controllers.GarbageCollector)
	SetDefaults_HealthControllerConfig(&in.Controllers.Health)
	SetDefaults_KubeletCSRApproverControllerConfig(&in.Controllers.KubeletCSRApprover)
	SetDefaults_ManagedResourceControllerConfig(&in.Controllers.ManagedResource)
	SetDefaults_NodeControllerConfig(&in.Controllers.Node)
	SetDefaults_SecretControllerConfig(&in.Controllers.Secret)
	SetDefaults_TokenInvalidatorControllerConfig(&in.Controllers.TokenInvalidator)
	SetDefaults_TokenRequestorControllerConfig(&in.Controllers.TokenRequestor)
	SetDefaults_PodSchedulerNameWebhookConfig(&in.Webhooks.PodSchedulerName)
	SetDefaults_ProjectedTokenMountWebhookConfig(&in.Webhooks.ProjectedTokenMount)
}
