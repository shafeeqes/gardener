# Adding Support For a New Kubernetes Version

This document describes the steps needed to perform in order to confidently add support for a new Kubernetes **minor** version.

> ⚠️ Typically, once a minor Kubernetes version `vX.Y` is supported by Gardener, then all patch versions `vX.Y.Z` are also automatically supported without any required action.
This is because patch versions do not introduce any new feature or API changes, so there is nothing that needs to be adapted in `gardener/gardener` code.

The Kubernetes community release a new minor version roughly every 4 months.
Please refer to the [official documentation](https://kubernetes.io/releases/release/) about their release cycles for any additional information.

Shortly before a new release, an "umbrella" issue should be opened which is used to collect the required adaptations and to track the work items.
For example, [#5102](https://github.com/gardener/gardener/issues/5102) can be used as a template for the issue description.
As you can see, the task of supporting a new Kubernetes version also includes the provider extensions maintained in the `gardener` GitHub organization and is not restricted to `gardener/gardener` only.

Generally, the work items can be split into two groups:
The first group contains tasks specific to the changes in the given Kubernetes release, the second group contains Kubernetes release-independent tasks.

> ℹ️ Upgrading the `k8s.io/*` and `sigs.k8s.io/controller-runtime` Golang dependencies is typically tracked and worked on separately (see e.g. [#4772](https://github.com/gardener/gardener/issues/4772) or [#5282](https://github.com/gardener/gardener/issues/5282)).

## Deriving Release-Specific Tasks

Most new minor Kubernetes releases incorporate API changes, deprecations, or new features.
The community announces them via their [change logs](https://github.com/kubernetes/kubernetes/blob/master/CHANGELOG/).
In order to derive the release-specific tasks, the respective change log for the new version `vX.Y` has to be read and understood (for example, [the changelog](https://github.com/kubernetes/kubernetes/blob/master/CHANGELOG/CHANGELOG-1.24.md) for `v1.24`).

As already mentioned, typical changes to watch out for are:

- API version promotions or deprecations
- Feature gate promotions or deprecations
- CLI flag changes for Kubernetes components
- New default values in resources
- New available fields in resources
- New features potentially relevant for the Gardener system
- Changes of labels or annotations Gardener relies on
- ...

Obviously, this requires a certain experience and understanding of the Gardener project so that all "relevant changes" can be identified.
While reading the change log, add the tasks (along with the respective PR in `kubernetes/kubernetes` to the umbrella issue).

> ℹ️ Some of the changes might be specific to certain cloud providers. Pay attention to those as well and add related tasks to the issue.

## List Of Release-Independent Tasks

The following paragraphs describe recurring tasks that need to be performed for each new release.

### Make Sure a New `hyperkube` Image Is Released

The [`gardener/hyperkube`](https://github.com/gardener/hyperkube) repository is used to release container images consisting of the `kubectl` and `kubelet` binaries.

There is a CI/CD job that runs periodically and releases a new `hyperkube` image when there is a new Kubernetes release. Before proceeding with the next steps, make sure that a new `hyperkube` image is released for the corresponding new Kubernetes minor version. Make sure that container image is present in GCR.

### Adapting Gardener

- Allow instantiation of a Kubernetes client for the new minor version and update the `README.md`:
  - See [this](https://github.com/gardener/gardener/pull/5255/commits/63bdae022f1cb1c9cbd1cd49b557545dca2ec32a) example commit.
  - The list of supported versions is meanwhile maintained [here](../../pkg/utils/validation/kubernetesversion/version.go) in the `SupportedVersions` variable.
- Maintain the Kubernetes feature gates used for validation of `Shoot` resources:
  - The feature gates are maintained in [this](https://github.com/gardener/gardener/blob/master/pkg/utils/validation/features/featuregates.go) file.
  - To maintain this list for new Kubernetes versions, run `hack/compare-k8s-feature-gates.sh <old-version> <new-version>` (e.g. `hack/compare-k8s-feature-gates.sh v1.22 v1.23`).
  - It will present 3 lists of feature gates: those added and those removed in `<new-version>` compared to `<old-version>` and feature gates that got locked to default in `<new-version>`.
  - Add all added feature gates to the map with `<new-version>` as `AddedInVersion` and no `RemovedInVersion`.
  - For any removed feature gates, add `<new-version>` as `RemovedInVersion` to the already existing feature gate in the map.
  - For feature gates locked to default, add `<new-version>` as `LockedToDefaultInVersion` to the already existing feature gate in the map.
  - See [this](https://github.com/gardener/gardener/pull/5255/commits/97923b0604300ff805def8eae981ed388d5e4a83) example commit.
- Maintain the Kubernetes `kube-apiserver` admission plugins used for validation of `Shoot` resources:
  - The admission plugins are maintained in [this](https://github.com/gardener/gardener/blob/master/pkg/utils/validation/admissionplugins/admissionplugins.go) file.
  - To maintain this list for new Kubernetes versions, run `hack/compare-k8s-admission-plugins.sh <old-version> <new-version>` (e.g. `hack/compare-k8s-admission-plugins.sh 1.24 1.25`).
  - It will present 2 lists of admission plugins: those added and those removed in `<new-version>` compared to `<old-version>`.
  - Add all added admission plugins to the `admissionPluginsVersionRanges` map with `<new-version>` as `AddedInVersion` and no `RemovedInVersion`.
  - For any removed admission plugins, add `<new-version>` as `RemovedInVersion` to the already existing admission plugin in the map.
  - Flag any admission plugins that are required (plugins that must not be disabled in the `Shoot` spec) by setting the `Required` boolean variable to true for the admission plugin in the map.
  - Flag any admission plugins that are forbidden by setting the `Forbidden` boolean variable to true for the admission plugin in the map.
- Maintain the `ServiceAccount` names for the controllers part of `kube-controller-manager`:
  - The names are maintained in [this](https://github.com/gardener/gardener/blob/master/pkg/operation/botanist/component/shootsystem/shootsystem.go) file.
  - To maintain this list for new Kubernetes versions, run `hack/compare-k8s-controllers.sh <old-version> <new-version>` (e.g. `hack/compare-k8s-controllers.sh 1.22 1.23`).
  - It will present 2 lists of controllers: those added and those removed in `<new-version>` compared to `<old-version>`.
  - Double check whether such `ServiceAccount` indeed appears in the `kube-system` namespace when creating a cluster with `<new-version>`. Note that it sometimes might be hidden behind a default-off feature gate. You can create a local cluster with the new version using the [local provider](https://github.com/gardener/gardener/blob/master/docs/development/getting_started_locally.md).
  - If it appears, add all added controllers to the list based on the Kubernetes version ([example](https://github.com/gardener/gardener/blob/5f87b18b951e104c2c25a7145548c8a2d08adefc/pkg/operation/botanist/component/shootsystem/shootsystem.go#L170-L174)).
  - For any removed controllers, add them only to the Kubernetes version if it is low enough.
- Maintain the names of controllers used for Workerless Shoots, [here](https://github.com/gardener/gardener/blob/61b8ad38fb676256433d314b938a572ec2ae01a1/pkg/operation/botanist/component/kubecontrollermanager/kube_controller_manager.go#L614) after carefully evaluating whether they are needed if there are no workers.
- Maintain copies of the `DaemonSet` controller's scheduling logic:
  - `gardener-resource-manager`'s [`Node` controller](../concepts/resource-manager.md#node-controllerpkgresourcemanagercontrollernode) uses a copy of parts of the `DaemonSet` controller's logic for determining whether a specific `Node` should run a daemon pod of a given `DaemonSet`: see [this file](https://github.com/gardener/gardener/blob/master/pkg/resourcemanager/controller/node/helper/daemon_controller.go).
  - Check the referenced upstream files for changes to the `DaemonSet` controller's logic and adapt our copies accordingly. This might include introducing version-specific checks in our codebase to handle different shoot cluster versions.
- Bump the used Kubernetes version for local `Shoot` and local e2e test.
  - See [this](https://github.com/gardener/gardener/pull/5255/commits/5707c4c7a4fd265b176387178b755cabeea89ffe) example commit.

#### Filing the Pull Request

Work on all the tasks you have collected and validate them using the [local provider](https://github.com/gardener/gardener/blob/master/docs/development/getting_started_locally.md).
Execute the e2e tests and if everything looks good, then go ahead and file the PR ([example PR](https://github.com/gardener/gardener/pull/5255)).
Generally, it is great if you add the PRs also to the umbrella issue so that they can be tracked more easily.

### Adapting Provider Extensions

After the PR in `gardener/gardener` for the support of the new version has been merged, you can go ahead and work on the provider extensions.

> Actually, you can already start even if the PR is not yet merged and use the branch of your fork.

- Revendor the `github.com/gardener/gardener` dependency in the extension and update the `README.md`.
- Work on release-specific tasks related to this provider.

#### Maintaining the `cloud-controller-manager` Images

Some of the cloud providers are not yet using upstream `cloud-controller-manager` images.
Instead, we build and maintain them ourselves:

- https://github.com/gardener/cloud-provider-aws
- https://github.com/gardener/cloud-provider-azure (since `v1.23`, we use the upstream image)
- https://github.com/gardener/cloud-provider-gcp

Until we switch to upstream images, you need to revendor the Kubernetes dependencies and release a new image.
The required steps are as follows:

- Checkout the `legacy-cloud-provider` branch of the respective repository
- Bump the versions in the `Dockerfile` ([example commit](https://github.com/gardener/cloud-provider-gcp/commit/b7eb3f56b252aaf29adc78406672574b1bc17495)).
- Update the `VERSION` to `vX.Y.Z-dev` where `Z` is the latest available Kubernetes patch version for the `vX.Y` minor version.
- Update the `k8s.io/*` dependencies in the `go.mod` file to `vX.Y.Z` and run `go mod vendor` and `go mod tidy` ([example commit](https://github.com/gardener/cloud-provider-gcp/commit/d41cc9f035bcc4893b40d90a4f617c4d436c5d62)).
- Checkout a new `release-vX.Y` branch and release it ([example](https://github.com/gardener/cloud-provider-gcp/commits/release-v1.23))

> As you are already on it, it is great if you also bump the `k8s.io/*` dependencies for the last three minor releases as well.
In this case, you need to checkout the `release-vX.{Y-{1,2,3}}` branches and only perform the last three steps ([example branch](https://github.com/gardener/cloud-provider-gcp/commits/release-v1.20), [example commit](https://github.com/gardener/cloud-provider-gcp/commit/372aa43fbacdeb76b3da9f6fad6cfd924d916227)).

Now you need to update the new releases in the `charts/images.yaml` of the respective provider extension so that they are used (see this [example commit](https://github.com/gardener/gardener-extension-provider-aws/pull/480/commits/76256de933d5a508aba26a8f589dd1a39026142e) for reference).

#### Filing the Pull Request

Again, work on all the tasks you have collected.
This time, you cannot use the local provider for validation but should create real clusters on the various infrastructures.
Typically, the following validations should be performed:

- Create new clusters with versions < `vX.Y`
- Create new clusters with version = `vX.Y`
- Upgrade old clusters from version `vX.{Y-1}` to version `vX.Y`
- Delete clusters with versions < `vX.Y`
- Delete clusters with version = `vX.Y`

If everything looks good, then go ahead and file the PR ([example PR](https://github.com/gardener/gardener-extension-provider-aws/pull/480)).
Generally, it is again great if you add the PRs also to the umbrella issue so that they can be tracked more easily.
