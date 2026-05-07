# SPDX-FileCopyrightText: SAP SE or an SAP affiliate company and Gardener contributors
#
# SPDX-License-Identifier: Apache-2.0

set -e
set -o pipefail

source "$(dirname "$0")/../../../hack/lockfile.sh"
acquire_lockfile "/tmp/generate-patch-gardenlet.sh.lock"

dir="$(dirname $0)"
type="${1:-image}"
ref="$SKAFFOLD_IMAGE"

if [[ "$type" == "helm" ]]; then
  patch_file="$dir/patch-helm-ref.yaml"
  cat <<EOF > "$patch_file"
apiVersion: seedmanagement.gardener.cloud/v1alpha1
kind: Gardenlet
metadata:
  name: local
  namespace: garden
spec:
  deployment:
    helm:
      ociRepository:
        ref: $ref
EOF
fi

if [[ "$type" == "image" ]]; then
  image_name="$2"
  repository="$(echo "$ref" | rev | cut -d':' -f 2- | rev)"
  tag="$(echo "$ref" | rev | cut -d':' -f 1 | rev)"

  patch_file="$dir/patch-imagevector-overwrite.yaml"
  if [[ ! -f "$patch_file" ]]; then
    cat <<EOF > "$patch_file"
apiVersion: seedmanagement.gardener.cloud/v1alpha1
kind: Gardenlet
metadata:
  name: local
  namespace: garden
spec:
  deployment:
    imageVectorOverwrite: |
      caBundle:
        inline: |
          -----BEGIN CERTIFICATE-----
          MIIFGzCCAwOgAwIBAgIUFf2NeqI0BGYozWBxWXlKUrlK9lgwDQYJKoZIhvcNAQEL
          BQAwHTEbMBkGA1UEAwwSTXlJbnRlcm5hbEhhcmJvckNBMB4XDTI2MDEyMTEwMTkz
          NloXDTM2MDExOTEwMTkzNlowHTEbMBkGA1UEAwwSTXlJbnRlcm5hbEhhcmJvckNB
          MIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEAwgLaLJQtfa575iPMB/ho
          bshO59lhRyiGrgK3/7uMQ6aQcIV/Kstf4/jIgjNZZNtD8dRm0PxfEaBfJFUArXns
          SNupJ1WVHNfDTb9JRV8xToAjueC0x7zYrywj6TL2xtYyB0EE91XigIp7hRjPKIpd
          4szWK/l8Wv8yvUDyp/NSR1lTYAzlxdic5N/J/EVU128YKBbwzcFb1qQFSwGOHusU
          ZQhyUdj4P0ZsEgfEMFdGW3RgLN7Qxp/TjJEotlGj39TAPnOtfatl7ttyGjvIinKa
          TTvkUR8lth1zNbmBujssS0cSQ+xA85L6yWndAu5Xi636gjp14M5oGnVFYCf0QtgH
          /zcF3bEc4VBQXhHNP8XF4ukxUcQAPqsx7vBHrN6VG9oXeORU/4440hXC7+WL2I2S
          kQlqHmi501gzacpdFZp5IYazl3NCOlJ5uTkZkPllGy2HLRpHTI30eAct7AeyYFEP
          BbixstOATHFCCs7D/Oo+jwdCPm9b9awyZGl76PqMoY2MUYQv49aLkije8pdh7Z8s
          Is4Yfvr0ouyfAGQbolgQAqDsqThQiEhm2nTXac55hDY4UD2ktjVZsXDxtwYyRTPm
          7dksj/b7pGxfFGGdyOMrgW7sd+ln2bpcpJEWmB7fuq/6WgXgeoMpo0cH/gQj1/WL
          uLpkYtuK87U451YbPFo+TEkCAwEAAaNTMFEwHQYDVR0OBBYEFEpUVXZNvNRR3DFC
          CqTaTpT7LhuVMB8GA1UdIwQYMBaAFEpUVXZNvNRR3DFCCqTaTpT7LhuVMA8GA1Ud
          EwEB/wQFMAMBAf8wDQYJKoZIhvcNAQELBQADggIBAFYVXakSwHgjxvpmSeLXHJsQ
          9QSKqQ7TMlIiH+l4ep7xrGs9ebA/xFDAR+9gPJRaCRBABoUxPVxVno8CLJ/iCu8b
          Vhk6AaksPGfDfea2xWA9yd/Jere3heS4/9fAZ/VVydl66xgdv/SpxGjpvjnAsMhW
          gCUEFKhiUFK/OT684nSB5m8JVaq5u5rVchlc3C44lFagjUflPFEGcVN9ko7OloAh
          EVCgxzo9VeiFag4ffNqVTJBU1D0e6qdn3oiA3cismjXBxs+Q2vVaJJyLqnlMmSb0
          8/+YyDGBy9VQ3Osxm42Qb+7NZ9hiZrITPPPY8ohAIFNFQQJVIYtPY9KnUEE/q05m
          6Hl/7TccALz/fwodC1zete4k4rbsKJ+w8b6IktEyyGO1jD7TWn0BbTQyY5YV/R0G
          OdVHRAlJ7SFjYQ4KE7FlJkIEzlz+2zbvD1avhDGL5bXFysXWg5b0P8mHRFLl4o7e
          kO7lkBXBXNktBDc6ik7NNv1MtlE+Qq9IIvMWinYQHhWHu9n2VD8R+5kaj+i/lKek
          Dh/ENvuKYd38YmaywyvgHwYHsoXWzxd+mdpih0tTxQJh3c7fLPwcQ9VYiiB0azQe
          1Q00llmQdg8iG+e0A6q5qrXCie6cV2lM34noW2kxiTxC+W4jS69jQZbzQDIgno2c
          36XuP9wP3FrTxHCZ678c
          -----END CERTIFICATE-----
      images: []
EOF
  fi

  images="$(yq e '.spec.deployment.imageVectorOverwrite' "$patch_file" | yq -o json)"

  images="$(echo "$images" | jq -r \
    --arg name "$image_name" \
    --arg repository "$repository" \
    --arg tag "$tag" \
    '.images |= if any(.name == $name) then
        map(if .name == $name then .repository = $repository | .tag = $tag else . end)
      else
        . + [{name: $name, repository: $repository, tag: $tag}] end' |\
   yq eval -P)"

  yq eval ".spec.deployment.imageVectorOverwrite = \"$images\"" -i "$patch_file"
fi
