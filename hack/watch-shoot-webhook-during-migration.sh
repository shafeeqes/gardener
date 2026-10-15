#!/usr/bin/env bash
# SPDX-FileCopyrightText: Contributors to the Gardener project
#
# SPDX-License-Identifier: Apache-2.0

# watch-shoot-webhook-during-migration.sh
#
# Verify the kube-apiserver -> shoot webhook path stays up throughout a (live-)migration.
#
# A ValidatingWebhookConfiguration (failurePolicy=Fail) on pods CREATE+UPDATE points at a webhook
# server pod running on a shoot node. The shoot kube-apiserver reaches that pod over the VPN tunnel,
# so every pod create/update is a synthetic probe of the apiserver->shoot write path: if the tunnel
# breaks, the webhook call fails and - because failurePolicy=Fail - the create/update is REJECTED,
# which this script detects. We loop create -> update -> delete a canary pod and flag any failure.
#
# The webhook only intercepts pods in its own probe namespace (namespaceSelector), so a dangling
# config can never block pod creation anywhere else in the shoot.

set -uo pipefail

KUBECONFIG_SHOOT="${KUBECONFIG:-}"
NAMESPACE="vpn-webhook-probe"
WEBHOOK="vpn-webhook-probe"                              # ValidatingWebhookConfiguration name (cluster-scoped)
INTERVAL=1                                               # seconds between probe cycles
TIMEOUT=5                                                # per webhook-call timeout (seconds)
IMAGE="registry.k8s.io/e2e-test-images/agnhost:2.47"    # agnhost ships a ready-made admission webhook server
PROBE_IMAGE="registry.k8s.io/pause:3.10"                # canary pods never run (pinned to a sink node), image is irrelevant
DEPLOY=1
KEEP=0
SELFTEST=0

# runtime counters
ATTEMPTS=0 FAILURES=0 STREAK=0 MAXSTREAK=0

usage() {
  cat >&2 <<EOF
Usage: $0 [options]
  -k, --kubeconfig FILE   shoot kubeconfig (default: \$KUBECONFIG)
  -n, --namespace NS      probe namespace (default: $NAMESPACE)
  -i, --interval SEC      seconds between probe cycles (default: $INTERVAL)
  -t, --timeout SEC       per webhook-call timeout (default: $TIMEOUT)
      --no-deploy         reuse an existing probe deployment instead of deploying one
      --keep              do not delete the probe namespace/webhook on exit
      --self-test         run the failure-counting logic against a stub and exit
  -h, --help              this help
Press Ctrl-C to stop and print a continuity summary.
EOF
  exit "${1:-0}"
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    -k|--kubeconfig) KUBECONFIG_SHOOT="$2"; shift 2;;
    -n|--namespace)  NAMESPACE="$2"; shift 2;;
    -i|--interval)   INTERVAL="$2"; shift 2;;
    -t|--timeout)    TIMEOUT="$2"; shift 2;;
    --no-deploy)     DEPLOY=0; shift;;
    --keep)          KEEP=1; shift;;
    --self-test)     SELFTEST=1; shift;;
    -h|--help)       usage 0;;
    *) echo "unknown argument: $1" >&2; usage 1;;
  esac
done

k() { kubectl ${KUBECONFIG_SHOOT:+--kubeconfig "$KUBECONFIG_SHOOT"} "$@"; }

record_ok() { ATTEMPTS=$((ATTEMPTS + 1)); STREAK=0; }
record_fail() { # $1=verb  $2=message
  ATTEMPTS=$((ATTEMPTS + 1)); FAILURES=$((FAILURES + 1)); STREAK=$((STREAK + 1))
  (( STREAK > MAXSTREAK )) && MAXSTREAK=$STREAK
  printf '!! %s REJECTED at %s: %s\n' "$1" "$(date -u +%H:%M:%S)" "$(printf '%s' "$2" | tr '\n' ' ' | cut -c1-200)"
}

# probe runs one create -> update -> delete cycle. A webhook-path outage surfaces as a non-zero
# kubectl exit with a "failed calling webhook" error (failurePolicy=Fail), counted as a failure.
# The canary pod is pinned to a non-existent node so it never schedules/runs: only admission fires.
probe() {
  local n="probe-$1" out
  if out=$(k -n "$NAMESPACE" run "$n" --image="$PROBE_IMAGE" --restart=Never \
             --overrides='{"spec":{"nodeName":"vpn-webhook-probe-unschedulable"}}' 2>&1); then
    record_ok
  else
    record_fail "CREATE" "$out"; return
  fi
  if out=$(k -n "$NAMESPACE" annotate --overwrite pod "$n" "probe=$1" 2>&1); then
    record_ok
  else
    record_fail "UPDATE" "$out"
  fi
  k -n "$NAMESPACE" delete pod "$n" --grace-period=0 --force --wait=false >/dev/null 2>&1 || true
}

summary() {
  echo
  echo "=== webhook continuity summary ==="
  echo "attempts=$ATTEMPTS failures=$FAILURES worst-failure-streak=$MAXSTREAK"
  if (( FAILURES == 0 )); then
    echo "RESULT: webhook path never failed - apiserver->shoot stayed up"
  else
    echo "RESULT: webhook path failed $FAILURES time(s), worst streak $MAXSTREAK consecutive"
  fi
}

cleanup() {
  (( KEEP )) && return
  # Delete the cluster-scoped webhook config first so a leftover failurePolicy=Fail config can
  # never outlive its backing service.
  k delete validatingwebhookconfiguration "$WEBHOOK" --ignore-not-found --wait=false >/dev/null 2>&1 || true
  (( DEPLOY )) && k delete namespace "$NAMESPACE" --wait=false >/dev/null 2>&1 || true
}

if (( SELFTEST )); then
  # Stub k() so no cluster is needed: 'run' fails, everything else succeeds. One probe cycle must
  # record exactly one CREATE failure (and short-circuit before the UPDATE).
  k() { case "$3" in run) return 1;; *) return 0;; esac; }
  probe 1 >/dev/null
  summary
  (( FAILURES == 1 && ATTEMPTS == 1 )) && { echo "SELF-TEST PASS"; exit 0; } || { echo "SELF-TEST FAIL"; exit 1; }
fi

[[ -n "$KUBECONFIG_SHOOT" ]] || { echo "no shoot kubeconfig (set --kubeconfig or \$KUBECONFIG)" >&2; exit 1; }
command -v openssl >/dev/null || { echo "openssl is required" >&2; exit 1; }

if (( DEPLOY )); then
  echo "deploying webhook server and configuration in $NAMESPACE ..."
  k create namespace "$NAMESPACE" --dry-run=client -o yaml | k apply -f - >/dev/null
  k label namespace "$NAMESPACE" "$WEBHOOK=true" --overwrite >/dev/null

  # Self-signed CA + server cert for the webhook service DNS name; caBundle below trusts the CA.
  certdir=$(mktemp -d)
  trap 'rm -rf "$certdir"' EXIT
  svc="webhook-svc.$NAMESPACE.svc"
  openssl req -x509 -newkey rsa:2048 -nodes -days 2 -keyout "$certdir/ca.key" -out "$certdir/ca.crt" \
    -subj "/CN=$WEBHOOK-ca" >/dev/null 2>&1
  openssl req -newkey rsa:2048 -nodes -keyout "$certdir/tls.key" -out "$certdir/tls.csr" \
    -subj "/CN=$svc" >/dev/null 2>&1
  openssl x509 -req -in "$certdir/tls.csr" -CA "$certdir/ca.crt" -CAkey "$certdir/ca.key" -CAcreateserial \
    -days 2 -out "$certdir/tls.crt" \
    -extfile <(printf 'subjectAltName=DNS:%s,DNS:%s.cluster.local' "$svc" "$svc") >/dev/null 2>&1
  cabundle=$(base64 < "$certdir/ca.crt" | tr -d '\n')

  k -n "$NAMESPACE" create secret tls webhook-certs --cert="$certdir/tls.crt" --key="$certdir/tls.key" \
    --dry-run=client -o yaml | k apply -f - >/dev/null

  cat <<YAML | k apply -f - >/dev/null
apiVersion: apps/v1
kind: Deployment
metadata:
  name: webhook-server
  namespace: $NAMESPACE
spec:
  replicas: 1
  selector:
    matchLabels: {app: webhook-server}
  template:
    metadata:
      labels: {app: webhook-server}
    spec:
      containers:
      - name: webhook
        image: $IMAGE
        args: ["webhook", "--tls-cert-file=/certs/tls.crt", "--tls-private-key-file=/certs/tls.key", "--port=8443"]
        ports: [{containerPort: 8443}]
        volumeMounts: [{name: certs, mountPath: /certs, readOnly: true}]
      volumes:
      - name: certs
        secret: {secretName: webhook-certs}
---
apiVersion: v1
kind: Service
metadata:
  name: webhook-svc
  namespace: $NAMESPACE
spec:
  selector: {app: webhook-server}
  ports: [{port: 443, targetPort: 8443}]
YAML

  cat <<YAML | k apply -f - >/dev/null
apiVersion: admissionregistration.k8s.io/v1
kind: ValidatingWebhookConfiguration
metadata:
  name: $WEBHOOK
webhooks:
- name: pods.$WEBHOOK.gardener.cloud
  admissionReviewVersions: ["v1"]
  sideEffects: None
  failurePolicy: Fail
  timeoutSeconds: $TIMEOUT
  namespaceSelector:
    matchLabels: {$WEBHOOK: "true"}
  rules:
  - apiGroups: [""]
    apiVersions: ["v1"]
    operations: ["CREATE", "UPDATE"]
    resources: ["pods"]
    scope: Namespaced
  clientConfig:
    service: {name: webhook-svc, namespace: $NAMESPACE, path: /pods, port: 443}
    caBundle: $cabundle
YAML

  echo "waiting for webhook server to become ready ..."
  k -n "$NAMESPACE" rollout status deploy/webhook-server --timeout=120s >/dev/null
fi

trap 'summary; cleanup; exit 0' INT TERM
trap cleanup EXIT

# Warm up: the apiserver may need a moment before it can reach the freshly-created webhook endpoint.
# Retry (uncounted) until the first create succeeds, so startup flakiness is not reported as an outage.
echo "warming up (waiting for first successful webhook call) ..."
for _ in $(seq 1 30); do
  if k -n "$NAMESPACE" run warmup --image="$PROBE_IMAGE" --restart=Never \
       --overrides='{"spec":{"nodeName":"vpn-webhook-probe-unschedulable"}}' >/dev/null 2>&1; then
    k -n "$NAMESPACE" delete pod warmup --grace-period=0 --force --wait=false >/dev/null 2>&1 || true
    break
  fi
  sleep 2
done

echo "watching webhook path in $NAMESPACE (timeout ${TIMEOUT}s, cycle ${INTERVAL}s). Ctrl-C to stop."
i=0
while true; do
  i=$((i + 1))
  probe "$i"
  sleep "$INTERVAL"
done
