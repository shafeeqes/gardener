#!/usr/bin/env bash
# SPDX-FileCopyrightText: Contributors to the Gardener project
#
# SPDX-License-Identifier: Apache-2.0

# watch-shoot-vpn-during-migration.sh
#
# Detect VPN tunnel disruptions while a shoot's control plane is being (live-)migrated.
#
# kubectl logs -f streams kube-apiserver -> (VPN tunnel) -> kubelet -> pod, so a stall or
# break in the log stream means the control plane temporarily lost its tunnel into the shoot
# network. We deploy a 1s heartbeat pod, follow its logs, and flag any gap longer than a
# threshold. The gap tracker survives stream reconnects, so an outage that kills the
# `kubectl logs -f` stream itself is still counted once connectivity returns.

set -uo pipefail

KUBECONFIG_SHOOT="${KUBECONFIG:-}"
NAMESPACE="vpn-migration-probe"
POD="vpn-heartbeat"
THRESHOLD=5     # seconds without a log line => treat as a disruption
INTERVAL=1      # heartbeat cadence in seconds
DEPLOY=1        # deploy the heartbeat pod (use --no-deploy to watch an existing pod)
KEEP=0          # keep the probe namespace on exit
SELFTEST=0

# runtime counters (global so they persist across stream reconnects)
LAST=0 DISRUPTIONS=0 MAXGAP=0 LINES=0

usage() {
  cat >&2 <<EOF
Usage: $0 [options]
  -k, --kubeconfig FILE   shoot kubeconfig (default: \$KUBECONFIG)
  -n, --namespace NS      namespace of the pod to watch (default: $NAMESPACE)
  -p, --pod NAME          pod to watch (default: $POD, the deployed heartbeat)
  -t, --threshold SEC     gap that counts as a disruption (default: $THRESHOLD)
  -i, --interval SEC      heartbeat cadence when deploying (default: $INTERVAL)
      --no-deploy         watch an existing pod instead of deploying a heartbeat
      --keep              do not delete the probe namespace on exit
      --self-test         run the gap detector against a synthetic stall and exit
  -h, --help              this help
Press Ctrl-C to stop and print a continuity summary.
EOF
  exit "${1:-0}"
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    -k|--kubeconfig) KUBECONFIG_SHOOT="$2"; shift 2;;
    -n|--namespace)  NAMESPACE="$2"; shift 2;;
    -p|--pod)        POD="$2"; shift 2;;
    -t|--threshold)  THRESHOLD="$2"; shift 2;;
    -i|--interval)   INTERVAL="$2"; shift 2;;
    --no-deploy)     DEPLOY=0; shift;;
    --keep)          KEEP=1; shift;;
    --self-test)     SELFTEST=1; shift;;
    -h|--help)       usage 0;;
    *) echo "unknown argument: $1" >&2; usage 1;;
  esac
done

k() { kubectl ${KUBECONFIG_SHOOT:+--kubeconfig "$KUBECONFIG_SHOOT"} "$@"; }

# stream emits the raw log lines. Overridden in --self-test.
stream() { k -n "$NAMESPACE" logs -f --tail=1 "$POD"; }

# monitor reads lines from stdin and updates the global counters. It returns when the
# stream closes (EOF) so the caller can reconnect; a long gap between lines (whether a
# stall within one stream or across a reconnect) is counted as a single disruption.
monitor() {
  local line rc now gap
  while true; do
    if IFS= read -r -t "$THRESHOLD" line; then
      now=$(date +%s); gap=$((now - LAST)); LAST=$now; LINES=$((LINES + 1))
      if (( gap > THRESHOLD )); then
        DISRUPTIONS=$((DISRUPTIONS + 1))
        (( gap > MAXGAP )) && MAXGAP=$gap
        printf '!! DISRUPTION: no logs for %ss, recovered at %s\n' "$gap" "$(date -u +%H:%M:%S)"
      fi
      printf '   %s\n' "$line"
    else
      rc=$?
      (( rc > 128 )) || return 0   # read error that is not a timeout => EOF, reconnect
      printf '.. stall: %ss without logs (since %s)\n' "$(( $(date +%s) - LAST ))" "$(date -u +%H:%M:%S)"
    fi
  done
}

summary() {
  echo
  echo "=== VPN continuity summary ==="
  echo "lines=$LINES disruptions=$DISRUPTIONS worst-gap=${MAXGAP}s threshold=${THRESHOLD}s"
  if (( DISRUPTIONS == 0 )); then
    echo "RESULT: no VPN disruption detected"
  else
    echo "RESULT: VPN disrupted $DISRUPTIONS time(s), worst outage ${MAXGAP}s"
  fi
}

cleanup() {
  if (( DEPLOY && ! KEEP )); then
    k delete namespace "$NAMESPACE" --wait=false >/dev/null 2>&1 || true
  fi
}

if (( SELFTEST )); then
  THRESHOLD=2
  # one line, a stall longer than the threshold, then one more line => exactly one disruption.
  stream() { echo "beat=1"; sleep $((THRESHOLD + 2)); echo "beat=2"; }
  LAST=$(date +%s)
  monitor < <(stream)
  summary
  (( DISRUPTIONS >= 1 )) && { echo "SELF-TEST PASS"; exit 0; } || { echo "SELF-TEST FAIL"; exit 1; }
fi

[[ -n "$KUBECONFIG_SHOOT" ]] || { echo "no shoot kubeconfig (set --kubeconfig or \$KUBECONFIG)" >&2; exit 1; }

if (( DEPLOY )); then
  echo "deploying heartbeat pod $NAMESPACE/$POD ..."
  k create namespace "$NAMESPACE" --dry-run=client -o yaml | k apply -f - >/dev/null
  cat <<YAML | k apply -f - >/dev/null
apiVersion: v1
kind: Pod
metadata:
  name: $POD
  namespace: $NAMESPACE
spec:
  terminationGracePeriodSeconds: 1
  containers:
  - name: heartbeat
    image: registry.k8s.io/e2e-test-images/busybox:1.36.1-1
    command: ["/bin/sh","-c","i=0; while true; do i=\$((i+1)); echo \"\$(date -u +%H:%M:%S) beat=\$i\"; sleep $INTERVAL; done"]
YAML
  k -n "$NAMESPACE" wait --for=condition=Ready "pod/$POD" --timeout=120s >/dev/null
fi

trap 'summary; cleanup; exit 0' INT TERM
trap cleanup EXIT

echo "watching $NAMESPACE/$POD (threshold ${THRESHOLD}s). Ctrl-C to stop."
LAST=$(date +%s)
while true; do
  monitor < <(stream) || true
  echo "-- log stream ended, reconnecting --"
  sleep 1
done
