#!/usr/bin/env bash
# Copyright AGNTCY Contributors (https://github.com/agntcy)
# SPDX-License-Identifier: Apache-2.0

# Runs a command against a throwaway `dirctl daemon` (runtime discovery on,
# Docker adapter) and a labelled container it discovers.
#
# Usage: run.sh <dirctl-binary> <command> [args...]
#
# The command gets DIRECTORY_RUNTIME_ADDRESS (the daemon's address) and
# RUNTIME_E2E_WORKLOAD_NAME (the name of the container to expect).

set -euo pipefail

if [ "$#" -lt 2 ]; then
  echo "usage: $0 <dirctl-binary> <command> [args...]" >&2
  exit 2
fi

DIRCTL="$1"
shift

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
DATA_DIR="$(mktemp -d)"
WORKLOAD_NAME="sdk-runtime-e2e-$$"
DAEMON_LOG="${DATA_DIR}/daemon.log"

cleanup() {
  docker rm -f "${WORKLOAD_NAME}" >/dev/null 2>&1 || true
  "${DIRCTL}" daemon stop --data-dir "${DATA_DIR}" >/dev/null 2>&1 || true
  rm -rf "${DATA_DIR}"
}
trap cleanup EXIT

cp "${HERE}/daemon.config.yaml" "${DATA_DIR}/daemon.config.yaml"
"${DIRCTL}" daemon start --data-dir "${DATA_DIR}" --config "${DATA_DIR}/daemon.config.yaml" >"${DAEMON_LOG}" 2>&1 &

ready() {
  "${DIRCTL}" daemon status --data-dir "${DATA_DIR}" 2>&1 | grep -q "Daemon is running" &&
    (exec 3<>/dev/tcp/127.0.0.1/18888) 2>/dev/null
}

for _ in $(seq 1 60); do
  ready && break
  sleep 1
done
if ! ready; then
  echo "daemon did not start:" >&2
  cat "${DAEMON_LOG}" >&2
  exit 1
fi

docker run -d --name "${WORKLOAD_NAME}" \
  --label sdk.agntcy/discover=true \
  --label sdk.agntcy/agent-type=a2a \
  -p 80 nginx:alpine >/dev/null

export DIRECTORY_RUNTIME_ADDRESS="localhost:18888"
export RUNTIME_E2E_WORKLOAD_NAME="${WORKLOAD_NAME}"
"$@"
