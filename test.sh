#!/usr/bin/env bash
set -euo pipefail

IMAGE_NAME="${CPK_INTERPRETERS_TEST_IMAGE_NAME:-control-plane-kit-interpreters-test:local}"
POLICY_IMAGE="${CPK_INTERPRETERS_POLICY_IMAGE:-python:3.14-slim}"
DEPENDENCY_MODE="${CPK_INTERPRETERS_DEPENDENCY_MODE:-pinned}"
CORE_REPO="${CPK_CORE_REPO:-}"
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# A separately admitted one-attempt provider phase; ordinary gates leave it off.
CONTRACT_MODE="${CPK_INTERPRETERS_START_NODE_CONTRACT:-0}"
CONTRACT_RUN="${CPK_INTERPRETERS_START_NODE_CONTRACT_RUN:-}"
CONTRACT_RECORDS="${CPK_INTERPRETERS_START_NODE_CONTRACT_RECORDS:-}"
CONTRACT_ARGS=()
case "$CONTRACT_MODE" in
  0)
    [[ -z "$CONTRACT_RUN" && -z "$CONTRACT_RECORDS" ]] || { echo 'provider-contract inputs require explicit opt-in' >&2; exit 2; }
    echo 'start-node-provider-contract=not-requested'
    ;;
  1)
    [[ "$CONTRACT_RUN" =~ ^cpk141-[a-z0-9-]{4,48}$ ]] || { echo 'provider-contract run identity invalid' >&2; exit 2; }
    [[ "$CONTRACT_RECORDS" =~ ^/tmp/cpk141-[a-zA-Z0-9_-]+$ && ! -e "$CONTRACT_RECORDS" && ! -L "$CONTRACT_RECORDS" ]] || { echo 'provider-contract requires a fresh exact records directory' >&2; exit 2; }
    mkdir -m 700 "$CONTRACT_RECORDS"
    CONTRACT_ARGS=(--mount "type=bind,source=$CONTRACT_RECORDS,target=/cpk141-records"
      -e CPK_INTERPRETERS_START_NODE_CONTRACT=1
      -e "CPK_INTERPRETERS_START_NODE_CONTRACT_RUN=$CONTRACT_RUN"
      -e CPK_INTERPRETERS_START_NODE_CONTRACT_RECORDS=/cpk141-records)
    ;;
  *) echo 'unsupported provider-contract mode' >&2; exit 2 ;;
esac
FIXTURE_RECORDS="$(mktemp -d)"
FIXTURE_RUN="cpk-secret-$(basename "$FIXTURE_RECORDS")"
FIXTURE_TAG="control-plane-kit-secret-reader:${FIXTURE_RUN}"
CONTAINER_NAME="${CPK_INTERPRETERS_TEST_CONTAINER:-${FIXTURE_RUN}-package}"

cd "$ROOT"

remove_recorded_container() {
  local identity observed owner
  identity="$(cat "$1")" || return 1
  observed="$(docker container ls -aq --no-trunc --filter "id=$identity")" || return 1
  [[ -z "$observed" ]] && return 0
  [[ "$observed" == "$identity" ]] || return 1
  owner="$(docker inspect --format '{{index .Config.Labels "org.openj92.cpk.test-run"}}' "$identity")" || return 1
  [[ "$owner" == "$FIXTURE_RUN" ]] || return 1
  docker rm -f "$identity" >/dev/null || return 1
  observed="$(docker container ls -aq --no-trunc --filter "id=$identity")" || return 1
  [[ -z "$observed" ]]
}

cleanup() {
  local failed=0
  if [[ -s "$FIXTURE_RECORDS/controller" ]]; then
    remove_recorded_container "$FIXTURE_RECORDS/controller" || failed=1
  fi
  if [[ -s "$FIXTURE_RECORDS/image" ]]; then
    local image_id
    image_id="$(cat "$FIXTURE_RECORDS/image")"
    if [[ "$(docker image inspect --format '{{.Id}}' "$FIXTURE_TAG")" == "$image_id" &&
          "$(docker image inspect --format '{{index .Config.Labels "org.openj92.cpk.test-run"}}' "$image_id")" == "$FIXTURE_RUN" ]]; then
      docker image rm "$FIXTURE_TAG" >/dev/null || failed=1
      local remaining
      remaining="$(docker image ls -q --no-trunc --filter "reference=$FIXTURE_TAG")" || failed=1
      [[ -z "$remaining" ]] || failed=1
    else
      failed=1
    fi
  fi
  if [[ -s "$FIXTURE_RECORDS/package" ]]; then
    remove_recorded_container "$FIXTURE_RECORDS/package" || failed=1
  fi
  if [[ "$failed" != 0 ]]; then
    echo "local secret fixture cleanup incomplete; records=$FIXTURE_RECORDS" >&2
    return 1
  fi
  rm -f "$FIXTURE_RECORDS/controller" "$FIXTURE_RECORDS/package" "$FIXTURE_RECORDS/image"
  rmdir "$FIXTURE_RECORDS"
}

trap cleanup EXIT

docker run --rm \
  -v "$ROOT:/source:ro" \
  -v "$ROOT/test_support:/test-support:ro" \
  -e CPK_PACKAGE_ROOT=/source \
  -e PYTHONDONTWRITEBYTECODE=1 \
  "$POLICY_IMAGE" \
  sh -c 'cd /test-support && python -m unittest discover -s tests -v'

docker run --rm \
  -v "$ROOT:/source:ro" \
  -v "$ROOT/test_support:/test-support:ro" \
  -e PYTHONDONTWRITEBYTECODE=1 \
  "$POLICY_IMAGE" \
  python /test-support/package_integrity.py \
    --package-root /source \
    --source-root src \
    --test-root tests \
    --gate-file test.sh

case "$DEPENDENCY_MODE" in
  pinned)
    if [[ -n "$CORE_REPO" ]]; then
      echo "CPK_CORE_REPO requires CPK_INTERPRETERS_DEPENDENCY_MODE=local-core" >&2
      exit 2
    fi
    echo "dependency-mode=pinned"
    grep 'https://github.com/OpenJ92/.*/archive/' pyproject.toml
    ;;
  local-core)
    if [[ -z "$CORE_REPO" || ! -d "$CORE_REPO/control-plane-kit-core" ]]; then
      echo "local-core mode requires CPK_CORE_REPO containing control-plane-kit-core" >&2
      exit 2
    fi
    echo "dependency-mode=local-core core-repo=$(cd "$CORE_REPO" && pwd)"
    ;;
  *)
    echo "unsupported CPK_INTERPRETERS_DEPENDENCY_MODE: $DEPENDENCY_MODE" >&2
    exit 2
    ;;
esac

docker build --target test -t "$IMAGE_NAME" .

if [[ "$DEPENDENCY_MODE" == "local-core" ]]; then
  docker run \
    --name "$CONTAINER_NAME" \
    --cidfile "$FIXTURE_RECORDS/package" --label "org.openj92.cpk.test-run=$FIXTURE_RUN" \
    -v "$(cd "$CORE_REPO" && pwd):/workspace/control-plane-kit:ro" \
    "$IMAGE_NAME" \
    sh -c 'cp -R /workspace/control-plane-kit/control-plane-kit-core /tmp/control-plane-kit-core && python -m pip install /tmp/control-plane-kit-core && python -m compileall src tests && python -m unittest discover -s tests -v'
else
  docker run \
    --name "$CONTAINER_NAME" \
    --cidfile "$FIXTURE_RECORDS/package" --label "org.openj92.cpk.test-run=$FIXTURE_RUN" \
    "$IMAGE_NAME" \
    sh -c 'python -m compileall src tests && python -m unittest discover -s tests -v'
fi

docker run --rm \
  "$IMAGE_NAME" \
  sh -c 'cd /tmp && python - <<'"'"'PY'"'"'
import sys
import control_plane_kit_interpreters

for forbidden in ("docker", "fastapi", "psycopg"):
    if forbidden in sys.modules:
        raise SystemExit(f"unexpected eager import: {forbidden}")

print("control-plane-kit-interpreters import ok")
PY'

# Local SDK witness: only this separate controller gets daemon authority.
# Docker Desktop exposes its engine socket inside the VM at /var/run/docker.sock;
# compare the engine ID in the controller to prevent an accidental engine switch.
if [[ -n "${DOCKER_TLS_VERIFY:-}" || -n "${DOCKER_CERT_PATH:-}" ]]; then
  echo 'local secret witness requires a local Unix Docker context' >&2
  exit 1
fi
DOCKER_ENDPOINT="${DOCKER_HOST:-$(docker context inspect --format '{{.Endpoints.docker.Host}}')}"
case "$DOCKER_ENDPOINT" in
  unix:///*) ;;
  *) echo 'local secret witness rejects remote or ambiguous Docker context' >&2; exit 1 ;;
esac
ENGINE_ID="$(docker info --format '{{.ID}}')"
[[ -n "$ENGINE_ID" ]]
FIXTURE_EXISTING="$(docker container ls -aq --no-trunc --filter "name=^/${FIXTURE_RUN}$")"
[[ -z "$FIXTURE_EXISTING" ]] || { echo 'fixture controller identity already exists' >&2; exit 1; }
FIXTURE_EXISTING="$(docker image ls -q --no-trunc --filter "reference=$FIXTURE_TAG")"
[[ -z "$FIXTURE_EXISTING" ]] || { echo 'fixture image tag already exists' >&2; exit 1; }
docker build --target secret-reader-test \
  --label "org.openj92.cpk.test-run=$FIXTURE_RUN" \
  --iidfile "$FIXTURE_RECORDS/image" -t "$FIXTURE_TAG" .
FIXTURE_IMAGE_ID="$(cat "$FIXTURE_RECORDS/image")"
HELPER_IMAGE_ID="$(docker image inspect --format '{{.Id}}' "$IMAGE_NAME")"
docker run --name "$FIXTURE_RUN" --cidfile "$FIXTURE_RECORDS/controller" \
  --label "org.openj92.cpk.test-run=$FIXTURE_RUN" \
  --mount type=bind,source=/var/run/docker.sock,target=/var/run/docker.sock \
  -e DOCKER_HOST=unix:///var/run/docker.sock \
  -e "CPK_SECRET_TEST_RUN=$FIXTURE_RUN" \
  -e "CPK_SECRET_READER_IMAGE=$FIXTURE_IMAGE_ID" \
  -e "CPK_SECRET_HELPER_IMAGE=$HELPER_IMAGE_ID" \
  -e "CPK_SECRET_ENGINE_ID=$ENGINE_ID" \
  "${CONTRACT_ARGS[@]}" \
  "$HELPER_IMAGE_ID" python tests/live_docker_secret.py
