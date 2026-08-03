#!/usr/bin/env bash
set -euo pipefail

IMAGE_NAME="${CPK_INTERPRETERS_TEST_IMAGE_NAME:-control-plane-kit-interpreters-test:local}"
CONTAINER_NAME="${CPK_INTERPRETERS_TEST_CONTAINER:-cpk-interpreters-test-runner}"
POLICY_IMAGE="${CPK_INTERPRETERS_POLICY_IMAGE:-python:3.14-slim}"
DEPENDENCY_MODE="${CPK_INTERPRETERS_DEPENDENCY_MODE:-pinned}"
CORE_REPO="${CPK_CORE_REPO:-}"
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

cd "$ROOT"

cleanup() {
  docker rm -f "$CONTAINER_NAME" >/dev/null 2>&1 || true
}

trap cleanup EXIT

cleanup

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
    -v "$(cd "$CORE_REPO" && pwd):/workspace/control-plane-kit:ro" \
    "$IMAGE_NAME" \
    sh -c 'cp -R /workspace/control-plane-kit/control-plane-kit-core /tmp/control-plane-kit-core && python -m pip install /tmp/control-plane-kit-core && python -m compileall src tests && python -m unittest discover -s tests -v'
else
  docker run \
    --name "$CONTAINER_NAME" \
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
