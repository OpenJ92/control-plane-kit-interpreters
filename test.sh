#!/usr/bin/env bash
set -euo pipefail

IMAGE_NAME="${CPK_INTERPRETERS_TEST_IMAGE_NAME:-control-plane-kit-interpreters-test:local}"
CONTAINER_NAME="${CPK_INTERPRETERS_TEST_CONTAINER:-cpk-interpreters-test-runner}"
CORE_REPO="${CPK_CORE_REPO:-../control-plane-kit}"

cleanup() {
  docker rm -f "$CONTAINER_NAME" >/dev/null 2>&1 || true
}

trap cleanup EXIT

cleanup

docker build --target test -t "$IMAGE_NAME" .
if [[ -d "$CORE_REPO/control-plane-kit-core" ]]; then
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
