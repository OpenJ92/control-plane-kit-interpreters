#!/usr/bin/env bash
set -euo pipefail

IMAGE_NAME="${CPK_INTERPRETERS_TEST_IMAGE_NAME:-control-plane-kit-interpreters-test:local}"
CONTAINER_NAME="${CPK_INTERPRETERS_TEST_CONTAINER:-cpk-interpreters-test-runner}"

cleanup() {
  docker rm -f "$CONTAINER_NAME" >/dev/null 2>&1 || true
}

trap cleanup EXIT

cleanup

docker build --target test -t "$IMAGE_NAME" .
docker run \
  --name "$CONTAINER_NAME" \
  "$IMAGE_NAME" \
  sh -c 'python -m compileall src tests && python -m unittest discover -s tests -v'
