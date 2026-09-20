# syntax=docker/dockerfile:1

ARG PYTHON_VERSION=3.14

FROM python:${PYTHON_VERSION}-slim AS package

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1

WORKDIR /app

COPY pyproject.toml README.md LICENSE ./
COPY src ./src

RUN python -m pip install --upgrade pip \
    && python -m pip install ".[test]"

CMD ["python", "-c", "import control_plane_kit_interpreters; print('control-plane-kit-interpreters ready')"]

FROM package AS secret-reader-test

USER 10006:10008

FROM package AS test

# Real gateway verification and health relay use this immutable owner package.
# Do not resolve Servers' old Interpreter pin over the candidate under test.
# Its imported Core/crypto/FastAPI/uvicorn dependencies come from .[test].
RUN python -m pip install --no-deps \
    "control-plane-kit-servers @ https://github.com/OpenJ92/control-plane-kit-servers/archive/127b7cbf9ae33ae05edbb01e9b610b518e824b90.zip"

COPY tests ./tests

CMD ["python", "-m", "unittest", "discover", "-s", "tests", "-v"]
