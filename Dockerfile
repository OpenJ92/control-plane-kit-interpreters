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
    && python -m pip install .

CMD ["python", "-c", "import control_plane_kit_interpreters; print('control-plane-kit-interpreters ready')"]

FROM package AS test

COPY tests ./tests

CMD ["python", "-m", "unittest", "discover", "-s", "tests", "-v"]
