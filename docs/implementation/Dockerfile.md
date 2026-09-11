Source: [Dockerfile](../../Dockerfile).
Maintain this document alongside its source file. When the source or relevant imported contracts change, verify and update this companion in the same change.

The package stage installs this source with its selected test extra; the test stage adds tests, while the separate secret-reader stage sets numeric UID10006 and GID10008. The reader stage is a permission witness image, not the product Secrets server or the default test controller. Do not move the USER instruction into a shared stage without checking those different roles.

The default Python build argument is3.14; this is independent of the declared minimum supported Python version. Package metadata owns dependency selection. Changing a base image, stage or dependency resolution may change the actual SDK observed by a fixture even when its source is unchanged. Building this Dockerfile is an effect performed by the owning gate; these notes do not request a build.

Source and governing references: [pyproject.toml](../../pyproject.toml), [test.sh](../../test.sh), [tests/live_docker_secret.py](../../tests/live_docker_secret.py).
