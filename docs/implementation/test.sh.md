Source: [test.sh](../../test.sh).
Maintain this companion in the same change when the source or its selected imports change the contract.

The ordinary Docker gate runs support and package-integrity checks, builds the test target,
runs the package suite, checks that the installed package root imports without eager backend
dependencies, and runs the [numeric-reader controller](../../tests/live_docker_secret.py).
The controller receives the local daemon socket and exercises configuration and installation
alongside numeric-user secret delivery. The package-test container runs without that socket.
The [Dockerfile](../../Dockerfile) and [package metadata](../../pyproject.toml) own image
targets and pinned package inputs.

Pinned dependencies are the default. Local-Core mode replaces Core for the package-test
invocation using the explicitly selected checkout. PostgreSQL readiness source tests require
that mode and a separate opt-in. Independently, the [StartNode provider witness](tests/live_docker_start_node_contract.py.md)
requires its own opt-in, run identity and fresh records directory. An ordinary PASS leaves
that historical provider path unexercised.

`GATE_COMPLETED` is set after the controller returns successfully. On exit, `finish_gate`
preserves the command status, runs cleanup for the recorded fixture resources, and requires
normal completion before it emits `owning-gate=PASS`. Package-test success alone leaves the
controller and cleanup unverified. The [original early-exit finding](https://github.com/OpenJ92/control-plane-kit-interpreters/issues/141#issuecomment-5628981451)
records why the final marker and exit status are read together.
