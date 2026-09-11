Source: `tests/live_docker_secret.py`.
Maintain this document alongside its source file. When the source or relevant imported contracts change, verify and update this companion in the same change.

[Source](../../../tests/live_docker_secret.py) is the ordinary real Docker secret-file controller called by [test.sh](../../../test.sh). It validates the engine, materializes disposable input, creates numeric reader/other-user recipients, and checks correct access, denied unrelated-UID access, read-only mounts and redaction. Its own tracked resources/helpers must be absent before the passed JSON is printed.

It creates its ordinary recipients directly using inspected image/network identities. This does not cover the runtime interpreter's combined StartNode request. The optional [sibling fixture](../../../tests/live_docker_start_node_contract.py) is called only for explicit mode1, after ordinary access assertions and before this controller's final cleanup. A sibling failure propagates as a fixed HOLD; it must not be swallowed into ordinary success.

Preserve numeric user versus group semantics, line-tailed logs and exact tracked cleanup. The current log read requests30 trailing lines; this is not a byte bound. The controller is privileged by its daemon socket even when recipient networking is private. Its green result establishes the stated local fixture laws, not public CPK admission/custody/history, production readiness or retry safety. The [creation evidence relation](../../architecture/docker-creation-evidence.md) explains the distinction.
