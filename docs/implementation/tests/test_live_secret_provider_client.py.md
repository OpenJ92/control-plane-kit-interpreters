# Real provider process client witness

Under #244, the existing process fixture selects explicit empty intents for
metadata/revoke and the exact used tunnel-token intent for write. Generation
and resolution grants, the real server:app entrypoint and all original
write/resolve/revoke/audit assertions remain intact. The adopted provider's
one-time seed rejects wildcard or nonempty intentless grants.

The earlier readiness timeout did not retain its child exception. No retry
reconstructs that exception. A later startup failure reports only a bounded
pre-cleanup exit code and fixed recognized exception class after the existing owned process
cleanup. It never emits stderr. One local regression covers redaction and
unrecognized output. The unchanged normal pinned test.sh owns acceptance.
