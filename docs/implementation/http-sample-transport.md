# One supplied signed HTTP sample (#148)

Source: `probes/http_sample_transport.py`; tests: `tests/test_http_sample_transport.py`.

The shared #181/#148 contract is one POST `/cpk/verification/http`, a transit
bearer header and a closed canonical JSON profile/target_id/request/workload
credential body. Both supplied Core grants/compact structures must bind the same
original request and exact role/audience, independent selected route/receiver and
full gateway target. Gateway and SDK own signature admission; this transport
does not resolve material, sign, grant current permission or prove provenance.

The client uses existing public-address authorization with selected Host/SNI,
HTTPS verification, no redirect/proxy environment and no private fallback. The
old health-V2 destination/protocol is not relabeled. Supplied route selection is
not a production transit declaration or a Docker adapter registration. Native
branch selection and the actual reached-check producer remain downstream.

Encoded tokens are bounded at16384 bytes with1024/15104/128 segment bounds;
outer body/aggregate headers at32768 bytes and64 headers. The sender emits only
the fixed request shape. A single absolute deadline, at most5s/original check
timeout, is clipped to both original credential expirations and covers DNS,
send/read and closure. No renewal/retry occurs. Cancellation propagates.

Only a bounded identity JSON200 of at most2048 raw bytes decoded by Core's
HttpVerificationSampleResultCodec(actual request, original HttpCheck) yields a
result. Mismatched200, non200, malformed/oversized replies and transport deadlines
yield fixed result-free classifications. Peer bodies/headers/errors/tokens are
never returned as diagnostics; a transport deadline is not application timeout.

The owning local suite remains unchanged. Its captured HTTP proof is separate
from Servers' one actual gateway→SDK→sender source composition. The latter must
record exact source/import provenance, Core/SDK coordinates and injected outer
transport, and cannot establish live TLS, native selection or producer admission.
