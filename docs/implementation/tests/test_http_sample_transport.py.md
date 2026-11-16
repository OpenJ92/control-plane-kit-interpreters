Source: [test_http_sample_transport.py](../../../tests/test_http_sample_transport.py).

The supplied-input proof uses real Core request/grant/check values and Ed25519
fixture credentials, plus captured HTTP transport. One fixed gateway POST yields
a result decoded against the original request and HttpCheck. A mismatched200,
unsupported route/redirect, incompatible selector/role/check and credential-clipped
deadline earn no fabricated evidence or private fallback. This does not prove
Operations admission, a running gateway/SDK exchange, signing-key resolution or
native Docker branch selection. The combined real-SDK proof belongs to #181.
