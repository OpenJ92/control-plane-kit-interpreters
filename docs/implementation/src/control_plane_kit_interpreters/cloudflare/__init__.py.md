Source: [src/control_plane_kit_interpreters/cloudflare/__init__.py](../../../../../src/control_plane_kit_interpreters/cloudflare/__init__.py).
Maintain this document alongside its source file. When the source or relevant imported contracts change, verify and update this companion in the same change.

This facade exposes the named-ingress interpreter, exact resource/reservation observations and closed provider failure evidence from client.py. It does not allocate a tunnel, resolve a token or create an HTTP client on import. Keep the public failure vocabulary and interpreter exports coordinated with their owner; the optional HTTP implementation is loaded by the transport when it makes a request.

Related source and evidence: [src/control_plane_kit_interpreters/cloudflare/client.py](../../../../../src/control_plane_kit_interpreters/cloudflare/client.py), [tests/test_cloudflare_named_ingress.py](../../../../../tests/test_cloudflare_named_ingress.py).
