"""Call an already configured semantic admission port; no policy or durable state."""
from __future__ import annotations

import asyncio


class InvocationPortError(RuntimeError):
    """The trusted composition did not supply its required bounded port."""


def control_errors(port, *, required=False):
    if port is None:
        if required:
            raise InvocationPortError("semantic invocation port is required")
        return ()
    base = getattr(port, "control_error", None)
    if (not isinstance(base, type) or not issubclass(base, Exception) or base is Exception
            or not callable(getattr(port, "admit", None))
            or not callable(getattr(port, "record_outcome", None))):
        raise InvocationPortError("semantic invocation port is invalid")
    return (base,)


def _finish(port, permit, error):
    # Called outside the capability's exception handler: a failed acknowledgement
    # must not acquire a private provider exception as its implicit context.
    if isinstance(error, asyncio.CancelledError):
        try:
            port.record_outcome(permit, "unknown")
        except Exception:
            # No durable acknowledgement is claimed. Cancellation still stops
            # the sequence after the capability's own cleanup has completed.
            pass
        raise error
    port.record_outcome(permit, "returned" if error is None else "unknown")
    if error is not None:
        raise error


def invoke(port, kind, call, *, authorization_id=None):
    controls = control_errors(port)
    if port is None:
        return call()
    permit = port.admit(kind, authorization_id=authorization_id)
    result, error = None, None
    try:
        result = call()
    except controls:
        raise
    except BaseException as caught:
        error = caught
    _finish(port, permit, error)
    return result


async def invoke_async(port, kind, call, *, authorization_id=None):
    controls = control_errors(port)
    if port is None:
        return await call()
    permit = port.admit(kind, authorization_id=authorization_id)
    result, error = None, None
    try:
        result = await call()
    except controls:
        raise
    except BaseException as caught:
        error = caught
    _finish(port, permit, error)
    return result
