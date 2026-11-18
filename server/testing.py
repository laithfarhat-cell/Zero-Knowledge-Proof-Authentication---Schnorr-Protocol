"""
server.testing
==============

Utilities for exercising the Verifier over a real HTTP socket in tests and in
the adversarial lab. Spins up a throwaway uvicorn instance bound to an
ephemeral localhost port; nothing here is used by the production service.
"""

from __future__ import annotations

import socket
import threading
import time
from contextlib import contextmanager
from typing import Iterator


def _free_port(host: str) -> int:
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.bind((host, 0))
    port = sock.getsockname()[1]
    sock.close()
    return port


@contextmanager
def live_server(app, host: str = "127.0.0.1", startup_timeout: float = 15.0) -> Iterator[str]:
    """Run ``app`` on an ephemeral port; yields the base URL. Always tears down."""
    import uvicorn

    port = _free_port(host)
    config = uvicorn.Config(app, host=host, port=port, log_level="warning", access_log=False)
    server = uvicorn.Server(config)
    thread = threading.Thread(target=server.run, name="schnorr-test-server", daemon=True)
    thread.start()
    deadline = time.time() + startup_timeout
    while time.time() < deadline:
        if getattr(server, "started", False):
            break
        if not thread.is_alive():
            raise RuntimeError("uvicorn exited before becoming ready")
        time.sleep(0.01)
    else:
        server.should_exit = True
        raise RuntimeError("uvicorn did not become ready in time")
    try:
        yield f"http://{host}:{port}"
    finally:
        server.should_exit = True
        thread.join(timeout=5.0)
