"""pytest configuration: path bootstrap, DB isolation, live-API fixtures."""

from __future__ import annotations

import os
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

# server.api creates a module-level app on import — isolate its side effects.
os.environ.setdefault("SCHNORR_DB_PATH", str(Path(tempfile.mkdtemp(prefix="schnorr-import-")) / "import_side_effect.db"))
os.environ.setdefault("SCHNORR_LOG_LEVEL", "WARNING")

import pytest
import httpx

from core.math_params import get_rfc3526_2048
from server.api import create_app
from server.testing import live_server


@pytest.fixture(scope="session")
def group():
    return get_rfc3526_2048()


@pytest.fixture()
def db_path(tmp_path):
    return str(tmp_path / "test.db")


@pytest.fixture()
def api(db_path):
    """A live Verifier (real HTTP over an ephemeral localhost port)."""
    app = create_app(db_path=db_path, group_spec="rfc3526-2048")
    with live_server(app) as base_url:
        with httpx.Client(base_url=base_url, timeout=30.0) as client:
            yield client, app, db_path
