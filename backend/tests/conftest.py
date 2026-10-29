"""Pytest loads this file before any test module."""

import os
import tempfile
from pathlib import Path

_root = Path(tempfile.mkdtemp(prefix="webset-test-"))
os.environ["WEBSET_DB_PATH"] = str(_root / "webset.db")
os.environ["WEBSET_EXTERNAL_SAST"] = "0"

import pytest
from fastapi.testclient import TestClient

from app.config import DB_PATH
from app.main import app

assert DB_PATH == Path(os.environ["WEBSET_DB_PATH"]), (
    "Tests are pointed at the demo database. "
    "config.py must read WEBSET_DB_PATH before the engine is created."
)


@pytest.fixture(scope="session")
def client():
    with TestClient(app) as test_client:
        yield test_client
