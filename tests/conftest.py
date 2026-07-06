import os

import pytest


@pytest.fixture(autouse=True)
def clean_sandbox():
    """Ensure each test starts and ends with a clean advsim sandbox."""
    from advsim.runner import Runner

    runner = Runner.__new__(Runner)
    runner.cleanup_all()
    yield
    runner.cleanup_all()


@pytest.fixture
def authorized_env(monkeypatch):
    monkeypatch.setenv("ADVSIM_AUTHORIZED", "1")
    yield
