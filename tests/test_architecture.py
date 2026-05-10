# ---------- Architecture Test: tests/test_architecture.py ---------- #
# This test suite validates the core architecture of the Security Shield backend.
# It ensures that the Security Engine correctly discovers and integrates security checks,
# and that all checks adhere to the expected structure defined by the BaseCheck class.

import pytest
from security_shield.backend.engine import SecurityEngine
from security_shield.backend.base_check import BaseCheck

@pytest.fixture
def engine():
    """Provides a fresh SecurityEngine instance for each test."""
    return SecurityEngine()

def test_engine_discovery(engine):
    """Ensures that the engine finds at least one active security check."""
    assert len(engine.checks) > 0, \
        "Architecture Error: The Security Engine failed to discover any checks in the 'checks/' package."

def test_check_inheritance(engine):
    """Verifies that every discovered check inherits from BaseCheck."""
    for check in engine.checks:
        assert isinstance(check, BaseCheck), \
            f"Validation Error: Check '{check.name}' does not inherit from BaseCheck."

def test_check_properties(engine):
    """Ensures each check has the basic required attributes."""
    for check in engine.checks:
        assert hasattr(check, 'name')
        assert hasattr(check, 'description')
        assert hasattr(check, 'is_active')