import os
import sys

import pytest


# Compute once the path to sekoia_indicators.py
SCRIPT_DIR = os.path.abspath(
    os.path.join(os.path.dirname(__file__), os.pardir, "sekoia.io", "bin")
)

# Prepend it to sys.path so that import sekoia_indicators works everywhere
if SCRIPT_DIR not in sys.path:
    sys.path.insert(0, SCRIPT_DIR)


@pytest.fixture(scope="session")
def script_path():
    """Return the full path to sekoia_indicators.py"""
    return os.path.join(SCRIPT_DIR, "sekoia_indicators.py")

@pytest.fixture(scope="session")
def sekoia_module():
    """Dynamically import and return the sekoia_indicators module."""
    import importlib
    return importlib.import_module("sekoia_indicators")
