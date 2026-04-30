"""
Test importing the sekoia_indicators module to ensure it is free of syntax errors and can be loaded properly.
"""
import importlib.util
import os
import py_compile
import sys


SEKOIA_INDICATORS_SCRIPT_DIR_PATH = os.path.abspath(
    os.path.join(os.path.dirname(__file__), os.pardir, "sekoia.io", "bin")
)
sys.path.insert(0, SEKOIA_INDICATORS_SCRIPT_DIR_PATH)

def test_sekoia_indicators_importable():
    """
    Ensure that the sekoia_indicators module can be imported without errors.
    This will catch SyntaxError, NameError, ModuleNotFoundError, etc.
    """
    # Attempt a normal import
    import sekoia_indicators  # noqa: F401
    # If the import fails, pytest will automatically register a failure.

def test_sekoia_indicators_syntax_compiles():
    """
    Compile the source file to ensure there are no syntax errors.
    This acts as a second layer of defense against broken code.
    """
    source_path = os.path.join(SEKOIA_INDICATORS_SCRIPT_DIR_PATH, "sekoia_indicators.py")
    # py_compile.compile raises an exception if there's a syntax error
    py_compile.compile(source_path, doraise=True)

def test_sekoia_indicators_module_spec_loads():
    """
    Dynamically load the module via importlib to ensure
    the loader machinery works (e.g. no broken package layout).
    """
    module_name = "sekoia_indicators"
    file_path = os.path.join(SEKOIA_INDICATORS_SCRIPT_DIR_PATH, module_name + ".py")
    spec = importlib.util.spec_from_file_location(module_name, file_path)
    module = importlib.util.module_from_spec(spec)
    # Execute the module in its own namespace
    spec.loader.exec_module(module)
    # A simple assertion to confirm we got a module object
    assert hasattr(module, "SEKOIAIndicators")
