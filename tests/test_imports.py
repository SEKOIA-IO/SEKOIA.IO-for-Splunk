"""
Test importing the sekoia_indicators module to ensure it is free of syntax errors and can be loaded properly.
"""
import importlib.util
import py_compile


def test_sekoia_indicators_importable(sekoia_module):
    """
    Ensure that the sekoia_indicators module can be imported without errors.
    This will catch SyntaxError, NameError, ModuleNotFoundError, etc.
    """
    # If this fixture was created, imports succeeded
    assert hasattr(sekoia_module, "SEKOIAIndicators")

def test_sekoia_indicators_syntax_compiles(script_path):
    """
    Compile the source file to ensure there are no syntax errors.
    This acts as a second layer of defense against broken code.
    """
    source_path = script_path
    # py_compile.compile raises an exception if there's a syntax error
    py_compile.compile(script_path, doraise=True)

def test_sekoia_indicators_module_spec_loads(script_path):
    """
    Dynamically load the module via importlib to ensure
    the loader machinery works (e.g. no broken package layout).
    """
    module_name = "sekoia_indicators"
    spec = importlib.util.spec_from_file_location(module_name, script_path)
    module = importlib.util.module_from_spec(spec)
    # Execute the module in its own namespace
    spec.loader.exec_module(module)
    # A simple assertion to confirm we got a module object
    assert hasattr(module, "SEKOIAIndicators")
