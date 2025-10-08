import importlib
import os
import sys


PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)


def test_parser_module_imports() -> None:
    module = importlib.import_module("tools.parser")
    assert module is not None


