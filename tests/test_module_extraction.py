#!/usr/bin/env python3
"""
Tests for module-level line extraction functionality.

This module tests the feature that extracts only module-level source code lines
(imports, global variables, top-level statements) while excluding function and
class definitions from the module object's source code at the AST compiler level.

The tests use real AST compilation to ensure the compiler properly extracts
module-level code into the module CodeObject.
"""

import pytest
from pathlib import Path
from src.common.malwi_report import MalwiReport


class TestModuleLevelExtraction:
    """Test cases for extracting module-level lines from source code at compiler level."""

    def test_module_extraction_with_functions(self, tmp_path):
        """Test extraction when file contains functions that should be excluded."""
        # Create test file with mixed module-level and function code
        test_content = """import os
import sys

GLOBAL_VAR = "module level"

def function_one():
    return "function code"

def function_two():
    print("more function code")
    return 42

# Module level comment
print("Module level execution")
x = function_one()
"""
        test_file = tmp_path / "test_functions.py"
        test_file.write_text(test_content)

        # Use real AST compiler via MalwiReport.create
        report = MalwiReport.create(
            input_path=test_file,
            accepted_extensions=["py"],
            predict=False,  # Skip ML prediction for test
            silent=True,
            malicious_threshold=0.7,
        )

        # Find the module object
        module_obj = None
        for obj in report.all_objects:
            if obj.name == "<module>":
                module_obj = obj
                break

        assert module_obj is not None, "Module object not found"

        # Test that the module CodeObject has only module-level source code
        if hasattr(module_obj, "ast_code_object") and module_obj.ast_code_object:
            module_source = module_obj.ast_code_object.source_code

            # The module source should exclude function definitions
            assert "import os" in module_source
            assert "import sys" in module_source
            assert 'GLOBAL_VAR = "module level"' in module_source
            assert "# Module level comment" in module_source
            assert 'print("Module level execution")' in module_source
            assert "x = function_one()" in module_source

            # Should NOT contain function definitions
            assert "def function_one():" not in module_source
            assert "def function_two():" not in module_source
            assert 'return "function code"' not in module_source
        else:
            pytest.fail("Module object missing ast_code_object")

    def test_module_extraction_with_classes(self, tmp_path):
        """Test extraction when file contains classes."""
        test_content = """import json
from pathlib import Path

class MyClass:
    def __init__(self):
        self.value = 42
    
    def method(self):
        return self.value

# Module level
obj = MyClass()
result = obj.method()
"""
        test_file = tmp_path / "test_classes.py"
        test_file.write_text(test_content)

        # Use real AST compiler
        report = MalwiReport.create(
            input_path=test_file,
            accepted_extensions=["py"],
            predict=False,
            silent=True,
            malicious_threshold=0.7,
        )

        # Find the module object
        module_obj = None
        for obj in report.all_objects:
            if obj.name == "<module>":
                module_obj = obj
                break

        assert module_obj is not None

        # Test module-level source extraction
        if hasattr(module_obj, "ast_code_object") and module_obj.ast_code_object:
            module_source = module_obj.ast_code_object.source_code

            # Should contain module-level code
            assert "import json" in module_source
            assert "from pathlib import Path" in module_source
            assert "# Module level" in module_source
            assert "obj = MyClass()" in module_source
            assert "result = obj.method()" in module_source

            # Should NOT contain class definition
            assert "class MyClass:" not in module_source
            assert "def __init__(self):" not in module_source
            assert "def method(self):" not in module_source
        else:
            pytest.fail("Module object missing ast_code_object")

    def test_module_extraction_only_imports(self, tmp_path):
        """Test extraction when file contains only imports and function definitions."""
        test_content = """import os
import sys
from pathlib import Path

def only_function():
    return "nothing else here"

def another_function():
    pass
"""
        test_file = tmp_path / "test_imports_only.py"
        test_file.write_text(test_content)

        report = MalwiReport.create(
            input_path=test_file,
            accepted_extensions=["py"],
            predict=False,
            silent=True,
            malicious_threshold=0.7,
        )

        # Find the module object
        module_obj = None
        for obj in report.all_objects:
            if obj.name == "<module>":
                module_obj = obj
                break

        assert module_obj is not None

        if hasattr(module_obj, "ast_code_object") and module_obj.ast_code_object:
            module_source = module_obj.ast_code_object.source_code

            # Should contain only imports
            assert "import os" in module_source
            assert "import sys" in module_source
            assert "from pathlib import Path" in module_source

            # Should NOT contain function definitions
            assert "def only_function():" not in module_source
            assert "def another_function():" not in module_source
        else:
            pytest.fail("Module object missing ast_code_object")

    def test_module_extraction_no_functions(self, tmp_path):
        """Test extraction when file contains no function/class definitions."""
        test_content = """import requests
import json

API_URL = "https://api.example.com"
config = {"timeout": 30}

response = requests.get(API_URL)
data = response.json()
print(f"Got {len(data)} items")
"""
        test_file = tmp_path / "test_no_functions.py"
        test_file.write_text(test_content)

        report = MalwiReport.create(
            input_path=test_file,
            accepted_extensions=["py"],
            predict=False,
            silent=True,
            malicious_threshold=0.7,
        )

        # Find the module object
        module_obj = None
        for obj in report.all_objects:
            if obj.name == "<module>":
                module_obj = obj
                break

        assert module_obj is not None

        if hasattr(module_obj, "ast_code_object") and module_obj.ast_code_object:
            module_source = module_obj.ast_code_object.source_code

            # Should include all content since there are no functions to exclude
            assert "import requests" in module_source
            assert "import json" in module_source
            assert 'API_URL = "https://api.example.com"' in module_source
            assert 'config = {"timeout": 30}' in module_source
            assert "response = requests.get(API_URL)" in module_source
            assert "data = response.json()" in module_source
            assert 'print(f"Got {len(data)} items")' in module_source
        else:
            pytest.fail("Module object missing ast_code_object")

    def test_compiler_integration_end_to_end(self, tmp_path):
        """End-to-end test that module extraction works correctly throughout the system."""
        test_content = """import subprocess
import os

def malicious_func():
    os.system("rm -rf /")
    return "evil"

# Module execution
result = malicious_func()
print("Module level print")
"""
        test_file = tmp_path / "test_integration.py"
        test_file.write_text(test_content)

        # Create report using real compilation
        report = MalwiReport.create(
            input_path=test_file,
            accepted_extensions=["py"],
            predict=False,
            silent=True,
            malicious_threshold=0.7,
        )

        # Should have module and function objects
        module_obj = None
        func_obj = None
        for obj in report.all_objects:
            if obj.name == "<module>":
                module_obj = obj
            elif obj.name == "malicious_func":
                func_obj = obj

        assert module_obj is not None, "Module object not found"
        assert func_obj is not None, "Function object not found"

        # Test module object has only module-level source
        module_source = module_obj.ast_code_object.source_code
        assert "import subprocess" in module_source
        assert "import os" in module_source
        assert "result = malicious_func()" in module_source
        assert 'print("Module level print")' in module_source
        # Should NOT contain function definition
        assert "def malicious_func():" not in module_source
        assert 'os.system("rm -rf /")' not in module_source

        # Test function object has only function source
        func_source = func_obj.ast_code_object.source_code
        assert "def malicious_func():" in func_source
        assert 'os.system("rm -rf /")' in func_source
        assert 'return "evil"' in func_source
        # Should NOT contain imports or module calls
        assert "import subprocess" not in func_source
        assert "result = malicious_func()" not in func_source
