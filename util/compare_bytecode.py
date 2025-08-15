#!/usr/bin/env python3
"""
Compare bytecode generation between Python's dis module and malwi's ast_to_malwicode.py

This utility helps identify missing or wrongly translated OpCodes by comparing:
1. Python's official bytecode (via dis module)
2. malwi's custom bytecode generation

Usage:
    python util/compare_bytecode.py [test_file.py]

If no file is provided, it will create and test a sample file with common Python constructs.
"""

import dis
import sys
import tempfile
import os
from pathlib import Path

# Add src to path to import malwi modules
sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

from common.ast_to_malwicode import ASTCompiler


def create_test_file():
    """Create a comprehensive test file with various Python constructs"""
    test_code = """
# Basic operations
x = 5
y = x + 3

# Function definition and call
def greet(name):
    return f"Hello {name}!"

result = greet("World")

# List operations
numbers = [1, 2, 3, 4, 5]
squares = [x**2 for x in numbers]

# Tuple unpacking
a, b = (10, 20)

# Dictionary operations
data = {"key": "value", "count": 42}
value = data["key"]

# Control flow
if x > 0:
    print("Positive")
else:
    print("Non-positive")

# Loop
for item in numbers:
    print(item)

# Exception handling
try:
    result = 10 / 0
except ZeroDivisionError:
    print("Division by zero")

# Generator
def counter():
    yield 1
    yield 2
    yield 3

# Delete operations
temp_var = 100
del temp_var

temp_list = [1, 2, 3]
del temp_list[0]

# String formatting
name = "Python"
message = f"Learning {name} is fun!"
"""

    with tempfile.NamedTemporaryFile(mode="w", suffix=".py", delete=False) as f:
        f.write(test_code)
        return f.name


def get_python_bytecode(file_path):
    """Get Python's official bytecode using dis module"""
    with open(file_path, "r") as f:
        code = f.read()

    # Compile and disassemble
    compiled = compile(code, file_path, "exec")

    # Capture dis output
    import io
    from contextlib import redirect_stdout

    output = io.StringIO()
    with redirect_stdout(output):
        dis.dis(compiled)

    bytecode_lines = output.getvalue().split("\n")

    # Extract opcodes
    opcodes = []
    for line in bytecode_lines:
        if line.strip():
            parts = line.split()
            if len(parts) >= 3 and parts[2].isupper():
                opcodes.append(parts[2])

    return opcodes


def get_malwi_bytecode(file_path):
    """Get malwi's bytecode using ast_to_malwicode.py"""
    compiler = ASTCompiler("python")

    # Read the file
    with open(file_path, "rb") as f:
        source_code_bytes = f.read()

    # Generate bytecode
    try:
        code_objects = compiler.process_file(Path(file_path))
        opcodes = []
        for code_obj in code_objects:
            for instruction in code_obj.byte_code:
                opcodes.append(instruction.opcode.name)
        return opcodes
    except Exception as e:
        print(f"Error compiling with malwi: {e}")
        return []


def compare_opcodes(python_opcodes, malwi_opcodes):
    """Compare the two sets of opcodes and identify differences"""
    python_set = set(python_opcodes)
    malwi_set = set(malwi_opcodes)

    # Find differences
    only_in_python = python_set - malwi_set
    only_in_malwi = malwi_set - python_set
    common_opcodes = python_set & malwi_set

    print("=== BYTECODE COMPARISON RESULTS ===\n")

    print(f"Python opcodes found: {len(python_set)}")
    print(f"Malwi opcodes found: {len(malwi_set)}")
    print(f"Common opcodes: {len(common_opcodes)}")
    print()

    if only_in_python:
        print("🔴 MISSING in malwi (present in Python):")
        for opcode in sorted(only_in_python):
            print(f"  - {opcode}")
        print()

    if only_in_malwi:
        print("🟡 EXTRA in malwi (not in Python):")
        for opcode in sorted(only_in_malwi):
            print(f"  - {opcode}")
        print()

    if common_opcodes:
        print("✅ COMMON opcodes:")
        for opcode in sorted(common_opcodes):
            print(f"  - {opcode}")
        print()

    # Detailed sequence comparison
    print("=== SEQUENCE COMPARISON ===")
    print("\nPython bytecode sequence:")
    for i, opcode in enumerate(python_opcodes[:20]):  # First 20
        print(f"  {i:2d}: {opcode}")
    if len(python_opcodes) > 20:
        print(f"  ... and {len(python_opcodes) - 20} more")

    print("\nMalwi bytecode sequence:")
    for i, opcode in enumerate(malwi_opcodes[:20]):  # First 20
        print(f"  {i:2d}: {opcode}")
    if len(malwi_opcodes) > 20:
        print(f"  ... and {len(malwi_opcodes) - 20} more")


def identify_missing_constructs(missing_opcodes):
    """Identify which Python constructs are likely missing based on opcodes"""
    construct_opcodes = {
        "Exception handling": [
            "SETUP_FINALLY",
            "SETUP_EXCEPT",
            "POP_EXCEPT",
            "RERAISE",
            "RAISE_VARARGS",
        ],
        "Context managers": [
            "SETUP_WITH",
            "WITH_CLEANUP_START",
            "WITH_CLEANUP_FINISH",
            "WITH_EXCEPT_START",
        ],
        "Generators": ["YIELD_VALUE", "YIELD_FROM", "GEN_START"],
        "Async/Await": [
            "GET_AWAITABLE",
            "GET_AITER",
            "GET_ANEXT",
            "END_ASYNC_FOR",
            "BEFORE_ASYNC_WITH",
        ],
        "List/Set/Dict comprehensions": [
            "LIST_APPEND",
            "SET_ADD",
            "MAP_ADD",
            "BUILD_MAP_UNPACK_WITH_CALL",
        ],
        "Extended unpacking": ["UNPACK_EX", "BUILD_LIST_UNPACK", "BUILD_SET_UNPACK"],
        "Pattern matching": [
            "MATCH_SEQUENCE",
            "MATCH_MAPPING",
            "MATCH_CLASS",
            "MATCH_KEYS",
        ],
        "Slice operations": ["BUILD_SLICE", "STORE_SLICE", "DELETE_SLICE"],
        "Import system": ["IMPORT_STAR", "IMPORT_FROM"],
        "Format strings": ["FORMAT_VALUE", "BUILD_STRING"],
    }

    missing_constructs = []
    for construct, opcodes in construct_opcodes.items():
        missing_from_construct = [op for op in opcodes if op in missing_opcodes]
        if missing_from_construct:
            missing_constructs.append((construct, missing_from_construct))

    if missing_constructs:
        print("\n🔍 LIKELY MISSING CONSTRUCTS:")
        for construct, opcodes in missing_constructs:
            print(f"\n  {construct}:")
            for op in opcodes:
                print(f"    - {op}")

    return missing_constructs


def main():
    if len(sys.argv) > 1:
        test_file = sys.argv[1]
        cleanup_file = False
    else:
        print("No test file provided, creating a comprehensive test file...")
        test_file = create_test_file()
        cleanup_file = True
        print(f"Created test file: {test_file}")

    try:
        print(f"\nAnalyzing file: {test_file}")
        print("=" * 50)

        # Get bytecode from both sources
        python_opcodes = get_python_bytecode(test_file)
        malwi_opcodes = get_malwi_bytecode(test_file)

        # Compare them
        compare_opcodes(python_opcodes, malwi_opcodes)

        # Identify missing constructs
        python_set = set(python_opcodes)
        malwi_set = set(malwi_opcodes)
        missing_opcodes = python_set - malwi_set

        if missing_opcodes:
            identify_missing_constructs(missing_opcodes)

    finally:
        if cleanup_file and os.path.exists(test_file):
            os.unlink(test_file)
            print(f"\nCleaned up temporary file: {test_file}")


if __name__ == "__main__":
    main()
