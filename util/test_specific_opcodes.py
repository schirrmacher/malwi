#!/usr/bin/env python3
"""
Test specific opcode translations with minimal examples

This script creates focused test cases for specific opcodes to understand
exactly how they should be implemented in malwi's ast_to_malwicode.py

Usage:
    python util/test_specific_opcodes.py [opcode_name]

If no opcode is specified, it will test all known opcodes with examples.
"""

import dis
import sys
import tempfile
import os
from pathlib import Path

# Add src to path to import malwi modules
sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

from common.bytecode import ASTCompiler


# Test cases for specific opcodes
OPCODE_TEST_CASES = {
    "UNPACK_SEQUENCE": [
        "a, b = (1, 2)",
        "x, y, z = [1, 2, 3]",
        "first, *rest = range(5)",
        'head, *middle, tail = "hello"',
    ],
    "BUILD_STRING": ['f"Hello world"', 'f"Value: {42}"', 'f"x={x}, y={y}"'],
    "FORMAT_VALUE": ['f"{42:02d}"', 'f"{3.14:.2f}"', 'f"{name!r}"', 'f"{value!s}"'],
    "LIST_APPEND": ["[x**2 for x in range(3)]", "[i for i in range(5) if i % 2 == 0]"],
    "SET_ADD": ["{x**2 for x in range(3)}", "{i for i in range(5) if i % 2 == 0}"],
    "MAP_ADD": ["{x: x**2 for x in range(3)}", "{str(i): i for i in range(3)}"],
    "YIELD_VALUE": [
        """def gen():
    yield 1
    yield 2""",
        """def fibonacci():
    a, b = 0, 1
    while True:
        yield a
        a, b = b, a + b""",
    ],
    "DELETE_NAME": [
        """x = 5
del x""",
        """temp = "temporary"
del temp""",
    ],
    "DELETE_SUBSCR": [
        """lst = [1, 2, 3]
del lst[0]""",
        """d = {"a": 1, "b": 2}
del d["a"]""",
    ],
    "BINARY_SUBSCR": ["arr[0]", 'dict_obj["key"]', "text[1:3]"],
    "STORE_SUBSCR": [
        """arr = [1, 2, 3]
arr[0] = 99""",
        '''d = {}
d["key"] = "value"''',
    ],
    "BUILD_SLICE": ["arr[1:3]", "text[:5]", "data[::2]", "items[1:10:2]"],
    "SETUP_EXCEPT": [
        """try:
    risky_operation()
except Exception:
    handle_error()"""
    ],
    "SETUP_WITH": [
        """with open("file.txt") as f:
    content = f.read()"""
    ],
    "LOAD_CLOSURE": [
        """def outer():
    x = 10
    def inner():
        return x
    return inner"""
    ],
    "MAKE_FUNCTION": [
        """def func(x, y=10):
    return x + y""",
        """lambda x: x * 2""",
    ],
}


def create_test_file_for_opcode(opcode, test_cases):
    """Create a test file containing specific opcode test cases"""
    if opcode not in test_cases:
        return None

    # Create test code
    test_code = f"# Test cases for {opcode}\n\n"

    for i, case in enumerate(test_cases[opcode]):
        test_code += f"# Test case {i + 1}\n"
        test_code += case + "\n\n"

    # Write to temporary file
    with tempfile.NamedTemporaryFile(mode="w", suffix=".py", delete=False) as f:
        f.write(test_code)
        return f.name


def analyze_opcode_in_bytecode(file_path, target_opcode):
    """Analyze how a specific opcode appears in Python bytecode"""
    with open(file_path, "r") as f:
        code = f.read()

    try:
        compiled = compile(code, file_path, "exec")
    except SyntaxError as e:
        print(f"Syntax error: {e}")
        return []

    # Find all instructions for the target opcode
    matching_instructions = []
    for instruction in dis.get_instructions(compiled):
        if instruction.opname == target_opcode:
            matching_instructions.append(
                {
                    "offset": instruction.offset,
                    "opname": instruction.opname,
                    "arg": instruction.arg,
                    "argval": instruction.argval,
                    "argrepr": instruction.argrepr,
                    "starts_line": instruction.starts_line,
                }
            )

    return matching_instructions


def test_malwi_compilation(file_path):
    """Test how malwi compiles the same file"""
    compiler = ASTCompiler("python")

    try:
        code_objects = compiler.process_file(Path(file_path))
        # Convert to string representation like the original
        bytecode_instructions = []
        for code_obj in code_objects:
            for instruction in code_obj.byte_code:
                # Format like the original output
                instr_str = instruction.opcode.name
                if instruction.arg is not None:
                    instr_str += f" {instruction.arg}"
                bytecode_instructions.append(instr_str)
        return bytecode_instructions
    except Exception as e:
        print(f"Malwi compilation error: {e}")
        return []


def compare_opcode_handling(opcode):
    """Compare how Python and malwi handle a specific opcode"""
    print(f"\n{'=' * 60}")
    print(f"TESTING OPCODE: {opcode}")
    print(f"{'=' * 60}")

    if opcode not in OPCODE_TEST_CASES:
        print(f"No test cases defined for {opcode}")
        return

    # Create test file
    test_file = create_test_file_for_opcode(opcode, OPCODE_TEST_CASES)
    if not test_file:
        return

    try:
        print(f"\nTest cases for {opcode}:")
        with open(test_file, "r") as f:
            print(f.read())

        print(f"\n--- Python bytecode analysis ---")
        python_instructions = analyze_opcode_in_bytecode(test_file, opcode)

        if python_instructions:
            print(f"Found {len(python_instructions)} instances of {opcode}:")
            for i, instr in enumerate(python_instructions):
                print(
                    f"  {i + 1}. Line {instr['starts_line']}: "
                    f"{instr['opname']} {instr['argrepr']}"
                )
        else:
            print(f"No {opcode} instructions found in Python bytecode")

        print(f"\n--- Malwi bytecode analysis ---")
        malwi_bytecode = test_malwi_compilation(test_file)

        # Look for the opcode in malwi output
        malwi_opcodes = []
        for instruction in malwi_bytecode:
            if instruction.startswith(opcode):
                malwi_opcodes.append(instruction.strip())

        if malwi_opcodes:
            print(f"Found {len(malwi_opcodes)} instances in malwi bytecode:")
            for i, instr in enumerate(malwi_opcodes):
                print(f"  {i + 1}. {instr}")
        else:
            print(f"❌ {opcode} not found in malwi bytecode")

        # Summary
        python_count = len(python_instructions)
        malwi_count = len(malwi_opcodes)

        print(f"\n--- Summary ---")
        print(f"Python uses {opcode}: {python_count} times")
        print(f"Malwi generates {opcode}: {malwi_count} times")

        if python_count > 0 and malwi_count == 0:
            print(f"🔴 MISSING: {opcode} needs to be implemented in malwi")
        elif python_count == malwi_count:
            print(f"✅ MATCH: {opcode} correctly implemented")
        else:
            print(f"⚠️  MISMATCH: Different counts (needs investigation)")

    finally:
        if os.path.exists(test_file):
            os.unlink(test_file)


def main():
    if len(sys.argv) > 1:
        # Test specific opcode
        opcode = sys.argv[1].upper()
        compare_opcode_handling(opcode)
    else:
        # Test all opcodes
        print("Testing all known opcodes...")

        for opcode in OPCODE_TEST_CASES.keys():
            compare_opcode_handling(opcode)

        print(f"\n{'=' * 60}")
        print("TESTING COMPLETE")
        print(f"{'=' * 60}")
        print(f"Tested {len(OPCODE_TEST_CASES)} opcodes")
        print(
            "Use 'python util/test_specific_opcodes.py OPCODE_NAME' to test individual opcodes"
        )


if __name__ == "__main__":
    main()
