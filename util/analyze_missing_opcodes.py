#!/usr/bin/env python3
"""
Focused analysis of missing opcodes with implementation recommendations

This script provides detailed analysis of opcodes that are missing from malwi's
ast_to_malwicode.py implementation, categorized by priority and with specific
recommendations for implementation.

Usage:
    python util/analyze_missing_opcodes.py [test_file.py]
"""

import dis
import sys
import tempfile
import os
from pathlib import Path
from collections import Counter

# Add src to path to import malwi modules
sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

from common.ast_to_malwicode import ASTCompiler


# Opcode categorization based on importance for malware detection
CRITICAL_OPCODES = {
    "UNPACK_SEQUENCE": "Tuple/list unpacking - common in malicious scripts",
    "BUILD_STRING": "F-string construction - used in dynamic code generation",
    "FORMAT_VALUE": "F-string value formatting - used in obfuscation",
    "LIST_APPEND": "List comprehension optimization - memory attacks",
    "SET_ADD": "Set comprehension optimization",
    "MAP_ADD": "Dict comprehension optimization",
    "YIELD_VALUE": "Generator yield - async malware patterns",
    "DELETE_NAME": "Variable deletion - anti-analysis technique",
    "DELETE_SUBSCR": "Subscript deletion - data manipulation",
}

HIGH_PRIORITY_OPCODES = {
    "BINARY_SUBSCR": "Array/dict access - data exfiltration patterns",
    "STORE_SUBSCR": "Array/dict assignment - payload injection",
    "BUILD_SLICE": "Slice operations - data manipulation",
    "EXTENDED_ARG": "Extended argument support for large constants",
    "LOAD_CLOSURE": "Closure loading - advanced obfuscation",
    "MAKE_FUNCTION": "Function creation with closure",
    "SETUP_EXCEPT": "Exception handling setup - error hiding",
    "POP_EXCEPT": "Exception cleanup",
    "RERAISE": "Exception reraising",
}

MEDIUM_PRIORITY_OPCODES = {
    "SETUP_FINALLY": "Finally block setup",
    "SETUP_WITH": "Context manager setup - file operations",
    "WITH_CLEANUP_START": "Context manager cleanup",
    "WITH_CLEANUP_FINISH": "Context manager cleanup completion",
    "GET_AWAITABLE": "Async operations",
    "GET_AITER": "Async iteration",
    "GET_ANEXT": "Async next",
    "BEFORE_ASYNC_WITH": "Async context manager",
}

LOW_PRIORITY_OPCODES = {
    "SETUP_ANNOTATIONS": "Type annotation setup",
    "BUILD_CONST_KEY_MAP": "Constant key mapping optimization",
    "DICT_MERGE": "Dictionary merging (Python 3.9+)",
    "DICT_UPDATE": "Dictionary update operations",
    "LIST_EXTEND": "List extend operations",
    "SET_UPDATE": "Set update operations",
    "MATCH_SEQUENCE": "Pattern matching (Python 3.10+)",
    "MATCH_MAPPING": "Mapping pattern matching",
    "MATCH_CLASS": "Class pattern matching",
    "MATCH_KEYS": "Key matching in patterns",
}

IGNORABLE_OPCODES = {
    "CACHE": "Internal caching - not relevant for analysis",
    "RESUME": "Internal resume operation",
    "PRECALL": "Pre-call optimization",
    "KW_NAMES": "Keyword argument names",
    "PUSH_NULL": "Internal stack operation",
    "COPY": "Internal copy operation",
    "SWAP": "Internal swap operation",
}


def create_comprehensive_test_file():
    """Create a test file that exercises many Python opcodes"""
    test_code = """
import os
import sys
from collections import defaultdict

# Basic operations
x = 5
y = [1, 2, 3]
z = {"key": "value"}

# Tuple unpacking (UNPACK_SEQUENCE)
a, b, c = (1, 2, 3)
first, *rest = [1, 2, 3, 4, 5]

# F-strings (BUILD_STRING, FORMAT_VALUE)
name = "world"
greeting = f"Hello {name}!"
complex_format = f"Value: {x:02d}, List: {y!r}"

# Comprehensions (LIST_APPEND, SET_ADD, MAP_ADD)
squares = [i**2 for i in range(10)]
unique_squares = {i**2 for i in range(10)}
square_map = {i: i**2 for i in range(10)}

# Subscript operations (BINARY_SUBSCR, STORE_SUBSCR)
value = y[0]
y[1] = 100
dict_value = z["key"]
z["new_key"] = "new_value"

# Slicing (BUILD_SLICE)
subset = y[1:3]
y[1:2] = [99]

# Generators (YIELD_VALUE)
def number_generator():
    for i in range(3):
        yield i

# Function with closure (LOAD_CLOSURE, MAKE_FUNCTION)
def outer_function():
    outer_var = "captured"
    def inner_function():
        return outer_var
    return inner_function

# Exception handling (SETUP_EXCEPT, POP_EXCEPT, RERAISE)
try:
    risky_operation = 10 / 0
except ZeroDivisionError as e:
    print(f"Error: {e}")
    # Re-raise in some cases
    if x > 10:
        raise
finally:
    print("Cleanup")

# Context managers (SETUP_WITH, WITH_CLEANUP_START, WITH_CLEANUP_FINISH)
with open(__file__, 'r') as f:
    content = f.read()

# Delete operations (DELETE_NAME, DELETE_SUBSCR)
temp_var = 42
del temp_var
temp_list = [1, 2, 3]
del temp_list[0]

# Advanced dictionary operations (Python 3.9+)
dict1 = {"a": 1}
dict2 = {"b": 2}
merged = {**dict1, **dict2}

# Async operations (if supported)
async def async_function():
    return "async result"

# Class definition
class TestClass:
    def __init__(self, value):
        self.value = value
    
    def method(self):
        return self.value

# Pattern matching (Python 3.10+)
def process_data(data):
    match data:
        case [x] if x > 0:
            return f"Single positive: {x}"
        case [x, y]:
            return f"Pair: {x}, {y}"
        case {"type": "dict", "value": v}:
            return f"Dict with value: {v}"
        case _:
            return "Unknown pattern"
"""

    with tempfile.NamedTemporaryFile(mode="w", suffix=".py", delete=False) as f:
        f.write(test_code)
        return f.name


def get_python_opcodes_detailed(file_path):
    """Get detailed Python opcodes with frequency"""
    with open(file_path, "r") as f:
        code = f.read()

    try:
        compiled = compile(code, file_path, "exec")
    except SyntaxError as e:
        print(f"Syntax error in {file_path}: {e}")
        return Counter()

    # Extract opcodes from bytecode
    opcodes = []
    for instruction in dis.get_instructions(compiled):
        opcodes.append(instruction.opname)

    return Counter(opcodes)


def get_malwi_opcodes_detailed(file_path):
    """Get detailed malwi opcodes with frequency"""
    compiler = ASTCompiler("python")

    try:
        code_objects = compiler.process_file(Path(file_path))
        opcodes = []
        for code_obj in code_objects:
            for instruction in code_obj.byte_code:
                opcodes.append(instruction.opcode.name)
        return Counter(opcodes)
    except Exception as e:
        print(f"Error compiling with malwi: {e}")
        return Counter()


def categorize_missing_opcodes(missing_opcodes):
    """Categorize missing opcodes by priority"""
    categorized = {
        "Critical": {},
        "High Priority": {},
        "Medium Priority": {},
        "Low Priority": {},
        "Ignorable": {},
        "Unknown": {},
    }

    for opcode in missing_opcodes:
        if opcode in CRITICAL_OPCODES:
            categorized["Critical"][opcode] = CRITICAL_OPCODES[opcode]
        elif opcode in HIGH_PRIORITY_OPCODES:
            categorized["High Priority"][opcode] = HIGH_PRIORITY_OPCODES[opcode]
        elif opcode in MEDIUM_PRIORITY_OPCODES:
            categorized["Medium Priority"][opcode] = MEDIUM_PRIORITY_OPCODES[opcode]
        elif opcode in LOW_PRIORITY_OPCODES:
            categorized["Low Priority"][opcode] = LOW_PRIORITY_OPCODES[opcode]
        elif opcode in IGNORABLE_OPCODES:
            categorized["Ignorable"][opcode] = IGNORABLE_OPCODES[opcode]
        else:
            categorized["Unknown"][opcode] = "Unknown opcode - needs investigation"

    return categorized


def generate_implementation_template(opcode, description):
    """Generate implementation template for an opcode"""
    template = f'''
# Implementation for {opcode}
# Description: {description}

def _handle_{opcode.lower()}(self, node, source_code_bytes, file_path):
    """Handle {opcode} opcode generation"""
    bytecode = []
    
    # TODO: Implement {opcode} logic here
    # Consider the AST node structure and generate appropriate bytecode
    
    bytecode.append(emit(OpCode.{opcode}, argument))
    return bytecode
'''
    return template


def main():
    if len(sys.argv) > 1:
        test_file = sys.argv[1]
        cleanup_file = False
    else:
        print("Creating comprehensive test file...")
        test_file = create_comprehensive_test_file()
        cleanup_file = True

    try:
        print(f"Analyzing opcodes in: {test_file}")
        print("=" * 60)

        # Get opcode frequencies
        python_opcodes = get_python_opcodes_detailed(test_file)
        malwi_opcodes = get_malwi_opcodes_detailed(test_file)

        # Find missing opcodes
        missing_opcodes = set(python_opcodes.keys()) - set(malwi_opcodes.keys())

        if not missing_opcodes:
            print("✅ No missing opcodes found!")
            return

        # Categorize missing opcodes
        categorized = categorize_missing_opcodes(missing_opcodes)

        print(f"Found {len(missing_opcodes)} missing opcodes\n")

        # Display by category
        for category, opcodes in categorized.items():
            if opcodes:
                print(f"🔴 {category.upper()} MISSING OPCODES:")
                for opcode, description in opcodes.items():
                    frequency = python_opcodes[opcode]
                    print(f"  • {opcode} (used {frequency}x) - {description}")
                print()

        # Generate implementation recommendations
        print("=" * 60)
        print("IMPLEMENTATION RECOMMENDATIONS:")
        print("=" * 60)

        # Focus on critical and high priority
        critical_and_high = {**categorized["Critical"], **categorized["High Priority"]}

        if critical_and_high:
            print("\n🚨 IMMEDIATE ACTION REQUIRED:")
            for opcode, description in critical_and_high.items():
                print(f"\n{opcode}:")
                print(
                    f"  Priority: {'CRITICAL' if opcode in CRITICAL_OPCODES else 'HIGH'}"
                )
                print(f"  Usage: {python_opcodes[opcode]} times in test")
                print(f"  Impact: {description}")
                print(f"  Implementation: Add to OpCode enum and implement handler")

        # Summary statistics
        print("\n" + "=" * 60)
        print("SUMMARY STATISTICS:")
        print("=" * 60)
        total_missing = len(missing_opcodes)
        critical_count = len(categorized["Critical"])
        high_count = len(categorized["High Priority"])

        print(f"Total missing opcodes: {total_missing}")
        print(f"Critical missing: {critical_count}")
        print(f"High priority missing: {high_count}")
        print(
            f"Implementation urgency: {'🚨 HIGH' if critical_count > 0 else '⚠️ MEDIUM' if high_count > 0 else '📋 LOW'}"
        )

    finally:
        if cleanup_file and os.path.exists(test_file):
            os.unlink(test_file)


if __name__ == "__main__":
    main()
