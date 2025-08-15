#!/usr/bin/env python3
"""
Enhanced bytecode comparison tool that shows detailed diffs and identifies missing constructs.

This utility compares Python's dis bytecode with malwi's bytecode generation to:
1. Show line-by-line differences
2. Identify missing Python constructs
3. Provide actionable insights for implementation

Usage:
    python util/bytecode_diff_analyzer.py [test_file.py]
    python util/bytecode_diff_analyzer.py --construct list_comprehension
    python util/bytecode_diff_analyzer.py --all-constructs
"""

import dis
import sys
import tempfile
import os
import ast
import difflib
from pathlib import Path
from collections import defaultdict
from typing import List, Tuple, Dict, Set

# Add src to path to import malwi modules
sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

from common.ast_to_malwicode import ASTCompiler


# Python construct test cases
PYTHON_CONSTRUCTS = {
    "basic_assignment": """
x = 5
y = 10
z = x + y
""",
    "function_definition": """
def add(a, b):
    return a + b

result = add(3, 4)
""",
    "list_comprehension": """
numbers = [1, 2, 3, 4, 5]
squares = [x**2 for x in numbers]
evens = [x for x in numbers if x % 2 == 0]
""",
    "dict_comprehension": """
keys = ['a', 'b', 'c']
values = [1, 2, 3]
d = {k: v for k, v in zip(keys, values)}
""",
    "set_comprehension": """
numbers = [1, 2, 2, 3, 3, 4]
unique_squares = {x**2 for x in numbers}
""",
    "generator_expression": """
gen = (x**2 for x in range(5))
result = list(gen)
""",
    "tuple_unpacking": """
a, b = (10, 20)
x, y, z = [1, 2, 3]
first, *rest = [1, 2, 3, 4, 5]
""",
    "extended_unpacking": """
a, *middle, b = [1, 2, 3, 4, 5]
x, y, *rest = range(10)
""",
    "if_elif_else": """
x = 10
if x > 0:
    result = "positive"
elif x < 0:
    result = "negative"
else:
    result = "zero"
""",
    "nested_if": """
x, y = 5, 10
if x > 0:
    if y > 0:
        result = "both positive"
    else:
        result = "x positive, y not"
else:
    result = "x not positive"
""",
    "for_loop": """
total = 0
for i in range(5):
    total += i
    
for x, y in [(1, 2), (3, 4)]:
    print(x, y)
""",
    "while_loop": """
count = 0
while count < 5:
    count += 1
    
x = 10
while x > 0:
    x -= 2
    if x == 4:
        break
""",
    "try_except": """
try:
    result = 10 / 0
except ZeroDivisionError:
    result = "infinity"
except Exception as e:
    result = str(e)
""",
    "try_finally": """
try:
    file = open("test.txt")
    data = file.read()
finally:
    file.close()
""",
    "context_manager": """
with open("test.txt", "w") as f:
    f.write("Hello")
    
from contextlib import contextmanager
@contextmanager
def my_context():
    yield "resource"
""",
    "class_definition": """
class MyClass:
    def __init__(self, value):
        self.value = value
    
    def get_value(self):
        return self.value
    
    @property
    def double(self):
        return self.value * 2

obj = MyClass(5)
""",
    "decorators": """
def decorator(func):
    def wrapper(*args, **kwargs):
        return func(*args, **kwargs)
    return wrapper

@decorator
def greet(name):
    return f"Hello {name}"
""",
    "lambda_functions": """
square = lambda x: x**2
add = lambda x, y: x + y
result = square(5)
""",
    "generators": """
def fibonacci():
    a, b = 0, 1
    while True:
        yield a
        a, b = b, a + b

gen = fibonacci()
first_five = [next(gen) for _ in range(5)]
""",
    "async_await": """
async def fetch_data():
    await asyncio.sleep(1)
    return "data"

async def main():
    result = await fetch_data()
""",
    "match_case": """
def describe(value):
    match value:
        case 0:
            return "zero"
        case 1 | 2 | 3:
            return "small"
        case _:
            return "other"
""",
    "walrus_operator": """
if (n := len([1, 2, 3])) > 2:
    print(f"List has {n} elements")
    
while (line := input()) != "quit":
    print(line)
""",
    "f_strings": """
name = "World"
age = 25
message = f"Hello {name}, you are {age} years old"
complex = f"Result: {2 + 2}, {name.upper()}"
""",
    "delete_operations": """
x = 10
del x

lst = [1, 2, 3, 4, 5]
del lst[0]
del lst[1:3]

d = {'a': 1, 'b': 2}
del d['a']
""",
    "slice_operations": """
lst = [0, 1, 2, 3, 4, 5]
a = lst[1:4]
b = lst[::2]
c = lst[::-1]
lst[1:3] = [10, 20]
""",
    "binary_operations": """
a = 5 & 3
b = 5 | 3
c = 5 ^ 3
d = ~5
e = 5 << 2
f = 20 >> 2
""",
    "augmented_assignment": """
x = 10
x += 5
x -= 3
x *= 2
x //= 4
x **= 2
x &= 3
""",
    "global_nonlocal": """
global_var = 10

def outer():
    x = 20
    
    def inner():
        nonlocal x
        global global_var
        x = 30
        global_var = 40
    
    inner()
""",
    "import_variations": """
import os
import sys as system
from pathlib import Path
from collections import defaultdict, Counter
from math import *
""",
    "yield_from": """
def gen1():
    yield 1
    yield 2

def gen2():
    yield from gen1()
    yield 3
""",
    "annotations": """
def add(x: int, y: int) -> int:
    return x + y

class Point:
    x: float
    y: float
""",
    "keyword_only_args": """
def func(a, b, *, c, d=10):
    return a + b + c + d

result = func(1, 2, c=3)
""",
    "positional_only_args": """
def func(a, b, /, c, d):
    return a + b + c + d

result = func(1, 2, 3, 4)
""",
}


def get_python_bytecode_detailed(code: str) -> List[Tuple[str, str, str]]:
    """Get detailed Python bytecode with line numbers and arguments"""
    compiled = compile(code, "<string>", "exec")

    instructions = []
    for instr in dis.get_instructions(compiled):
        opname = instr.opname
        arg = str(instr.arg) if instr.arg is not None else ""
        argval = str(instr.argval) if instr.argval is not None else ""
        instructions.append((opname, arg, argval))

    return instructions


def get_malwi_bytecode_detailed(code: str) -> List[Tuple[str, str, str]]:
    """Get detailed malwi bytecode with arguments"""
    with tempfile.NamedTemporaryFile(mode="w", suffix=".py", delete=False) as f:
        f.write(code)
        temp_file = f.name

    try:
        compiler = ASTCompiler("python")
        code_objects = compiler.process_file(Path(temp_file))

        instructions = []
        for code_obj in code_objects:
            for instr in code_obj.byte_code:
                opname = instr.opcode.name
                arg = str(instr.arg) if instr.arg is not None else ""
                argval = str(instr.arg) if instr.arg is not None else ""
                instructions.append((opname, arg, argval))

        return instructions
    finally:
        os.unlink(temp_file)


def format_instruction(instr: Tuple[str, str, str], index: int) -> str:
    """Format an instruction for display"""
    opname, arg, argval = instr
    if arg:
        return f"{index:4d}: {opname:<20} {arg:<10} ({argval})"
    else:
        return f"{index:4d}: {opname:<20}"


def show_bytecode_diff(construct_name: str, code: str):
    """Show detailed bytecode differences for a construct"""
    print(f"\n{'=' * 80}")
    print(f"CONSTRUCT: {construct_name}")
    print(f"{'=' * 80}")
    print("\nCode:")
    print("-" * 40)
    for line in code.strip().split("\n"):
        print(f"  {line}")
    print("-" * 40)

    # Get bytecode from both sources
    python_bytecode = get_python_bytecode_detailed(code)
    malwi_bytecode = get_malwi_bytecode_detailed(code)

    # Format for diff
    python_lines = [
        format_instruction(instr, i) for i, instr in enumerate(python_bytecode)
    ]
    malwi_lines = [
        format_instruction(instr, i) for i, instr in enumerate(malwi_bytecode)
    ]

    # Show counts
    print(f"\nBytecode instruction count:")
    print(f"  Python: {len(python_bytecode)} instructions")
    print(f"  Malwi:  {len(malwi_bytecode)} instructions")

    # Show diff
    print("\nDetailed diff (- Python, + Malwi):")
    print("-" * 80)

    diff = difflib.unified_diff(
        python_lines,
        malwi_lines,
        fromfile="Python dis",
        tofile="Malwi",
        lineterm="",
        n=3,
    )

    diff_lines = list(diff)
    if len(diff_lines) > 4:  # Skip header lines if there are differences
        for line in diff_lines[4:]:  # Skip the header
            if line.startswith("+"):
                print(f"\033[32m{line}\033[0m")  # Green for additions
            elif line.startswith("-"):
                print(f"\033[31m{line}\033[0m")  # Red for deletions
            else:
                print(line)
    else:
        print("  No differences found!")

    # Identify missing opcodes
    python_opcodes = set(instr[0] for instr in python_bytecode)
    malwi_opcodes = set(instr[0] for instr in malwi_bytecode)
    missing = python_opcodes - malwi_opcodes
    extra = malwi_opcodes - python_opcodes

    if missing:
        print(f"\n🔴 Missing opcodes in malwi:")
        for op in sorted(missing):
            print(f"  - {op}")

    if extra:
        print(f"\n🟡 Extra opcodes in malwi:")
        for op in sorted(extra):
            print(f"  - {op}")


def analyze_all_constructs():
    """Analyze all Python constructs and summarize findings"""
    missing_opcodes_by_construct = defaultdict(set)
    construct_issues = defaultdict(list)

    print("\n" + "=" * 80)
    print("ANALYZING ALL PYTHON CONSTRUCTS")
    print("=" * 80)

    for construct_name, code in PYTHON_CONSTRUCTS.items():
        try:
            python_bytecode = get_python_bytecode_detailed(code)
            malwi_bytecode = get_malwi_bytecode_detailed(code)

            python_opcodes = set(instr[0] for instr in python_bytecode)
            malwi_opcodes = set(instr[0] for instr in malwi_bytecode)
            missing = python_opcodes - malwi_opcodes

            if missing:
                missing_opcodes_by_construct[construct_name] = missing
                construct_issues[construct_name].append(
                    f"Missing opcodes: {', '.join(sorted(missing))}"
                )

            # Check for significant size differences
            size_diff = abs(len(python_bytecode) - len(malwi_bytecode))
            if size_diff > len(python_bytecode) * 0.3:  # More than 30% difference
                construct_issues[construct_name].append(
                    f"Significant size difference: Python={len(python_bytecode)}, Malwi={len(malwi_bytecode)}"
                )

        except Exception as e:
            construct_issues[construct_name].append(f"Error: {str(e)}")

    # Summary report
    print("\n" + "=" * 80)
    print("SUMMARY REPORT")
    print("=" * 80)

    # Constructs with issues
    if construct_issues:
        print("\n🔴 Constructs with issues:")
        for construct, issues in sorted(construct_issues.items()):
            print(f"\n  {construct}:")
            for issue in issues:
                print(f"    - {issue}")
    else:
        print("\n✅ All constructs compiled successfully!")

    # Missing opcodes summary
    all_missing_opcodes = set()
    for opcodes in missing_opcodes_by_construct.values():
        all_missing_opcodes.update(opcodes)

    if all_missing_opcodes:
        print("\n🔴 All missing opcodes across all constructs:")
        opcode_constructs = defaultdict(list)
        for construct, opcodes in missing_opcodes_by_construct.items():
            for opcode in opcodes:
                opcode_constructs[opcode].append(construct)

        for opcode in sorted(all_missing_opcodes):
            constructs = opcode_constructs[opcode]
            print(f"\n  {opcode}:")
            print(f"    Used in: {', '.join(constructs[:5])}")
            if len(constructs) > 5:
                print(f"    ... and {len(constructs) - 5} more constructs")

    # Recommendations
    print("\n" + "=" * 80)
    print("IMPLEMENTATION RECOMMENDATIONS")
    print("=" * 80)

    priority_opcodes = []
    for opcode, constructs in opcode_constructs.items():
        if len(constructs) >= 3:  # Used in 3 or more constructs
            priority_opcodes.append((opcode, len(constructs)))

    if priority_opcodes:
        print("\n🎯 High-priority opcodes to implement (used in multiple constructs):")
        for opcode, count in sorted(priority_opcodes, key=lambda x: x[1], reverse=True):
            print(f"  - {opcode} (used in {count} constructs)")

    # Specific construct recommendations
    critical_constructs = [
        "try_except",
        "generators",
        "list_comprehension",
        "class_definition",
    ]
    missing_critical = [c for c in critical_constructs if c in construct_issues]

    if missing_critical:
        print("\n🚨 Critical constructs needing attention:")
        for construct in missing_critical:
            print(f"  - {construct}")


def main():
    import argparse

    parser = argparse.ArgumentParser(
        description="Enhanced bytecode comparison and analysis tool"
    )
    parser.add_argument("file", nargs="?", help="Python file to analyze")
    parser.add_argument(
        "--construct",
        help="Analyze a specific construct",
        choices=list(PYTHON_CONSTRUCTS.keys()),
    )
    parser.add_argument(
        "--all-constructs", action="store_true", help="Analyze all Python constructs"
    )
    parser.add_argument(
        "--list-constructs", action="store_true", help="List available constructs"
    )

    args = parser.parse_args()

    if args.list_constructs:
        print("Available constructs:")
        for name in sorted(PYTHON_CONSTRUCTS.keys()):
            print(f"  - {name}")
        return

    if args.all_constructs:
        analyze_all_constructs()
    elif args.construct:
        show_bytecode_diff(args.construct, PYTHON_CONSTRUCTS[args.construct])
    elif args.file:
        # Analyze a specific file
        with open(args.file, "r") as f:
            code = f.read()
        show_bytecode_diff(args.file, code)
    else:
        # Run a few examples
        print("Running example analyses...")
        for construct in ["list_comprehension", "try_except", "generators"]:
            show_bytecode_diff(construct, PYTHON_CONSTRUCTS[construct])

        print("\n" + "=" * 80)
        print("For full analysis, run with --all-constructs")
        print("To analyze specific construct: --construct <name>")
        print("To list all constructs: --list-constructs")


if __name__ == "__main__":
    main()
