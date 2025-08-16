#!/usr/bin/env python3
"""
Visual bytecode comparison tool with side-by-side diff view.

This tool provides a visual comparison of Python's dis bytecode and malwi's bytecode,
helping to identify exactly where the implementations differ.

Usage:
    python util/bytecode_visual_diff.py [test_file.py]
    python util/bytecode_visual_diff.py --simple  # Run simple examples
"""

import dis
import sys
import tempfile
import os
import ast
from pathlib import Path
from typing import List, Tuple, Optional
import textwrap

# Add src to path to import malwi modules
sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

from common.bytecode import ASTCompiler


class BytecodeInstruction:
    def __init__(
        self,
        offset: int,
        opname: str,
        arg: Optional[int] = None,
        argval: Optional[str] = None,
        line_no: Optional[int] = None,
    ):
        self.offset = offset
        self.opname = opname
        self.arg = arg
        self.argval = argval
        self.line_no = line_no

    def __str__(self):
        parts = [f"{self.offset:4d}"]
        if self.line_no is not None:
            parts.append(f"L{self.line_no:3d}")
        else:
            parts.append("    ")
        parts.append(f"{self.opname:<20}")
        if self.arg is not None:
            if isinstance(self.arg, int):
                parts.append(f"{self.arg:5d}")
            else:
                parts.append(f"{str(self.arg):>5}")
            if self.argval is not None:
                parts.append(f"({self.argval})")
        return " ".join(parts)


def get_python_instructions(code: str) -> List[BytecodeInstruction]:
    """Get Python bytecode instructions with full details"""
    compiled = compile(code, "<string>", "exec")

    instructions = []
    for instr in dis.get_instructions(compiled):
        instructions.append(
            BytecodeInstruction(
                offset=instr.offset,
                opname=instr.opname,
                arg=instr.arg,
                argval=str(instr.argval) if instr.argval is not None else None,
                line_no=instr.starts_line,
            )
        )

    return instructions


def get_malwi_instructions(code: str) -> List[BytecodeInstruction]:
    """Get malwi bytecode instructions"""
    with tempfile.NamedTemporaryFile(mode="w", suffix=".py", delete=False) as f:
        f.write(code)
        temp_file = f.name

    try:
        compiler = ASTCompiler("python")
        code_objects = compiler.process_file(Path(temp_file))

        instructions = []
        offset = 0
        for code_obj in code_objects:
            for i, instr in enumerate(code_obj.byte_code):
                instructions.append(
                    BytecodeInstruction(
                        offset=offset,
                        opname=instr.opcode.name,
                        arg=instr.arg if hasattr(instr, "arg") else None,
                        argval=str(instr.arg) if instr.arg is not None else None,
                        line_no=None,  # malwi doesn't track line numbers yet
                    )
                )
                offset += 2  # Approximate offset

        return instructions
    finally:
        os.unlink(temp_file)


def align_instructions(
    python_instrs: List[BytecodeInstruction], malwi_instrs: List[BytecodeInstruction]
) -> List[Tuple[Optional[BytecodeInstruction], Optional[BytecodeInstruction], str]]:
    """Align instructions for side-by-side comparison using sequence matching"""
    result = []

    # Simple alignment strategy - can be improved with better sequence matching
    i, j = 0, 0

    while i < len(python_instrs) or j < len(malwi_instrs):
        if i >= len(python_instrs):
            # Remaining malwi instructions
            result.append((None, malwi_instrs[j], "added"))
            j += 1
        elif j >= len(malwi_instrs):
            # Remaining python instructions
            result.append((python_instrs[i], None, "missing"))
            i += 1
        else:
            # Try to match opcodes
            if python_instrs[i].opname == malwi_instrs[j].opname:
                # Match found
                diff_type = "match"
                if (
                    python_instrs[i].argval != malwi_instrs[j].argval
                    and python_instrs[i].argval is not None
                    and malwi_instrs[j].argval is not None
                ):
                    diff_type = "diff_arg"
                result.append((python_instrs[i], malwi_instrs[j], diff_type))
                i += 1
                j += 1
            else:
                # Look ahead for matches
                found_match = False

                # Check if python opcode appears later in malwi
                for k in range(j + 1, min(j + 5, len(malwi_instrs))):
                    if python_instrs[i].opname == malwi_instrs[k].opname:
                        # Add malwi instructions up to the match
                        for l in range(j, k):
                            result.append((None, malwi_instrs[l], "added"))
                        j = k
                        found_match = True
                        break

                if not found_match:
                    # Check if malwi opcode appears later in python
                    for k in range(i + 1, min(i + 5, len(python_instrs))):
                        if python_instrs[k].opname == malwi_instrs[j].opname:
                            # Add python instructions up to the match
                            for l in range(i, k):
                                result.append((python_instrs[l], None, "missing"))
                            i = k
                            found_match = True
                            break

                if not found_match:
                    # No match found, advance python
                    result.append((python_instrs[i], None, "missing"))
                    i += 1

    return result


def print_side_by_side(
    code: str,
    aligned: List[
        Tuple[Optional[BytecodeInstruction], Optional[BytecodeInstruction], str]
    ],
):
    """Print side-by-side comparison"""
    # Print header
    print("\n" + "=" * 120)
    print(f"{'PYTHON BYTECODE':^55} | {'MALWI BYTECODE':^55}")
    print("=" * 120)

    # Print code
    print("\nSource code:")
    print("-" * 120)
    for line in code.strip().split("\n"):
        print(f"  {line}")
    print("-" * 120)
    print()

    # Statistics
    stats = {"match": 0, "missing": 0, "added": 0, "diff_arg": 0}
    for _, _, diff_type in aligned:
        stats[diff_type] += 1

    print(
        f"Statistics: {stats['match']} matches, {stats['missing']} missing, "
        f"{stats['added']} added, {stats['diff_arg']} different args"
    )
    print()

    # Print instructions
    for python_instr, malwi_instr, diff_type in aligned:
        python_str = str(python_instr) if python_instr else ""
        malwi_str = str(malwi_instr) if malwi_instr else ""

        # Color coding
        if diff_type == "match":
            print(f"{python_str:<55} | {malwi_str:<55}")
        elif diff_type == "missing":
            print(f"\033[31m{python_str:<55}\033[0m | {' ' * 55}")
        elif diff_type == "added":
            print(f"{' ' * 55} | \033[32m{malwi_str:<55}\033[0m")
        elif diff_type == "diff_arg":
            print(f"\033[33m{python_str:<55} | {malwi_str:<55}\033[0m")

    print("\n" + "=" * 120)

    # Legend
    print(
        "Legend: \033[31mRed = Missing in malwi\033[0m, "
        "\033[32mGreen = Extra in malwi\033[0m, "
        "\033[33mYellow = Different arguments\033[0m"
    )


def analyze_construct_patterns():
    """Analyze common patterns in missing opcodes"""
    test_cases = {
        "Exception Handling": """
try:
    x = 1 / 0
except ZeroDivisionError:
    x = float('inf')
finally:
    print("done")
""",
        "Context Manager": """
with open('test.txt', 'w') as f:
    f.write('hello')
""",
        "List Comprehension": """
numbers = [1, 2, 3, 4, 5]
squares = [x**2 for x in numbers if x % 2 == 0]
""",
        "Generator": """
def gen():
    yield 1
    yield 2
    return 3

g = gen()
""",
        "Slice Assignment": """
lst = [1, 2, 3, 4, 5]
lst[1:3] = [10, 20]
del lst[0]
""",
        "Extended Unpacking": """
first, *middle, last = [1, 2, 3, 4, 5]
""",
        "Pattern Matching": """
def check(value):
    match value:
        case 0:
            return "zero"
        case [x, y]:
            return f"pair: {x}, {y}"
        case _:
            return "other"
""",
        "Async/Await": """
async def fetch():
    await asyncio.sleep(1)
    return "data"
""",
    }

    print("\n" + "=" * 80)
    print("ANALYZING COMMON CONSTRUCT PATTERNS")
    print("=" * 80)

    missing_by_construct = {}

    for name, code in test_cases.items():
        try:
            python_instrs = get_python_instructions(code)
            malwi_instrs = get_malwi_instructions(code)

            python_ops = set(instr.opname for instr in python_instrs)
            malwi_ops = set(instr.opname for instr in malwi_instrs)
            missing = python_ops - malwi_ops

            if missing:
                missing_by_construct[name] = missing

        except Exception as e:
            missing_by_construct[name] = {f"ERROR: {str(e)}"}

    # Report findings
    for construct, missing_ops in missing_by_construct.items():
        print(f"\n{construct}:")
        for op in sorted(missing_ops):
            print(f"  - {op}")

    # Find common patterns
    all_missing = set()
    for ops in missing_by_construct.values():
        all_missing.update(ops)

    print("\n" + "=" * 80)
    print("MOST COMMON MISSING OPCODES:")
    print("=" * 80)

    opcode_count = {}
    for ops in missing_by_construct.values():
        for op in ops:
            if not op.startswith("ERROR"):
                opcode_count[op] = opcode_count.get(op, 0) + 1

    for op, count in sorted(opcode_count.items(), key=lambda x: x[1], reverse=True):
        constructs = [name for name, ops in missing_by_construct.items() if op in ops]
        print(f"\n{op} (appears in {count} constructs):")
        print(f"  Used by: {', '.join(constructs)}")


def main():
    import argparse

    parser = argparse.ArgumentParser(description="Visual bytecode comparison tool")
    parser.add_argument("file", nargs="?", help="Python file to analyze")
    parser.add_argument("--simple", action="store_true", help="Run simple example")
    parser.add_argument(
        "--patterns", action="store_true", help="Analyze construct patterns"
    )

    args = parser.parse_args()

    if args.patterns:
        analyze_construct_patterns()
        return

    if args.simple or not args.file:
        # Simple example
        code = """
def greet(name):
    return f"Hello, {name}!"

result = greet("World")
print(result)
"""
        print("Analyzing simple example...")
    else:
        with open(args.file, "r") as f:
            code = f.read()
        print(f"Analyzing file: {args.file}")

    # Get instructions
    python_instrs = get_python_instructions(code)
    malwi_instrs = get_malwi_instructions(code)

    # Align and display
    aligned = align_instructions(python_instrs, malwi_instrs)
    print_side_by_side(code, aligned)

    # Summary of missing opcodes
    python_ops = set(instr.opname for instr in python_instrs)
    malwi_ops = set(instr.opname for instr in malwi_instrs)
    missing = python_ops - malwi_ops

    if missing:
        print(f"\n🔴 Missing opcodes: {', '.join(sorted(missing))}")
        print(
            "\nTo implement these opcodes, add them to the OpCode enum in ast_to_malwicode.py"
        )
        print("and handle them in the appropriate node type processing.")


if __name__ == "__main__":
    main()
