#!/usr/bin/env python3
"""
View and compare bytecode outputs for specific domains.
Useful for debugging specific language constructs.
"""

import sys
import argparse
from pathlib import Path
from typing import Optional


def display_bytecode(file_path: Path, max_lines: Optional[int] = None):
    """Display bytecode from a file with optional line limit"""
    if not file_path.exists():
        print(f"❌ File not found: {file_path}")
        return

    content = file_path.read_text()
    lines = content.strip().split("\n")

    if max_lines and len(lines) > max_lines:
        print(f"(Showing first {max_lines} lines of {len(lines)} total)")
        lines = lines[:max_lines]
        lines.append("...")

    for line in lines:
        if line.startswith("==="):
            print(f"\n\033[1;34m{line}\033[0m")  # Blue bold for headers
        elif any(op in line for op in ["LOAD_", "STORE_", "CALL", "RETURN", "JUMP"]):
            print(f"\033[32m{line}\033[0m")  # Green for important ops
        elif "ERROR" in line or "FAILED" in line:
            print(f"\033[31m{line}\033[0m")  # Red for errors
        else:
            print(line)


def compare_bytecode(raw_path: Path, mapped_path: Path):
    """Display raw and mapped bytecode side by side"""
    if not raw_path.exists() or not mapped_path.exists():
        print("❌ One or both files not found")
        return

    raw_lines = raw_path.read_text().strip().split("\n")
    mapped_lines = mapped_path.read_text().strip().split("\n")

    print(f"\n{'RAW BYTECODE':<50} | {'MAPPED BYTECODE'}")
    print("=" * 100)

    max_lines = max(len(raw_lines), len(mapped_lines))

    for i in range(max_lines):
        raw_line = raw_lines[i] if i < len(raw_lines) else ""
        mapped_line = mapped_lines[i] if i < len(mapped_lines) else ""

        # Truncate long lines
        if len(raw_line) > 48:
            raw_line = raw_line[:45] + "..."
        if len(mapped_line) > 48:
            mapped_line = mapped_line[:45] + "..."

        print(f"{raw_line:<50} | {mapped_line}")


def list_domains(language: str):
    """List all available domains for a language"""
    base_path = (
        Path(__file__).parent.parent
        / "tests"
        / "source_samples"
        / language
    )

    if not base_path.exists():
        print(f"❌ No bytecode outputs found for {language}")
        return

    domains = sorted([d.name for d in base_path.iterdir() if d.is_dir()])

    print(f"\nAvailable {language} domains:")
    for domain in domains:
        files = list((base_path / domain).glob("*_bytecode*.txt"))
        print(f"  - {domain} ({len(files)} bytecode files)")


def main():
    parser = argparse.ArgumentParser(
        description="View and compare domain bytecode outputs",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # List all domains
  python util/view_domain_bytecode.py --list

  # View mapped bytecode for Python control flow
  python util/view_domain_bytecode.py python control_flow --mapped

  # Compare raw and mapped for JavaScript functions
  python util/view_domain_bytecode.py javascript functions --compare

  # View first 20 lines of Python imports
  python util/view_domain_bytecode.py python imports --lines 20
        """,
    )

    parser.add_argument(
        "language",
        nargs="?",
        choices=["python", "javascript"],
        help="Programming language",
    )
    parser.add_argument(
        "domain", nargs="?", help="Domain name (e.g., control_flow, functions)"
    )
    parser.add_argument("--raw", action="store_true", help="Show raw bytecode")
    parser.add_argument("--mapped", action="store_true", help="Show mapped bytecode")
    parser.add_argument(
        "--compare", action="store_true", help="Compare raw and mapped side by side"
    )
    parser.add_argument(
        "--list", action="store_true", help="List all available domains"
    )
    parser.add_argument(
        "--lines", type=int, metavar="N", help="Show only first N lines"
    )
    parser.add_argument(
        "--file",
        metavar="NAME",
        help="Specific test file name (default: test_<domain>)",
    )

    args = parser.parse_args()

    # Handle list option
    if args.list:
        list_domains("python")
        list_domains("javascript")
        return

    # Require language and domain for other operations
    if not args.language or not args.domain:
        parser.error("Language and domain required (unless using --list)")

    # Build paths
    base_path = Path(__file__).parent.parent / "tests" / "source_samples"
    bytecode_dir = base_path / args.language / args.domain

    if not bytecode_dir.exists():
        print(f"❌ Domain not found: {args.language}/{args.domain}")
        list_domains(args.language)
        return

    # Determine file name
    file_prefix = args.file or f"test_{args.domain}"
    raw_file = bytecode_dir / f"{file_prefix}_bytecode.txt"
    mapped_file = bytecode_dir / f"{file_prefix}_bytecode_mapped.txt"

    # Default to mapped if no option specified
    if not args.raw and not args.mapped and not args.compare:
        args.mapped = True

    # Display bytecode
    print(f"\n{args.language.upper()} - {args.domain}")
    print("=" * 60)

    if args.compare:
        compare_bytecode(raw_file, mapped_file)
    else:
        if args.raw:
            print("\nRAW BYTECODE:")
            display_bytecode(raw_file, args.lines)

        if args.mapped:
            print("\nMAPPED BYTECODE:")
            display_bytecode(mapped_file, args.lines)


if __name__ == "__main__":
    main()
