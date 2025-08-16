#!/usr/bin/env python3
"""
Generate bytecode output files for each syntax domain.
This creates both raw and mapped bytecode outputs for easier debugging.
"""

import sys
from pathlib import Path

# Add src to path
sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

from common.bytecode import ASTCompiler


def generate_bytecode_for_file(
    compiler: ASTCompiler, source_file: Path, output_dir: Path
):
    """Generate both raw and mapped bytecode outputs for a single file"""

    # Process the file
    try:
        code_objects = compiler.process_file(source_file)
    except Exception as e:
        print(f"  ❌ Error processing {source_file.name}: {e}")
        return False

    # Create output filenames
    base_name = source_file.stem
    raw_output = output_dir / f"{base_name}_bytecode.txt"
    mapped_output = output_dir / f"{base_name}_bytecode_mapped.txt"

    # Generate raw bytecode output
    raw_lines = []
    for code_obj in code_objects:
        raw_lines.append(f"=== {code_obj.name} ===")
        raw_lines.append(code_obj.to_string(mapped=False, one_line=False))
        raw_lines.append("")

    # Generate mapped bytecode output
    mapped_lines = []
    for code_obj in code_objects:
        mapped_lines.append(f"=== {code_obj.name} ===")
        mapped_lines.append(code_obj.to_string(mapped=True, one_line=False))
        mapped_lines.append("")

    # Write files
    raw_output.write_text("\n".join(raw_lines))
    mapped_output.write_text("\n".join(mapped_lines))

    print(f"  ✓ Generated: {raw_output.name} and {mapped_output.name}")
    return True


def process_language_domains(language: str):
    """Process all domains for a given language"""
    print(f"\n{'=' * 60}")
    print(f"Processing {language.upper()} domains")
    print(f"{'=' * 60}")

    # Setup paths
    base_path = Path(__file__).parent.parent / "tests" / "source_samples"
    source_dir = base_path / language

    # Create compiler
    compiler = ASTCompiler(language)

    # Get all domain directories
    domains = sorted([d for d in source_dir.iterdir() if d.is_dir()])

    for domain_dir in domains:
        domain_name = domain_dir.name
        print(f"\n{domain_name}:")

        # Output files go in the same directory as source files

        # Process all files in the domain
        files = sorted(domain_dir.glob("*.py" if language == "python" else "*.js"))

        for source_file in files:
            generate_bytecode_for_file(compiler, source_file, domain_dir)


def main():
    """Generate bytecode outputs for all domains"""
    print("Generating bytecode outputs for all syntax domains...")

    # Process Python domains
    process_language_domains("python")

    # Process JavaScript domains
    process_language_domains("javascript")

    print("\n✅ Bytecode generation complete!")
    print("\nOutput structure:")
    print("  tests/source_samples/")
    print("    ├── python/               # Python source + bytecode")
    print("    │   ├── imports/")
    print("    │   │   ├── test_imports.py")
    print("    │   │   ├── test_imports_bytecode.txt")
    print("    │   │   └── test_imports_bytecode_mapped.txt")
    print("    │   └── ... (each domain)")
    print("    └── javascript/           # JavaScript source + bytecode")
    print("        └── ... (same structure)")
    print("\nEach domain directory contains:")
    print("  - *.py/*.js             # Source files")
    print("  - *_bytecode.txt        # Raw bytecode (numeric opcodes)")
    print("  - *_bytecode_mapped.txt # Mapped bytecode (readable names)")


if __name__ == "__main__":
    main()
