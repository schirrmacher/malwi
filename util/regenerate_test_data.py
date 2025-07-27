#!/usr/bin/env python3
"""
Utility to regenerate test data for ast_to_malwicode tests.
This is useful when changes are made to the compiler that affect output format.
"""

import sys
from pathlib import Path

# Add src to path
src_path = Path(__file__).parent.parent / "src"
sys.path.append(str(src_path))

from research.ast_to_malwicode import ASTCompiler


def generate_expected_output(language, input_file, output_file, format_mode="default"):
    """Generate expected output format for tests"""
    compiler = ASTCompiler(language)
    code_objects = compiler.process_file(Path(input_file))
    
    if format_mode == "mapped":
        # Generate mapping output format using the new "mapped" format
        mapping_output_parts = []
        for i, code_obj in enumerate(code_objects):
            if i == 0:
                mapping_output_parts.append(f"Root CodeObject ({code_obj.name}) - Mapping:")
            else:
                mapping_output_parts.append(f"\n{code_obj.name} - Mapping:")

            # Add mapped representation using to_string with "mapped" format
            mapping_output_parts.append(code_obj.to_string(format_mode="mapped"))

        generated_string = "\n".join(mapping_output_parts).strip()
    else:
        # Generate default format (just the bytecode without headers)
        output_parts = []
        for code_obj in code_objects:
            output_parts.append(code_obj.to_string())
        generated_string = "\n".join(output_parts).strip()
    
    with open(output_file, 'w') as f:
        f.write(generated_string)
    
    print(f"✓ Generated {output_file}")


def main():
    """Regenerate all test data files"""
    test_samples_dir = Path(__file__).parent.parent / "tests" / "source_samples"
    
    print("Regenerating test data files...")
    print("=" * 50)
    
    # Generate Python test outputs
    print("\nPython outputs:")
    generate_expected_output(
        "python", 
        test_samples_dir / "python.py",
        test_samples_dir / "expected_python_output.txt",
        format_mode="default"
    )
    
    generate_expected_output(
        "python", 
        test_samples_dir / "python.py",
        test_samples_dir / "expected_python_output_mapped.txt",
        format_mode="mapped"
    )
    
    # Generate JavaScript test outputs
    print("\nJavaScript outputs:")
    generate_expected_output(
        "javascript", 
        test_samples_dir / "javascript.js",
        test_samples_dir / "expected_javascript_output.txt",
        format_mode="default"
    )
    
    generate_expected_output(
        "javascript", 
        test_samples_dir / "javascript.js",
        test_samples_dir / "expected_javascript_output_mapped.txt",
        format_mode="mapped"
    )
    
    print("\n" + "=" * 50)
    print("✅ All test data files regenerated successfully!")
    print("\nRun 'uv run pytest tests/test_ast_to_malwicode.py' to verify tests pass.")


if __name__ == "__main__":
    main()