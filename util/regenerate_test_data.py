#!/usr/bin/env python3
"""
Utility to regenerate test data for ast_to_malwicode tests.
This is useful when changes are made to the compiler that affect output format.
"""

import sys
import re
from pathlib import Path

# Add src to path
src_path = Path(__file__).parent.parent / "src"
sys.path.append(str(src_path))

from research.ast_to_malwicode import ASTCompiler


def normalize_paths_in_output(content: str, project_root: Path) -> str:
    """
    Normalize absolute paths in the output to relative paths from project root.
    This makes test files portable across different systems.
    """
    def replace_path(match):
        full_path = match.group(1)
        try:
            # Convert to Path and make relative to project root
            path_obj = Path(full_path)
            relative_path = path_obj.relative_to(project_root)
            return f"path={relative_path}"
        except (ValueError, OSError):
            # If can't make relative, keep original
            return match.group(0)
    
    # Pattern to match path=/absolute/path/to/file in CodeObject repr
    path_pattern = r'path=([^,)]+)'
    return re.sub(path_pattern, replace_path, content)


def generate_expected_output(language, input_file, output_file, format_mode="default"):
    """Generate expected output format for tests"""
    compiler = ASTCompiler(language)
    code_objects = compiler.process_file(Path(input_file))

    if format_mode == "mapped":
        # Generate mapped output format (same logic as tests)
        generated_string = "\n".join(
            code_obj.to_string(one_line=False) for code_obj in code_objects
        ).strip()
    else:
        # Generate default format (just the bytecode without headers)
        generated_string = "\n".join(
            code_obj.to_string(mapped=False, one_line=False)
            for code_obj in code_objects
        ).strip()

    # Normalize paths to be relative to project root
    project_root = Path(__file__).parent.parent
    generated_string = normalize_paths_in_output(generated_string, project_root)

    with open(output_file, "w") as f:
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
        format_mode="default",
    )

    generate_expected_output(
        "python",
        test_samples_dir / "python.py",
        test_samples_dir / "expected_python_output_mapped.txt",
        format_mode="mapped",
    )

    # Generate JavaScript test outputs
    print("\nJavaScript outputs:")
    generate_expected_output(
        "javascript",
        test_samples_dir / "javascript.js",
        test_samples_dir / "expected_javascript_output.txt",
        format_mode="default",
    )

    generate_expected_output(
        "javascript",
        test_samples_dir / "javascript.js",
        test_samples_dir / "expected_javascript_output_mapped.txt",
        format_mode="mapped",
    )

    print("\n" + "=" * 50)
    print("✅ All test data files regenerated successfully!")
    print("\nRun 'uv run pytest tests/test_ast_to_malwicode.py' to verify tests pass.")


if __name__ == "__main__":
    main()
