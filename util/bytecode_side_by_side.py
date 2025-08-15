#!/usr/bin/env python3
"""
Enhanced side-by-side bytecode renderer with improved visualization.

This tool provides a clear, aligned view of Python and malwi bytecode
to make differences immediately apparent.

Usage:
    python util/bytecode_side_by_side.py [test_file.py]
    python util/bytecode_side_by_side.py --code "x = 5; y = x + 3"
    python util/bytecode_side_by_side.py --html output.html  # Generate HTML output
"""

import dis
import sys
import tempfile
import os
import ast
from pathlib import Path
from typing import List, Tuple, Optional, Dict
import html as html_module
import difflib

# Add src to path to import malwi modules
sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

from common.ast_to_malwicode import ASTCompiler


class BytecodeRenderer:
    def __init__(self):
        self.python_instructions = []
        self.malwi_instructions = []
        self.aligned_pairs = []

    def analyze_code(self, code: str):
        """Analyze code and extract bytecode from both sources"""
        # Get Python bytecode
        self.python_instructions = self._get_python_bytecode(code)

        # Get malwi bytecode
        self.malwi_instructions = self._get_malwi_bytecode(code)

        # Align instructions
        self.aligned_pairs = self._align_bytecode()

    def _get_python_bytecode(self, code: str) -> List[Dict]:
        """Extract Python bytecode with all details"""
        compiled = compile(code, "<string>", "exec")

        instructions = []
        for instr in dis.get_instructions(compiled):
            instructions.append(
                {
                    "offset": instr.offset,
                    "opname": instr.opname,
                    "arg": instr.arg,
                    "argval": instr.argval,
                    "line_no": instr.starts_line,
                    "is_jump_target": instr.is_jump_target,
                }
            )

        return instructions

    def _get_malwi_bytecode(self, code: str) -> List[Dict]:
        """Extract malwi bytecode"""
        with tempfile.NamedTemporaryFile(mode="w", suffix=".py", delete=False) as f:
            f.write(code)
            temp_file = f.name

        try:
            compiler = ASTCompiler("python")
            code_objects = compiler.process_file(Path(temp_file))

            instructions = []
            offset = 0

            for code_obj in code_objects:
                # Add code object marker
                if code_obj.name != "<module>":
                    instructions.append(
                        {
                            "offset": offset,
                            "opname": f"[CodeObject: {code_obj.name}]",
                            "arg": None,
                            "argval": None,
                            "line_no": None,
                            "is_jump_target": False,
                            "is_marker": True,
                        }
                    )
                    offset += 2

                for instr in code_obj.byte_code:
                    instructions.append(
                        {
                            "offset": offset,
                            "opname": instr.opcode.name,
                            "arg": instr.arg,
                            "argval": instr.arg,
                            "line_no": None,
                            "is_jump_target": False,
                            "is_marker": False,
                        }
                    )
                    offset += 2

            return instructions
        finally:
            os.unlink(temp_file)

    def _align_bytecode(self) -> List[Tuple[Optional[Dict], Optional[Dict], str]]:
        """Align Python and malwi bytecode for comparison"""
        aligned = []

        # Create opname sequences for alignment
        python_ops = [i["opname"] for i in self.python_instructions]
        malwi_ops = [
            i["opname"]
            for i in self.malwi_instructions
            if not i.get("is_marker", False)
        ]

        # Use sequence matcher
        matcher = difflib.SequenceMatcher(None, python_ops, malwi_ops)

        p_idx = 0
        m_idx = 0

        for tag, p_start, p_end, m_start, m_end in matcher.get_opcodes():
            if tag == "equal":
                # Matching opcodes
                for i in range(p_end - p_start):
                    aligned.append(
                        (
                            self.python_instructions[p_start + i],
                            self.malwi_instructions[m_start + i],
                            "match",
                        )
                    )
                p_idx = p_end
                m_idx = m_end

            elif tag == "delete":
                # In Python but not in malwi
                for i in range(p_start, p_end):
                    aligned.append((self.python_instructions[i], None, "missing"))
                p_idx = p_end

            elif tag == "insert":
                # In malwi but not in Python
                for i in range(m_start, m_end):
                    aligned.append((None, self.malwi_instructions[i], "extra"))
                m_idx = m_end

            elif tag == "replace":
                # Different opcodes
                p_count = p_end - p_start
                m_count = m_end - m_start

                # Pair up what we can
                for i in range(min(p_count, m_count)):
                    aligned.append(
                        (
                            self.python_instructions[p_start + i],
                            self.malwi_instructions[m_start + i],
                            "different",
                        )
                    )

                # Handle remaining
                if p_count > m_count:
                    for i in range(m_count, p_count):
                        aligned.append(
                            (self.python_instructions[p_start + i], None, "missing")
                        )
                else:
                    for i in range(p_count, m_count):
                        aligned.append(
                            (None, self.malwi_instructions[m_start + i], "extra")
                        )

                p_idx = p_end
                m_idx = m_end

        return aligned

    def render_text(self, code: str) -> str:
        """Render as colored text output"""
        output = []

        # Header
        output.append("\n" + "=" * 120)
        output.append("SIDE-BY-SIDE BYTECODE COMPARISON")
        output.append("=" * 120)
        output.append("\nSource Code:")
        output.append("-" * 120)

        for i, line in enumerate(code.strip().split("\n"), 1):
            output.append(f"{i:3d} | {line}")

        output.append("-" * 120)

        # Statistics
        stats = self._calculate_stats()
        output.append(f"\nStatistics:")
        output.append(f"  Python: {stats['python_total']} instructions")
        output.append(f"  Malwi:  {stats['malwi_total']} instructions")
        output.append(
            f"  Matching: {stats['matching']} ({stats['match_percent']:.1f}%)"
        )
        output.append(
            f"  Missing:  {stats['missing']} ({stats['missing_percent']:.1f}%)"
        )
        output.append(f"  Extra:    {stats['extra']} ({stats['extra_percent']:.1f}%)")

        # Column headers
        output.append("\n" + "=" * 120)
        output.append(f"{'PYTHON BYTECODE':^58} │ {'MALWI BYTECODE':^58}")
        output.append(
            f"{'Offset  Op              Arg     Value':^58} │ {'Offset  Op              Arg     Value':^58}"
        )
        output.append("=" * 120)

        # Instructions
        for python_instr, malwi_instr, diff_type in self.aligned_pairs:
            python_str = (
                self._format_instruction(python_instr) if python_instr else " " * 58
            )
            malwi_str = (
                self._format_instruction(malwi_instr) if malwi_instr else " " * 58
            )

            # Color based on diff type
            if diff_type == "match":
                output.append(f"{python_str} │ {malwi_str}")
            elif diff_type == "missing":
                output.append(f"\033[91m{python_str}\033[0m │ {' ' * 58}")
            elif diff_type == "extra":
                output.append(f"{' ' * 58} │ \033[92m{malwi_str}\033[0m")
            elif diff_type == "different":
                output.append(f"\033[93m{python_str} │ {malwi_str}\033[0m")

        # Footer
        output.append("=" * 120)
        output.append("\nLegend:")
        output.append("  \033[91m█\033[0m Missing in malwi (red)")
        output.append("  \033[92m█\033[0m Extra in malwi (green)")
        output.append("  \033[93m█\033[0m Different opcodes (yellow)")

        # Missing opcodes summary
        missing_ops = self._get_missing_opcodes()
        if missing_ops:
            output.append(f"\nMissing opcodes: {', '.join(sorted(missing_ops))}")

        return "\n".join(output)

    def render_html(self, code: str) -> str:
        """Render as HTML with styling"""
        html = []

        # HTML header with CSS
        html.append("""
<!DOCTYPE html>
<html>
<head>
<style>
body { font-family: 'Consolas', 'Monaco', monospace; background: #1e1e1e; color: #d4d4d4; }
.container { max-width: 1200px; margin: 0 auto; padding: 20px; }
.code-block { background: #2d2d2d; padding: 15px; border-radius: 5px; margin: 10px 0; }
.stats { background: #2d2d2d; padding: 10px; border-radius: 5px; margin: 10px 0; }
table { width: 100%; border-collapse: collapse; }
th { background: #3d3d3d; padding: 10px; text-align: left; }
td { padding: 5px; border-bottom: 1px solid #3d3d3d; }
.match { color: #d4d4d4; }
.missing { color: #f48771; background: rgba(244, 135, 113, 0.1); }
.extra { color: #89d185; background: rgba(137, 209, 133, 0.1); }
.different { color: #f9c74f; background: rgba(249, 199, 79, 0.1); }
.line-number { color: #858585; }
.opcode { color: #569cd6; font-weight: bold; }
.arg { color: #ce9178; }
.marker { color: #c586c0; font-style: italic; }
</style>
</head>
<body>
<div class="container">
<h1>Bytecode Comparison</h1>
""")

        # Source code
        html.append("<h2>Source Code</h2>")
        html.append('<div class="code-block"><pre>')
        for i, line in enumerate(code.strip().split("\n"), 1):
            escaped_line = html_module.escape(line)
            html.append(f'<span class="line-number">{i:3d}</span> {escaped_line}')
        html.append("</pre></div>")

        # Statistics
        stats = self._calculate_stats()
        html.append("<h2>Statistics</h2>")
        html.append('<div class="stats">')
        html.append(f"<p>Python: {stats['python_total']} instructions</p>")
        html.append(f"<p>Malwi: {stats['malwi_total']} instructions</p>")
        html.append(
            f"<p>Matching: {stats['matching']} ({stats['match_percent']:.1f}%)</p>"
        )
        html.append(
            f"<p>Missing: {stats['missing']} ({stats['missing_percent']:.1f}%)</p>"
        )
        html.append(f"<p>Extra: {stats['extra']} ({stats['extra_percent']:.1f}%)</p>")
        html.append("</div>")

        # Bytecode table
        html.append("<h2>Bytecode Comparison</h2>")
        html.append("<table>")
        html.append("<tr><th>Python Bytecode</th><th>Malwi Bytecode</th></tr>")

        for python_instr, malwi_instr, diff_type in self.aligned_pairs:
            html.append(f'<tr class="{diff_type}">')

            # Python column
            html.append("<td>")
            if python_instr:
                html.append(self._format_html_instruction(python_instr))
            html.append("</td>")

            # Malwi column
            html.append("<td>")
            if malwi_instr:
                html.append(self._format_html_instruction(malwi_instr))
            html.append("</td>")

            html.append("</tr>")

        html.append("</table>")

        # Missing opcodes
        missing_ops = self._get_missing_opcodes()
        if missing_ops:
            html.append("<h2>Missing Opcodes</h2>")
            html.append('<div class="stats">')
            html.append(f"<p>{', '.join(sorted(missing_ops))}</p>")
            html.append("</div>")

        html.append("</div></body></html>")

        return "\n".join(html)

    def _format_instruction(self, instr: Dict) -> str:
        """Format instruction for text display"""
        if instr.get("is_marker", False):
            return f"       {instr['opname']:<51}"

        offset = f"{instr['offset']:6d}"
        opname = f"{instr['opname']:<15}"

        if instr["arg"] is not None:
            arg = f"{str(instr['arg']):<7}"
            if instr["argval"] is not None and instr["argval"] != instr["arg"]:
                argval = f"({str(instr['argval'])[:20]})"
            else:
                argval = ""
        else:
            arg = ""
            argval = ""

        line_marker = f"L{instr['line_no']}" if instr.get("line_no") else "  "
        jump_marker = ">" if instr.get("is_jump_target") else " "

        return f"{jump_marker}{offset} {line_marker} {opname} {arg} {argval}"

    def _format_html_instruction(self, instr: Dict) -> str:
        """Format instruction for HTML display"""
        if instr.get("is_marker", False):
            return f'<span class="marker">{html_module.escape(instr["opname"])}</span>'

        parts = []

        # Offset
        parts.append(f"{instr['offset']:6d}")

        # Line number
        if instr.get("line_no"):
            parts.append(f" L{instr['line_no']}")
        else:
            parts.append("    ")

        # Opcode
        parts.append(
            f' <span class="opcode">{html_module.escape(instr["opname"])}</span>'
        )

        # Arguments
        if instr["arg"] is not None:
            parts.append(
                f' <span class="arg">{html_module.escape(str(instr["arg"]))}</span>'
            )
            if instr["argval"] is not None and instr["argval"] != instr["arg"]:
                parts.append(f" ({html_module.escape(str(instr['argval'])[:20])})")

        return "".join(parts)

    def _calculate_stats(self) -> Dict:
        """Calculate comparison statistics"""
        stats = {
            "python_total": len(self.python_instructions),
            "malwi_total": len(
                [i for i in self.malwi_instructions if not i.get("is_marker", False)]
            ),
            "matching": sum(1 for _, _, t in self.aligned_pairs if t == "match"),
            "missing": sum(1 for _, _, t in self.aligned_pairs if t == "missing"),
            "extra": sum(1 for _, _, t in self.aligned_pairs if t == "extra"),
            "different": sum(1 for _, _, t in self.aligned_pairs if t == "different"),
        }

        total = len(self.aligned_pairs)
        if total > 0:
            stats["match_percent"] = (stats["matching"] / total) * 100
            stats["missing_percent"] = (stats["missing"] / total) * 100
            stats["extra_percent"] = (stats["extra"] / total) * 100
        else:
            stats["match_percent"] = 0
            stats["missing_percent"] = 0
            stats["extra_percent"] = 0

        return stats

    def _get_missing_opcodes(self) -> set:
        """Get set of missing opcodes"""
        python_ops = set(i["opname"] for i in self.python_instructions)
        malwi_ops = set(
            i["opname"]
            for i in self.malwi_instructions
            if not i.get("is_marker", False)
        )
        return python_ops - malwi_ops


def main():
    import argparse

    parser = argparse.ArgumentParser(
        description="Side-by-side bytecode comparison tool"
    )
    parser.add_argument("file", nargs="?", help="Python file to analyze")
    parser.add_argument("--code", "-c", help="Inline code to analyze")
    parser.add_argument("--html", help="Output as HTML to specified file")
    parser.add_argument(
        "--examples", action="store_true", help="Show example comparisons"
    )

    args = parser.parse_args()

    # Determine code to analyze
    if args.examples:
        examples = [
            ("Simple Assignment", "x = 5\ny = x + 3"),
            ("Function Call", "result = max(10, 20)"),
            ("List Comprehension", "squares = [x**2 for x in range(5)]"),
            (
                "If Statement",
                "x = 10\nif x > 5:\n    print('big')\nelse:\n    print('small')",
            ),
        ]

        for name, code in examples:
            print(f"\n{'=' * 50}")
            print(f"Example: {name}")
            print(f"{'=' * 50}")

            renderer = BytecodeRenderer()
            renderer.analyze_code(code)
            print(renderer.render_text(code))

        return

    if args.code:
        code = args.code
    elif args.file:
        with open(args.file, "r") as f:
            code = f.read()
    else:
        # Default example
        code = """
def greet(name):
    return f"Hello, {name}!"

result = greet("World")
print(result)
"""

    # Analyze code
    renderer = BytecodeRenderer()
    renderer.analyze_code(code)

    # Output
    if args.html:
        html_output = renderer.render_html(code)
        with open(args.html, "w") as f:
            f.write(html_output)
        print(f"HTML output written to {args.html}")
    else:
        print(renderer.render_text(code))


if __name__ == "__main__":
    main()
