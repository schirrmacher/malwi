import pathlib
import logging
import argparse
from enum import Enum, auto
from pathlib import Path
from tree_sitter import Node
from typing import Optional, Any, List, Tuple

from tree_sitter import Parser, Language

# Import both language bindings
import tree_sitter_python as tspython
import tree_sitter_javascript as tsjavascript


def collect_files_by_extension(
    path: Path, accepted_extensions: List[str]
) -> Tuple[List[Path], int]:
    """
    Collects files from a path (file or directory) matching the given extensions.
    """
    files = []
    if not path.exists():
        return [], 0
    if path.is_file():
        if path.suffix in accepted_extensions:
            return [path], 1
        return [], 0
    # If it's a directory, search recursively
    for ext in accepted_extensions:
        files.extend(path.rglob(f"*{ext}"))
    return files, len(files)


# Add JavaScript to the dictionary of supported languages
LANGUAGES = {
    "python": tspython.language(),
    "javascript": tsjavascript.language(),
}

PARSER_INSTANCE: Optional[Parser] = None
CURRENT_LANGUAGE: Optional[str] = None


class OpCode(Enum):
    """
    Defines the set of all possible bytecode operations for Malwicode.
    """

    LOAD_CONST = auto()
    LOAD_NAME = auto()
    STORE_NAME = auto()
    BINARY_ADD = auto()
    BINARY_SUBTRACT = auto()
    BINARY_MULTIPLY = auto()
    BINARY_DIVIDE = auto()
    BINARY_OPERATION = auto()  # Fallback for unhandled operators
    CALL_FUNCTION = auto()
    MAKE_FUNCTION = auto()
    RETURN_VALUE = auto()


def get_parser_instance(language_name: str) -> Optional[Parser]:
    """
    Gets a parser instance for the specified language. Re-initializes the
    parser only if the language changes.
    """
    global PARSER_INSTANCE, CURRENT_LANGUAGE
    if PARSER_INSTANCE is None or CURRENT_LANGUAGE != language_name:
        language_object = LANGUAGES.get(language_name)
        if language_object is None:
            logging.warning(f"No language object found for: {language_name}")
            CURRENT_LANGUAGE = PARSER_INSTANCE = None
            return None
        try:
            # This logic is specific to your environment/library version.
            PARSER_INSTANCE = Parser(Language(language_object))
            CURRENT_LANGUAGE = language_name
        except Exception as e:
            CURRENT_LANGUAGE = PARSER_INSTANCE = None
            logging.warning(f"{language_name} could not be loaded: {e}")
    return PARSER_INSTANCE


class ASTCompiler:
    """
    Compiles a tree-sitter AST from Python or JavaScript into "Malwicode".
    """

    @classmethod
    def treesitter_ast_to_malwicode(
        cls, root_node: Node, source_code_bytes: bytes
    ) -> List[Tuple[OpCode, Any]]:
        """
        Public method to initiate the compilation of an AST to Malwicode.
        """
        return cls._generate_bytecode(root_node, source_code_bytes)

    @classmethod
    def _get_node_text(cls, node: Node, source_code_bytes: bytes) -> str:
        """Helper to extract text from a node."""
        return source_code_bytes[node.start_byte : node.end_byte].decode(
            "utf-8", errors="replace"
        )

    @classmethod
    def _generate_bytecode(
        cls, node: Node, source_code_bytes: bytes
    ) -> List[Tuple[OpCode, Any]]:
        """
        Recursively traverses a Python or JavaScript AST and generates bytecode.
        """
        bytecode = []
        node_type = node.type

        binary_operator_mapping = {
            "+": OpCode.BINARY_ADD,
            "-": OpCode.BINARY_SUBTRACT,
            "*": OpCode.BINARY_MULTIPLY,
            "/": OpCode.BINARY_DIVIDE,
        }

        # --- Handle Literals and Identifiers (often same across languages) ---
        if node_type in ["integer", "float", "number"]:  # JS uses "number"
            bytecode.append(
                (OpCode.LOAD_CONST, float(cls._get_node_text(node, source_code_bytes)))
            )
        elif node_type == "string":
            str_content = cls._get_node_text(node, source_code_bytes)
            bytecode.append((OpCode.LOAD_CONST, str_content))
        elif node_type == "identifier":
            bytecode.append(
                (OpCode.LOAD_NAME, cls._get_node_text(node, source_code_bytes))
            )

        # --- Handle Expressions and Calls ---
        elif node_type in [
            "binary_operator",
            "binary_expression",
        ]:  # PY: binary_operator, JS: binary_expression
            bytecode.extend(
                cls._generate_bytecode(
                    node.child_by_field_name("left"), source_code_bytes
                )
            )
            bytecode.extend(
                cls._generate_bytecode(
                    node.child_by_field_name("right"), source_code_bytes
                )
            )
            op_node = node.child_by_field_name("operator")
            if op_node:
                op_text = cls._get_node_text(op_node, source_code_bytes)
                op_code = binary_operator_mapping.get(op_text, OpCode.BINARY_OPERATION)
                bytecode.append((op_code, None))

        elif node_type in ["call", "call_expression"]:  # PY: call, JS: call_expression
            func_node = node.child_by_field_name("function")
            args_node = node.child_by_field_name("arguments")
            if func_node:
                bytecode.extend(cls._generate_bytecode(func_node, source_code_bytes))

            arg_count = 0
            if args_node:
                for arg in args_node.children:
                    # Ignore punctuation
                    if arg.type not in [",", "(", ")"]:
                        bytecode.extend(cls._generate_bytecode(arg, source_code_bytes))
                        arg_count += 1
            bytecode.append((OpCode.CALL_FUNCTION, arg_count))

        # --- Handle Statements ---
        elif node_type in [
            "assignment",
            "assignment_expression",
        ]:  # PY: assignment, JS: assignment_expression
            bytecode.extend(
                cls._generate_bytecode(
                    node.child_by_field_name("right"), source_code_bytes
                )
            )
            var_name = cls._get_node_text(
                node.child_by_field_name("left"), source_code_bytes
            )
            bytecode.append((OpCode.STORE_NAME, var_name))

        # JS variable declaration: var x = 10;
        elif node_type == "variable_declarator":
            if node.child_by_field_name("value"):
                bytecode.extend(
                    cls._generate_bytecode(
                        node.child_by_field_name("value"), source_code_bytes
                    )
                )
                var_name = cls._get_node_text(
                    node.child_by_field_name("name"), source_code_bytes
                )
                bytecode.append((OpCode.STORE_NAME, var_name))

        elif node_type == "return_statement":
            # Handle explicit return statements in both languages
            if node.child_count > 1:
                # Assumes the value is the second child after the 'return' keyword
                return_val_node = node.children[1]
                bytecode.extend(
                    cls._generate_bytecode(return_val_node, source_code_bytes)
                )
            bytecode.append((OpCode.RETURN_VALUE, None))

        # --- Handle Function and Program Structure ---
        elif node_type in [
            "function_definition",
            "function_declaration",
        ]:  # PY: function_definition, JS: function_declaration
            func_name = cls._get_node_text(
                node.child_by_field_name("name"), source_code_bytes
            )
            body_node = node.child_by_field_name("body")

            func_body_bytecode = cls._generate_bytecode(body_node, source_code_bytes)
            # Add an implicit return if one is not already present
            if (
                not func_body_bytecode
                or func_body_bytecode[-1][0] != OpCode.RETURN_VALUE
            ):
                func_body_bytecode.append((OpCode.RETURN_VALUE, None))

            bytecode.append((OpCode.MAKE_FUNCTION, func_body_bytecode))
            bytecode.append((OpCode.STORE_NAME, func_name))

        # --- Block, Module, and Program Handling ---
        elif node_type in ["block", "module", "program"]:  # JS root node is "program"
            for child in node.children:
                bytecode.extend(cls._generate_bytecode(child, source_code_bytes))

        # Fallback for unhandled nodes: traverse children to not miss anything
        else:
            for child in node.named_children:
                bytecode.extend(cls._generate_bytecode(child, source_code_bytes))

        return bytecode

    @classmethod
    def bytes_to_treesitter_ast(
        cls, source_code_bytes: bytes, file_path: str, language: str
    ) -> Node | None:
        parser = get_parser_instance(language)
        if parser is None:
            logging.warning(
                f"No parser available for language: {language} for file {file_path}"
            )
            return None
        try:
            tree = parser.parse(source_code_bytes)
        except Exception as e:
            logging.warning(f"Parsing error of file {file_path}: {e}")
            return None
        return tree.root_node


def process_file(file_path: Path, language: str) -> List[Any]:
    """Processes a single file to generate and print its Malwicode."""
    print(f"--- Processing {language.capitalize()} File: {file_path.name} ---")
    try:
        source_code = file_path.read_text(encoding="utf-8", errors="replace")
        source_code_bytes = source_code.encode("utf-8", errors="replace")

        ast = ASTCompiler.bytes_to_treesitter_ast(
            source_code_bytes=source_code_bytes,
            file_path=str(file_path),
            language=language,
        )

        if ast:
            malwicode = ASTCompiler.treesitter_ast_to_malwicode(
                root_node=ast, source_code_bytes=source_code_bytes
            )

            print("Generated Malwicode:")
            for i, (opcode, arg) in enumerate(malwicode):
                if isinstance(arg, list):
                    print(f"{i:04d}: {opcode.name}")
                    for j, (sub_op, sub_arg) in enumerate(arg):
                        print(
                            f"    {j:04d}: {sub_op.name:<20} {sub_arg if sub_arg is not None else ''}"
                        )
                else:
                    print(
                        f"{i:04d}: {opcode.name:<20} {arg if arg is not None else ''}"
                    )

            print("-" * (35 + len(str(file_path.name))))
            return malwicode

    except Exception as e:
        logging.error(f"Failed to process {file_path}: {e}")

    return []


def main() -> None:
    """
    Main function to parse arguments, collect files, and compile them.
    Detects language based on file extension.
    """
    parser = argparse.ArgumentParser(
        description="A tool to parse source files (Python, JS) and compile them to dummy bytecode."
    )
    parser.add_argument(
        "input_path",
        type=Path,
        help="The path to the source file or directory to compile.",
    )
    parser.add_argument(
        "--extensions",
        nargs="+",
        default=[".py", ".js"],  # Added .js to defaults
        help="A list of file extensions to process (e.g., .py .js).",
    )
    args = parser.parse_args()

    source_files, sources_count = collect_files_by_extension(
        args.input_path, accepted_extensions=args.extensions
    )

    if sources_count == 0:
        print(f"No files with extensions {args.extensions} found in {args.input_path}")
        return

    print(f"Found {sources_count} file(s) to process...")
    for source in source_files:
        # Detect language and process the file
        lang = None
        if source.suffix == ".py":
            lang = "python"
        elif source.suffix == ".js":
            lang = "javascript"

        if lang:
            process_file(source, lang)
        else:
            print(f"Skipping unsupported file extension: {source.name}")


if __name__ == "__main__":
    main()
