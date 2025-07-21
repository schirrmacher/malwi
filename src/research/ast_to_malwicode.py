import pathlib
import logging
import argparse
from enum import Enum, auto
from pathlib import Path
from tree_sitter import Node
from typing import Optional, Any, List, Tuple, Dict

from tree_sitter import Parser, Language

# Import both language bindings
import tree_sitter_python as tspython
import tree_sitter_javascript as tsjavascript


class CodeObject:
    """
    A container for a compiled piece of code, including its bytecode,
    source, and location.
    """

    def __init__(
        self,
        name: str,
        byte_code: List[Tuple[Enum, Any]],
        source_code: str,
        path: Path,
        location: Tuple[int, int],
    ):
        self.name = name
        self.byte_code = byte_code
        self.source_code = source_code
        self.path = path
        self.location = location

    def __repr__(self) -> str:
        return (
            f"CodeObject(name={self.name}, path={self.path}, location={self.location})"
        )

    def to_string(self, indent_level: int = 0) -> str:
        """
        Formats the bytecode of this CodeObject into a readable,
        indented string, normalizing jump addresses for consistent output.
        """
        result_lines = []
        indent = "    " * indent_level
        for opcode, arg in self.byte_code:
            # Normalize jump targets for consistent test output
            if opcode in (OpCode.POP_JUMP_IF_FALSE, OpCode.JUMP_FORWARD):
                arg_str = "<JUMP_TARGET>"
            elif isinstance(arg, CodeObject):
                # Handle nested function/class by recursively calling its own to_string
                result_lines.append(f"{indent}{opcode.name:<20} <{arg.name}>")
                result_lines.append(arg.to_string(indent_level + 1))
                continue  # Skip the rest of the loop for this item
            else:
                arg_str = str(arg) if arg is not None else ""

            result_lines.append(f"{indent}{opcode.name:<20} {arg_str.strip()}")

        return "\n".join(result_lines)


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
    MAKE_CLASS = auto()
    RETURN_VALUE = auto()
    POP_JUMP_IF_FALSE = auto()
    JUMP_FORWARD = auto()
    GET_ITER = auto()
    FOR_ITER = auto()
    BUILD_LIST = auto()
    BUILD_TUPLE = auto()
    BUILD_SET = auto()
    BUILD_MAP = auto()
    STORE_SUBSCR = auto()
    UNARY_NEGATIVE = auto()
    UNARY_NOT = auto()
    UNARY_INVERT = auto()
    IMPORT_NAME = auto()
    IMPORT_FROM = auto()
    EXPORT_DEFAULT = auto()
    EXPORT_NAMED = auto()


class ASTCompiler:
    """
    Compiles a tree-sitter AST from Python or JavaScript into "Malwicode".
    An instance of the compiler is tied to a specific language.
    """

    # Language definitions are now a class property
    SUPPORTED_LANGUAGES = {
        "python": tspython.language(),
        "javascript": tsjavascript.language(),
    }

    def __init__(self, language: str):
        """
        Initializes the compiler for a specific language.
        """
        self.language_name = language
        language_object = self.SUPPORTED_LANGUAGES.get(language)

        if language_object is None:
            raise ValueError(f"Language '{language}' is not supported.")

        # Adapted to use the requested Parser API
        self.parser = Parser(Language(language_object))

    def treesitter_ast_to_malwicode(
        self, root_node: Node, source_code_bytes: bytes, file_path: Path
    ) -> CodeObject:
        """
        Public method to initiate the compilation of an AST to a CodeObject.
        """
        source_code = source_code_bytes.decode("utf-8", errors="replace")
        location = (root_node.start_point[0] + 1, root_node.end_point[0] + 1)
        bytecode = self._generate_bytecode(root_node, source_code_bytes, file_path)
        return CodeObject(
            name="<module>",
            byte_code=bytecode,
            source_code=source_code,
            path=file_path,
            location=location,
        )

    def _get_node_text(self, node: Node, source_code_bytes: bytes) -> str:
        """Helper to extract text from a node."""
        return source_code_bytes[node.start_byte : node.end_byte].decode(
            "utf-8", errors="replace"
        )

    def _generate_bytecode(
        self, node: Node, source_code_bytes: bytes, file_path: Path
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
            ">": OpCode.BINARY_OPERATION,
        }

        # --- Handle Literals and Identifiers ---
        if node_type in ["integer", "float", "number"]:
            text = self._get_node_text(node, source_code_bytes)
            try:
                # Handle complex numbers (Python) and BigInt (JavaScript)
                if text.endswith("j") or text.endswith("J"):
                    # Python complex number - convert to float representation
                    # For malware analysis, we just need numeric representation
                    numeric_part = text[:-1]
                    if numeric_part:
                        value = float(numeric_part)
                    else:
                        value = 1.0  # 'j' alone represents 1j
                elif text.endswith("n"):
                    # JavaScript BigInt - strip the 'n' and convert to float
                    value = float(text[:-1])
                else:
                    # Regular integer or float
                    value = float(text)
                bytecode.append((OpCode.LOAD_CONST, value))
            except ValueError:
                # Fallback: treat as string if conversion fails
                bytecode.append((OpCode.LOAD_CONST, text))
        elif node_type == "string":
            str_content = self._get_node_text(node, source_code_bytes)
            bytecode.append((OpCode.LOAD_CONST, str_content))
        elif node_type == "identifier":
            bytecode.append(
                (OpCode.LOAD_NAME, self._get_node_text(node, source_code_bytes))
            )
        # Boolean and None literals
        elif node_type in ["true", "false"]:
            bytecode.append((OpCode.LOAD_CONST, node_type == "true"))
        elif node_type in ["none", "null"]:
            bytecode.append((OpCode.LOAD_CONST, None))
        elif node_type == "ellipsis":
            bytecode.append((OpCode.LOAD_CONST, "..."))

        # --- Handle Data Structures ---
        elif node_type in ["list", "array"]:
            element_count = 0
            for element in node.children:
                if element.type not in ["[", "]", ","]:
                    bytecode.extend(
                        self._generate_bytecode(element, source_code_bytes, file_path)
                    )
                    element_count += 1
            bytecode.append((OpCode.BUILD_LIST, element_count))
        elif node_type == "tuple":
            element_count = 0
            for element in node.children:
                if element.type not in ["(", ")", ","]:
                    bytecode.extend(
                        self._generate_bytecode(element, source_code_bytes, file_path)
                    )
                    element_count += 1
            bytecode.append((OpCode.BUILD_TUPLE, element_count))
        elif node_type == "set":
            element_count = 0
            for element in node.children:
                if element.type not in ["{", "}", ","]:
                    bytecode.extend(
                        self._generate_bytecode(element, source_code_bytes, file_path)
                    )
                    element_count += 1
            bytecode.append((OpCode.BUILD_SET, element_count))
        elif node_type in ["dictionary", "object"]:
            pair_count = 0
            for pair in node.children:
                if pair.type in [
                    "pair",
                    "property_identifier",
                ]:  # JS uses property_identifier for {key: val} shorthand
                    key_node = pair.child_by_field_name("key") or (
                        pair if pair.type == "property_identifier" else None
                    )
                    value_node = pair.child_by_field_name("value") or key_node

                    if key_node:
                        bytecode.extend(
                            self._generate_bytecode(
                                key_node,
                                source_code_bytes,
                                file_path,
                            )
                        )
                        bytecode.extend(
                            self._generate_bytecode(
                                value_node,
                                source_code_bytes,
                                file_path,
                            )
                        )
                        pair_count += 1
            bytecode.append((OpCode.BUILD_MAP, pair_count))

        # --- Handle Expressions and Calls ---
        elif node_type in ["binary_operator", "binary_expression"]:
            bytecode.extend(
                self._generate_bytecode(
                    node.child_by_field_name("left"), source_code_bytes, file_path
                )
            )
            bytecode.extend(
                self._generate_bytecode(
                    node.child_by_field_name("right"), source_code_bytes, file_path
                )
            )
            op_node = node.child_by_field_name("operator")
            if op_node:
                op_text = self._get_node_text(op_node, source_code_bytes)
                op_code = binary_operator_mapping.get(op_text, OpCode.BINARY_OPERATION)
                bytecode.append((op_code, None))
        elif node_type in ["unary_operator", "unary_expression"]:
            operand_node = node.child_by_field_name("operand") or node.children[-1]
            bytecode.extend(
                self._generate_bytecode(operand_node, source_code_bytes, file_path)
            )
            op_node = node.child_by_field_name("operator") or node.children[0]
            if op_node:
                op_text = self._get_node_text(op_node, source_code_bytes)
                if op_text in ["-", "+"]:
                    bytecode.append((OpCode.BINARY_OPERATION, None))  # Unary plus/minus
                else:
                    bytecode.append((OpCode.BINARY_OPERATION, None))  # Other unary ops
        elif node_type in ["boolean_operator", "logical_expression"]:
            # Handle 'and', 'or', '&&', '||' operators
            left_node = node.child_by_field_name("left")
            right_node = node.child_by_field_name("right")
            if left_node and right_node:
                bytecode.extend(
                    self._generate_bytecode(left_node, source_code_bytes, file_path)
                )
                bytecode.extend(
                    self._generate_bytecode(right_node, source_code_bytes, file_path)
                )
                bytecode.append((OpCode.BINARY_OPERATION, None))
        elif node_type in ["comparison_operator"]:
            # Handle comparison chains like 'a < b < c'
            for child in node.named_children:
                bytecode.extend(
                    self._generate_bytecode(child, source_code_bytes, file_path)
                )
            bytecode.append((OpCode.BINARY_OPERATION, None))
        elif node_type in ["not_operator"]:
            operand_node = node.child_by_field_name("operand") or node.children[-1]
            bytecode.extend(
                self._generate_bytecode(operand_node, source_code_bytes, file_path)
            )
            bytecode.append((OpCode.BINARY_OPERATION, None))

        elif node_type in ["call", "call_expression"]:
            func_node = node.child_by_field_name("function")
            args_node = node.child_by_field_name("arguments")
            if func_node:
                bytecode.extend(
                    self._generate_bytecode(func_node, source_code_bytes, file_path)
                )

            arg_count = 0
            if args_node:
                for arg in args_node.children:
                    if arg.type not in [",", "(", ")"]:
                        bytecode.extend(
                            self._generate_bytecode(arg, source_code_bytes, file_path)
                        )
                        arg_count += 1
            bytecode.append((OpCode.CALL_FUNCTION, arg_count))

        # --- Handle Statements ---
        elif node_type in [
            "assignment",
            "assignment_expression",
            "variable_declarator",
        ]:
            # This handles python `a=b`, JS `a=b`, and JS `var a=b`
            value_node = node.child_by_field_name("right") or node.child_by_field_name(
                "value"
            )
            name_node = node.child_by_field_name("left") or node.child_by_field_name(
                "name"
            )

            if value_node and name_node:
                bytecode.extend(
                    self._generate_bytecode(value_node, source_code_bytes, file_path)
                )
                var_name = self._get_node_text(name_node, source_code_bytes)
                bytecode.append((OpCode.STORE_NAME, var_name))

        elif node_type == "return_statement":
            if node.child_count > 1 and node.children[1].type not in [";"]:
                return_val_node = node.children[1]
                bytecode.extend(
                    self._generate_bytecode(
                        return_val_node, source_code_bytes, file_path
                    )
                )
            bytecode.append((OpCode.RETURN_VALUE, None))

        # Additional statement types
        elif node_type == "augmented_assignment":
            # Handle +=, -=, *=, etc.
            target_node = node.child_by_field_name("left")
            value_node = node.child_by_field_name("right")
            if target_node and value_node:
                # Load current value
                bytecode.extend(
                    self._generate_bytecode(target_node, source_code_bytes, file_path)
                )
                # Load new value
                bytecode.extend(
                    self._generate_bytecode(value_node, source_code_bytes, file_path)
                )
                # Perform operation
                bytecode.append((OpCode.BINARY_OPERATION, None))
                # Store result
                var_name = self._get_node_text(target_node, source_code_bytes)
                bytecode.append((OpCode.STORE_NAME, var_name))

        elif node_type == "pass_statement":
            # Pass is a no-op, but we'll add a placeholder
            pass

        elif node_type == "break_statement":
            bytecode.append((OpCode.BINARY_OPERATION, None))  # Placeholder for break

        elif node_type == "continue_statement":
            bytecode.append((OpCode.BINARY_OPERATION, None))  # Placeholder for continue

        elif node_type == "assert_statement":
            # Process the assertion condition
            condition_node = node.children[1] if len(node.children) > 1 else None
            if condition_node:
                bytecode.extend(
                    self._generate_bytecode(
                        condition_node, source_code_bytes, file_path
                    )
                )
            bytecode.append((OpCode.BINARY_OPERATION, None))  # Placeholder for assert

        elif node_type in ["raise_statement", "throw_statement"]:
            # Process the exception/error to raise
            if len(node.children) > 1:
                exception_node = node.children[1]
                bytecode.extend(
                    self._generate_bytecode(
                        exception_node, source_code_bytes, file_path
                    )
                )
            bytecode.append(
                (OpCode.BINARY_OPERATION, None)
            )  # Placeholder for raise/throw

        elif node_type in [
            "import_statement",
            "import_from_statement",
            "import_declaration",
        ]:
            # Process import - for malware analysis, we track the imported names
            # Handles both Python imports and JavaScript ES6 imports
            for child in node.named_children:
                if child.type == "identifier" or child.type == "dotted_name":
                    # Python direct imports
                    name = self._get_node_text(child, source_code_bytes)
                    if node_type == "import_statement":
                        bytecode.append((OpCode.IMPORT_NAME, name))
                    elif node_type == "import_from_statement":
                        bytecode.append((OpCode.IMPORT_FROM, name))
                    else:  # import_declaration (JavaScript)
                        bytecode.append((OpCode.IMPORT_NAME, name))
                elif child.type == "import_clause":
                    # JavaScript ES6 import clause - handle different import patterns
                    for import_child in child.named_children:
                        if import_child.type == "identifier":
                            # Default import: import React from 'react'
                            name = self._get_node_text(import_child, source_code_bytes)
                            bytecode.append((OpCode.IMPORT_NAME, name))
                        elif import_child.type == "named_imports":
                            # Named imports: import { x, y } from 'module'
                            for specifier in import_child.named_children:
                                if specifier.type == "import_specifier":
                                    for spec_child in specifier.named_children:
                                        if spec_child.type == "identifier":
                                            name = self._get_node_text(
                                                spec_child, source_code_bytes
                                            )
                                            bytecode.append((OpCode.IMPORT_FROM, name))
                        elif import_child.type == "namespace_import":
                            # Wildcard import: import * as fs from 'fs'
                            for namespace_child in import_child.named_children:
                                if namespace_child.type == "identifier":
                                    name = self._get_node_text(
                                        namespace_child, source_code_bytes
                                    )
                                    bytecode.append((OpCode.IMPORT_NAME, name))
                elif child.type == "aliased_import":
                    # Handle "import x as y" or "from x import y as z"
                    # Extract both the original and alias names
                    for grandchild in child.named_children:
                        if grandchild.type in ["identifier", "dotted_name"]:
                            name = self._get_node_text(grandchild, source_code_bytes)
                            if node_type == "import_statement":
                                bytecode.append((OpCode.IMPORT_NAME, name))
                            elif node_type == "import_from_statement":
                                bytecode.append((OpCode.IMPORT_FROM, name))
                            else:  # import_declaration (JavaScript)
                                bytecode.append((OpCode.IMPORT_NAME, name))
                elif child.type == "import_specifier":
                    # Handle JavaScript import specifiers like "import { x, y } from 'module'" (fallback)
                    for grandchild in child.named_children:
                        if grandchild.type == "identifier":
                            name = self._get_node_text(grandchild, source_code_bytes)
                            bytecode.append((OpCode.IMPORT_FROM, name))
                elif child.type == "string":
                    # Handle the module path in imports
                    module_path = self._get_node_text(child, source_code_bytes)
                    bytecode.append((OpCode.LOAD_CONST, module_path))
                else:
                    # Skip processing other children to avoid duplicating imports
                    pass

        elif node_type in ["export_statement", "export_default"]:
            # Process exports - for malware analysis, we track exported names
            # Handle both named exports and default exports
            for child in node.named_children:
                if child.type == "identifier":
                    name = self._get_node_text(child, source_code_bytes)
                    if node_type == "export_default":
                        bytecode.append((OpCode.EXPORT_DEFAULT, name))
                    else:
                        bytecode.append((OpCode.EXPORT_NAMED, name))
                elif child.type == "function_declaration":
                    # Handle export function name() {}
                    func_name = None
                    for grandchild in child.named_children:
                        if grandchild.type == "identifier":
                            func_name = self._get_node_text(
                                grandchild, source_code_bytes
                            )
                            break
                    if func_name:
                        bytecode.append((OpCode.EXPORT_NAMED, func_name))
                    bytecode.extend(
                        self._generate_bytecode(child, source_code_bytes, file_path)
                    )
                elif child.type == "variable_declaration":
                    # Handle export const/let/var declarations
                    for grandchild in child.named_children:
                        if grandchild.type == "variable_declarator":
                            for great_grandchild in grandchild.named_children:
                                if great_grandchild.type == "identifier":
                                    name = self._get_node_text(
                                        great_grandchild, source_code_bytes
                                    )
                                    bytecode.append((OpCode.EXPORT_NAMED, name))
                    bytecode.extend(
                        self._generate_bytecode(child, source_code_bytes, file_path)
                    )
                else:
                    bytecode.extend(
                        self._generate_bytecode(child, source_code_bytes, file_path)
                    )

        elif node_type in ["global_statement", "nonlocal_statement"]:
            # Process global/nonlocal declarations
            for child in node.named_children:
                if child.type == "identifier":
                    name = self._get_node_text(child, source_code_bytes)
                    bytecode.append((OpCode.LOAD_NAME, name))

        elif node_type == "delete_statement":
            # Process delete targets
            for child in node.named_children:
                bytecode.extend(
                    self._generate_bytecode(child, source_code_bytes, file_path)
                )
            bytecode.append((OpCode.BINARY_OPERATION, None))  # Placeholder for delete

        # --- Control Flow ---
        elif node_type == "if_statement":
            condition_node = node.child_by_field_name("condition")
            consequence_node = node.child_by_field_name("consequence")
            alternative_node = node.child_by_field_name("alternative")

            bytecode.extend(
                self._generate_bytecode(condition_node, source_code_bytes, file_path)
            )

            jump_instr_index = len(bytecode)
            bytecode.append((OpCode.POP_JUMP_IF_FALSE, -1))

            consequence_bytecode = self._generate_bytecode(
                consequence_node, source_code_bytes, file_path
            )
            bytecode.extend(consequence_bytecode)

            if alternative_node:
                jump_over_else_index = len(bytecode)
                bytecode.append((OpCode.JUMP_FORWARD, -1))
                # Set jump target for the initial if to point after the 'then' block
                bytecode[jump_instr_index] = (OpCode.POP_JUMP_IF_FALSE, len(bytecode))

                alternative_bytecode = self._generate_bytecode(
                    alternative_node, source_code_bytes, file_path
                )
                bytecode.extend(alternative_bytecode)
                # Set the jump to point after the 'else' block
                bytecode[jump_over_else_index] = (OpCode.JUMP_FORWARD, len(bytecode))

            else:
                # If no 'else', the jump just goes to the end of the 'then' block
                bytecode[jump_instr_index] = (OpCode.POP_JUMP_IF_FALSE, len(bytecode))

        elif node_type in ["for_statement", "for_in_statement"]:
            # Process for loops
            iterable_node = node.child_by_field_name(
                "right"
            ) or node.child_by_field_name("iterable")
            body_node = node.child_by_field_name("body")

            if iterable_node:
                bytecode.extend(
                    self._generate_bytecode(iterable_node, source_code_bytes, file_path)
                )

            if body_node:
                bytecode.extend(
                    self._generate_bytecode(body_node, source_code_bytes, file_path)
                )

        elif node_type == "while_statement":
            # Process while loops
            condition_node = node.child_by_field_name("condition")
            body_node = node.child_by_field_name("body")

            if condition_node:
                bytecode.extend(
                    self._generate_bytecode(
                        condition_node, source_code_bytes, file_path
                    )
                )
                bytecode.append((OpCode.POP_JUMP_IF_FALSE, len(bytecode) + 2))

            if body_node:
                bytecode.extend(
                    self._generate_bytecode(body_node, source_code_bytes, file_path)
                )

        elif node_type in ["try_statement"]:
            # Process try/except/finally blocks
            body_node = node.child_by_field_name("body")
            if body_node:
                bytecode.extend(
                    self._generate_bytecode(body_node, source_code_bytes, file_path)
                )

            # Process except clauses
            for child in node.children:
                if child.type in ["except_clause", "catch_clause"]:
                    bytecode.extend(
                        self._generate_bytecode(child, source_code_bytes, file_path)
                    )
                elif child.type == "finally_clause":
                    bytecode.extend(
                        self._generate_bytecode(child, source_code_bytes, file_path)
                    )

        elif node_type == "with_statement":
            # Process with statements
            for child in node.children:
                if child.type == "with_item":
                    bytecode.extend(
                        self._generate_bytecode(child, source_code_bytes, file_path)
                    )

            body_node = node.child_by_field_name("body")
            if body_node:
                bytecode.extend(
                    self._generate_bytecode(body_node, source_code_bytes, file_path)
                )

        elif node_type in ["lambda", "arrow_function"]:
            # Process lambda/arrow functions
            body_node = node.child_by_field_name("body")
            if body_node:
                func_body_bytecode = self._generate_bytecode(
                    body_node, source_code_bytes, file_path
                )
                if (
                    not func_body_bytecode
                    or func_body_bytecode[-1][0] != OpCode.RETURN_VALUE
                ):
                    func_body_bytecode.append((OpCode.RETURN_VALUE, None))

                func_source = self._get_node_text(body_node, source_code_bytes)
                location = (body_node.start_point[0] + 1, body_node.end_point[0] + 1)
                func_code_obj = CodeObject(
                    "lambda", func_body_bytecode, func_source, file_path, location
                )
                bytecode.append((OpCode.MAKE_FUNCTION, func_code_obj))

        elif node_type == "conditional_expression":
            # Handle ternary operator: condition ? true_expr : false_expr
            condition_node = node.child_by_field_name("condition")
            consequence_node = node.child_by_field_name("consequence")
            alternative_node = node.child_by_field_name("alternative")

            if condition_node:
                bytecode.extend(
                    self._generate_bytecode(
                        condition_node, source_code_bytes, file_path
                    )
                )

            jump_if_false = len(bytecode)
            bytecode.append((OpCode.POP_JUMP_IF_FALSE, -1))

            if consequence_node:
                bytecode.extend(
                    self._generate_bytecode(
                        consequence_node, source_code_bytes, file_path
                    )
                )

            jump_over_else = len(bytecode)
            bytecode.append((OpCode.JUMP_FORWARD, -1))

            bytecode[jump_if_false] = (OpCode.POP_JUMP_IF_FALSE, len(bytecode))

            if alternative_node:
                bytecode.extend(
                    self._generate_bytecode(
                        alternative_node, source_code_bytes, file_path
                    )
                )

            bytecode[jump_over_else] = (OpCode.JUMP_FORWARD, len(bytecode))

        # --- High-Level Structures (Functions, Classes) ---
        elif node_type in ["function_definition", "function_declaration"]:
            func_name = self._get_node_text(
                node.child_by_field_name("name"), source_code_bytes
            )
            body_node = node.child_by_field_name("body")

            func_body_bytecode = self._generate_bytecode(
                body_node, source_code_bytes, file_path
            )
            if (
                not func_body_bytecode
                or func_body_bytecode[-1][0] != OpCode.RETURN_VALUE
            ):
                func_body_bytecode.append((OpCode.RETURN_VALUE, None))

            func_source = self._get_node_text(body_node, source_code_bytes)
            location = (body_node.start_point[0] + 1, body_node.end_point[0] + 1)
            func_code_obj = CodeObject(
                func_name, func_body_bytecode, func_source, file_path, location
            )

            bytecode.append((OpCode.MAKE_FUNCTION, func_code_obj))
            bytecode.append((OpCode.STORE_NAME, func_name))

        elif node_type in ["class_definition", "class_declaration"]:
            class_name = self._get_node_text(
                node.child_by_field_name("name"), source_code_bytes
            )
            body_node = node.child_by_field_name("body")

            class_body_bytecode = self._generate_bytecode(
                body_node, source_code_bytes, file_path
            )
            class_source = self._get_node_text(body_node, source_code_bytes)
            location = (body_node.start_point[0] + 1, body_node.end_point[0] + 1)
            class_code_obj = CodeObject(
                class_name, class_body_bytecode, class_source, file_path, location
            )

            bytecode.append((OpCode.MAKE_CLASS, class_code_obj))
            bytecode.append((OpCode.STORE_NAME, class_name))

        # --- Comprehensions and Generators ---
        elif node_type in [
            "list_comprehension",
            "dictionary_comprehension",
            "set_comprehension",
            "generator_expression",
        ]:
            # Process comprehensions - simplified for malware analysis
            for child in node.named_children:
                bytecode.extend(
                    self._generate_bytecode(child, source_code_bytes, file_path)
                )
            if node_type == "list_comprehension":
                bytecode.append((OpCode.BUILD_LIST, 1))
            elif node_type == "dictionary_comprehension":
                bytecode.append((OpCode.BUILD_MAP, 1))
            elif node_type == "set_comprehension":
                bytecode.append((OpCode.BUILD_SET, 1))

        elif node_type == "await":
            # Process await expressions
            awaitable_node = node.child_by_field_name("awaitable")
            if awaitable_node:
                bytecode.extend(
                    self._generate_bytecode(
                        awaitable_node, source_code_bytes, file_path
                    )
                )
            bytecode.append((OpCode.BINARY_OPERATION, None))  # Placeholder for await

        elif node_type == "decorator":
            # Process decorators
            decorator_node = node.child_by_field_name("decorator")
            if decorator_node:
                bytecode.extend(
                    self._generate_bytecode(
                        decorator_node, source_code_bytes, file_path
                    )
                )

        elif node_type in ["switch_statement", "match_statement"]:
            # Process switch/match statements
            subject_node = node.child_by_field_name("subject")
            if subject_node:
                bytecode.extend(
                    self._generate_bytecode(subject_node, source_code_bytes, file_path)
                )

            # Process cases
            for child in node.children:
                if child.type in ["case_clause", "case"]:
                    bytecode.extend(
                        self._generate_bytecode(child, source_code_bytes, file_path)
                    )

        # --- Block, Module, and Program Handling ---
        elif node_type in [
            "block",
            "module",
            "program",
            "expression_statement",
            "lexical_declaration",
            "variable_declaration",
            "const_declaration",
            "let_declaration",
            "var_declaration",
            # JavaScript specific
            "template_string",
            "template_literal",
            "parenthesized_expression",
            "subscript",
            "attribute",
            # Python specific
            "concatenated_string",
            "f_string",
            "format_expression",
            # Exception handling
            "except_clause",
            "catch_clause",
            "finally_clause",
            "with_item",
            # Patterns and others
            "case_clause",
            "else_clause",
            "elif_clause",
        ]:
            for child in node.children:
                bytecode.extend(
                    self._generate_bytecode(child, source_code_bytes, file_path)
                )

        # Fallback for unhandled nodes
        else:
            for child in node.named_children:
                bytecode.extend(
                    self._generate_bytecode(child, source_code_bytes, file_path)
                )
        return bytecode

    def bytes_to_treesitter_ast(
        self, source_code_bytes: bytes, file_path: str
    ) -> Optional[Node]:
        """
        Parses source code bytes into a tree-sitter AST using the compiler's
        configured parser.
        """
        try:
            tree = self.parser.parse(source_code_bytes)
            return tree.root_node
        except Exception as e:
            logging.warning(
                f"Parsing error in file {file_path} with language {self.language_name}: {e}"
            )
            return None


def print_code_object(code_obj: CodeObject, indent_level: int = 0):
    """Recursively prints a CodeObject and its nested functions/classes."""
    header = f"--- CodeObject '{code_obj.name}' from {code_obj.path.name} (lines {code_obj.location[0]}-{code_obj.location[1]}) ---"
    separator = "-" * len(header)
    print(header)
    print(code_obj.to_string())
    print(separator)


def process_file(file_path: Path, compiler: ASTCompiler) -> Optional[CodeObject]:
    """Processes a single file to generate and print its Malwicode."""
    print(
        f"--- Processing {compiler.language_name.capitalize()} File: {file_path.name} ---"
    )
    try:
        source_code_bytes = file_path.read_bytes()

        ast = compiler.bytes_to_treesitter_ast(
            source_code_bytes=source_code_bytes,
            file_path=str(file_path),
        )

        if ast:
            malwicode_obj = compiler.treesitter_ast_to_malwicode(
                root_node=ast, source_code_bytes=source_code_bytes, file_path=file_path
            )
            print_code_object(malwicode_obj)
            return malwicode_obj

    except Exception as e:
        logging.error(f"Failed to process {file_path}: {e}")
    return None


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
        default=[".py", ".js"],
        help="A list of file extensions to process (e.g., .py .js).",
    )
    args = parser.parse_args()

    # Create a dictionary of compilers, one for each language.
    compilers: Dict[str, ASTCompiler] = {}
    try:
        if ".py" in args.extensions:
            compilers["python"] = ASTCompiler("python")
        if ".js" in args.extensions:
            compilers["javascript"] = ASTCompiler("javascript")
    except ValueError as e:
        logging.error(f"Failed to initialize compiler: {e}")
        return

    source_files, sources_count = collect_files_by_extension(
        args.input_path, accepted_extensions=args.extensions
    )

    if sources_count == 0:
        print(f"No files with extensions {args.extensions} found in {args.input_path}")
        return

    print(f"Found {sources_count} file(s) to process...")
    for source in source_files:
        lang = None
        if source.suffix == ".py":
            lang = "python"
        elif source.suffix == ".js":
            lang = "javascript"

        compiler_instance = compilers.get(lang)
        if compiler_instance:
            process_file(source, compiler_instance)
        else:
            print(f"Skipping unsupported file extension: {source.name}")


if __name__ == "__main__":
    main()
