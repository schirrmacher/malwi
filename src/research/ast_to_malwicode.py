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
    BINARY_MODULO = auto()
    BINARY_POWER = auto()
    BINARY_FLOOR_DIVIDE = auto()
    BINARY_AND = auto()
    BINARY_OR = auto()
    BINARY_XOR = auto()
    BINARY_LSHIFT = auto()
    BINARY_RSHIFT = auto()
    BINARY_UNSIGNED_RSHIFT = auto()  # JavaScript >>> operator
    BINARY_MATMUL = auto()  # Python @ operator
    BINARY_NULLISH_COALESCING = auto()  # JavaScript ?? operator
    COMPARE_OP = auto()
    COMPARE_LESS = auto()
    COMPARE_GREATER = auto()
    COMPARE_EQUAL = auto()
    COMPARE_NOT_EQUAL = auto()
    COMPARE_LESS_EQUAL = auto()
    COMPARE_GREATER_EQUAL = auto()
    COMPARE_IN = auto()
    COMPARE_NOT_IN = auto()
    COMPARE_IS = auto()
    COMPARE_IS_NOT = auto()
    COMPARE_INSTANCEOF = auto()
    LOGICAL_AND = auto()
    LOGICAL_OR = auto()
    LOGICAL_NOT = auto()
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
    BINARY_SUBSCR = auto()
    LOAD_ATTR = auto()
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
            # Arithmetic operators
            "+": OpCode.BINARY_ADD,
            "-": OpCode.BINARY_SUBTRACT,
            "*": OpCode.BINARY_MULTIPLY,
            "/": OpCode.BINARY_DIVIDE,
            "%": OpCode.BINARY_MODULO,
            "**": OpCode.BINARY_POWER,
            "//": OpCode.BINARY_FLOOR_DIVIDE,
            # Bitwise operators
            "&": OpCode.BINARY_AND,
            "|": OpCode.BINARY_OR,
            "^": OpCode.BINARY_XOR,
            "<<": OpCode.BINARY_LSHIFT,
            ">>": OpCode.BINARY_RSHIFT,
            ">>>": OpCode.BINARY_UNSIGNED_RSHIFT,  # JavaScript unsigned right shift
            # Matrix operations
            "@": OpCode.BINARY_MATMUL,  # Python matrix multiplication
            # Nullish coalescing
            "??": OpCode.BINARY_NULLISH_COALESCING,  # JavaScript nullish coalescing
            # Comparison operators
            "<": OpCode.COMPARE_LESS,
            ">": OpCode.COMPARE_GREATER,
            "==": OpCode.COMPARE_EQUAL,
            "===": OpCode.COMPARE_EQUAL,  # JavaScript strict equality
            "!=": OpCode.COMPARE_NOT_EQUAL,
            "!==": OpCode.COMPARE_NOT_EQUAL,  # JavaScript strict inequality
            "<=": OpCode.COMPARE_LESS_EQUAL,
            ">=": OpCode.COMPARE_GREATER_EQUAL,
            "in": OpCode.COMPARE_IN,
            "not in": OpCode.COMPARE_NOT_IN,
            "is": OpCode.COMPARE_IS,
            "is not": OpCode.COMPARE_IS_NOT,
            "instanceof": OpCode.COMPARE_INSTANCEOF,
            # Logical operators
            "and": OpCode.LOGICAL_AND,
            "or": OpCode.LOGICAL_OR,
            "&&": OpCode.LOGICAL_AND,  # JavaScript
            "||": OpCode.LOGICAL_OR,  # JavaScript
        }

        unary_operator_mapping = {
            # Arithmetic unary operators
            "-": OpCode.UNARY_NEGATIVE,
            "+": OpCode.BINARY_OPERATION,  # Unary plus (no specific opcode needed)
            # Bitwise unary operators
            "~": OpCode.UNARY_INVERT,
            # Logical unary operators
            "not": OpCode.LOGICAL_NOT,
            "!": OpCode.LOGICAL_NOT,  # JavaScript
            # Other operators
            "typeof": OpCode.BINARY_OPERATION,  # JavaScript typeof
            "void": OpCode.BINARY_OPERATION,  # JavaScript void
            "delete": OpCode.BINARY_OPERATION,  # JavaScript delete
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
                bytecode.append(
                    (op_code, op_text if op_code == OpCode.BINARY_OPERATION else None)
                )
        elif node_type in ["unary_operator", "unary_expression"]:
            operand_node = node.child_by_field_name("operand") or node.children[-1]
            bytecode.extend(
                self._generate_bytecode(operand_node, source_code_bytes, file_path)
            )
            op_node = node.child_by_field_name("operator") or node.children[0]
            if op_node:
                op_text = self._get_node_text(op_node, source_code_bytes)
                op_code = unary_operator_mapping.get(op_text, OpCode.BINARY_OPERATION)
                bytecode.append(
                    (op_code, op_text if op_code == OpCode.BINARY_OPERATION else None)
                )
        elif node_type in ["boolean_operator", "logical_expression"]:
            # Handle 'and', 'or', '&&', '||' operators
            left_node = node.child_by_field_name("left")
            right_node = node.child_by_field_name("right")
            op_node = node.child_by_field_name("operator")

            if left_node and right_node:
                bytecode.extend(
                    self._generate_bytecode(left_node, source_code_bytes, file_path)
                )
                bytecode.extend(
                    self._generate_bytecode(right_node, source_code_bytes, file_path)
                )

                if op_node:
                    op_text = self._get_node_text(op_node, source_code_bytes)
                    op_code = binary_operator_mapping.get(
                        op_text, OpCode.BINARY_OPERATION
                    )
                    bytecode.append(
                        (
                            op_code,
                            op_text if op_code == OpCode.BINARY_OPERATION else None,
                        )
                    )
                else:
                    bytecode.append((OpCode.BINARY_OPERATION, None))
        elif node_type in ["comparison_operator"]:
            # Handle comparison chains like 'a < b < c'
            for child in node.named_children:
                bytecode.extend(
                    self._generate_bytecode(child, source_code_bytes, file_path)
                )
            # For comparison chains, we'll use the generic COMPARE_OP
            bytecode.append((OpCode.COMPARE_OP, None))
        elif node_type in ["not_operator"]:
            operand_node = node.child_by_field_name("operand") or node.children[-1]
            bytecode.extend(
                self._generate_bytecode(operand_node, source_code_bytes, file_path)
            )
            bytecode.append((OpCode.LOGICAL_NOT, None))

        elif node_type in ["call", "call_expression"]:
            func_node = node.child_by_field_name("function")
            args_node = node.child_by_field_name("arguments")
            if func_node:
                bytecode.extend(
                    self._generate_bytecode(func_node, source_code_bytes, file_path)
                )

            arg_count = 0
            kwarg_count = 0
            has_starargs = False
            has_kwargs = False

            if args_node:
                for arg in args_node.children:
                    if arg.type not in [",", "(", ")"]:
                        if arg.type == "list_splat":
                            # Handle *args
                            argument_node = (
                                arg.child_by_field_name("argument")
                                or arg.named_children[0]
                            )
                            if argument_node:
                                bytecode.extend(
                                    self._generate_bytecode(
                                        argument_node, source_code_bytes, file_path
                                    )
                                )
                                has_starargs = True
                        elif arg.type == "dictionary_splat":
                            # Handle **kwargs
                            argument_node = (
                                arg.child_by_field_name("argument")
                                or arg.named_children[0]
                            )
                            if argument_node:
                                bytecode.extend(
                                    self._generate_bytecode(
                                        argument_node, source_code_bytes, file_path
                                    )
                                )
                                has_kwargs = True
                        elif arg.type == "keyword_argument":
                            # Handle key=value
                            name_node = arg.child_by_field_name("name")
                            value_node = arg.child_by_field_name("value")
                            if name_node and value_node:
                                key_name = self._get_node_text(
                                    name_node, source_code_bytes
                                )
                                bytecode.append((OpCode.LOAD_CONST, key_name))
                                bytecode.extend(
                                    self._generate_bytecode(
                                        value_node, source_code_bytes, file_path
                                    )
                                )
                                kwarg_count += 1
                        else:
                            # Regular positional argument
                            bytecode.extend(
                                self._generate_bytecode(
                                    arg, source_code_bytes, file_path
                                )
                            )
                            arg_count += 1

            # Choose appropriate call instruction based on argument types
            if has_kwargs or kwarg_count > 0:
                bytecode.append((OpCode.BINARY_OPERATION, None))  # CALL_FUNCTION_KW
            elif has_starargs:
                bytecode.append((OpCode.BINARY_OPERATION, None))  # CALL_FUNCTION_VAR
            else:
                bytecode.append((OpCode.CALL_FUNCTION, arg_count))

        elif node_type in ["update_expression"]:
            # Handle ++, -- operators (JavaScript)
            argument_node = node.child_by_field_name("argument")
            if argument_node:
                # Load current value
                bytecode.extend(
                    self._generate_bytecode(argument_node, source_code_bytes, file_path)
                )
                # Perform increment/decrement
                bytecode.append((OpCode.LOAD_CONST, 1.0))
                op_text = self._get_node_text(node, source_code_bytes)
                if "++" in op_text:
                    bytecode.append((OpCode.BINARY_ADD, None))
                else:  # "--"
                    bytecode.append((OpCode.BINARY_SUBTRACT, None))
                # Store back
                var_name = self._get_node_text(argument_node, source_code_bytes)
                bytecode.append((OpCode.STORE_NAME, var_name))

        elif node_type in ["new_expression"]:
            # Handle `new Constructor()` calls
            constructor_node = node.child_by_field_name("constructor")
            if constructor_node:
                bytecode.extend(
                    self._generate_bytecode(
                        constructor_node, source_code_bytes, file_path
                    )
                )

            # Process arguments
            arguments_node = node.child_by_field_name("arguments")
            arg_count = 0
            if arguments_node:
                for child in arguments_node.named_children:
                    bytecode.extend(
                        self._generate_bytecode(child, source_code_bytes, file_path)
                    )
                    arg_count += 1
            bytecode.append((OpCode.CALL_FUNCTION, arg_count))

        elif node_type in ["sequence_expression"]:
            # Handle comma operator (JavaScript)
            for child in node.named_children:
                bytecode.extend(
                    self._generate_bytecode(child, source_code_bytes, file_path)
                )
                # Only the last expression's value is kept

        elif node_type in ["yield_expression", "yield"]:
            # Handle Python yield and yield from expressions
            value_node = node.child_by_field_name(
                "argument"
            ) or node.child_by_field_name("value")

            # Check if this is "yield from" (Python) or just "yield"
            yield_text = self._get_node_text(node, source_code_bytes)
            is_yield_from = "yield from" in yield_text or "yield*" in yield_text

            if value_node:
                bytecode.extend(
                    self._generate_bytecode(value_node, source_code_bytes, file_path)
                )
            else:
                # yield without value yields None
                bytecode.append((OpCode.LOAD_CONST, None))

            if is_yield_from:
                bytecode.append((OpCode.BINARY_OPERATION, None))  # YIELD_FROM
            else:
                bytecode.append((OpCode.BINARY_OPERATION, None))  # YIELD_VALUE

        elif node_type in ["template_string"]:
            # Handle template literals with ${} substitutions
            for child in node.named_children:
                if child.type == "template_substitution":
                    # Handle ${expression}
                    expr_node = child.child_by_field_name("expression")
                    if expr_node:
                        bytecode.extend(
                            self._generate_bytecode(
                                expr_node, source_code_bytes, file_path
                            )
                        )
                else:
                    # Handle regular string parts
                    bytecode.extend(
                        self._generate_bytecode(child, source_code_bytes, file_path)
                    )
            # Concatenate all parts
            bytecode.append(
                (OpCode.BINARY_OPERATION, None)
            )  # Placeholder for string formatting

        elif node_type == "regex":
            # Handle regex literals
            pattern_text = self._get_node_text(node, source_code_bytes)
            bytecode.append((OpCode.LOAD_CONST, pattern_text))

        elif node_type in ["spread_element"]:
            # Handle ...spread syntax
            argument_node = node.child_by_field_name("argument")
            if argument_node:
                bytecode.extend(
                    self._generate_bytecode(argument_node, source_code_bytes, file_path)
                )
                bytecode.append(
                    (OpCode.BINARY_OPERATION, None)
                )  # Placeholder for spread

        elif node_type in ["optional_chain"]:
            # Handle ?. optional chaining
            for child in node.named_children:
                bytecode.extend(
                    self._generate_bytecode(child, source_code_bytes, file_path)
                )
            bytecode.append(
                (OpCode.BINARY_OPERATION, None)
            )  # Placeholder for optional access

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

        elif node_type == "do_statement":
            # Process do-while loops (JavaScript)
            body_node = node.child_by_field_name("body")
            condition_node = node.child_by_field_name("condition")

            # Execute body first
            if body_node:
                bytecode.extend(
                    self._generate_bytecode(body_node, source_code_bytes, file_path)
                )

            # Then check condition
            if condition_node:
                bytecode.extend(
                    self._generate_bytecode(
                        condition_node, source_code_bytes, file_path
                    )
                )
                bytecode.append(
                    (OpCode.POP_JUMP_IF_TRUE, len(bytecode) - 10)
                )  # Jump back to start

        elif node_type == "debugger_statement":
            # JavaScript debugger statement
            bytecode.append((OpCode.BINARY_OPERATION, None))  # Placeholder for debugger

        elif node_type == "labeled_statement":
            # Process labeled statements (JavaScript)
            label_node = node.child_by_field_name("label")
            statement_node = node.child_by_field_name("body")

            if label_node:
                label_name = self._get_node_text(label_node, source_code_bytes)
                bytecode.append((OpCode.LOAD_CONST, label_name))

            if statement_node:
                bytecode.extend(
                    self._generate_bytecode(
                        statement_node, source_code_bytes, file_path
                    )
                )

        elif node_type in ["try_statement"]:
            # Process try/except/finally blocks with proper exception handling
            body_node = node.child_by_field_name("body")
            except_clauses = []
            finally_clause = None

            # Collect except and finally clauses
            for child in node.children:
                if child.type in ["except_clause", "catch_clause"]:
                    except_clauses.append(child)
                elif child.type == "finally_clause":
                    finally_clause = child

            # Generate try block
            if body_node:
                bytecode.extend(
                    self._generate_bytecode(body_node, source_code_bytes, file_path)
                )

            # Jump over except blocks if no exception
            jump_to_finally = len(bytecode)
            bytecode.append((OpCode.JUMP_FORWARD, -1))  # Will be patched

            # Generate except clauses
            except_handlers = []
            for except_clause in except_clauses:
                except_start = len(bytecode)
                except_handlers.append(except_start)

                # Check if this except has a specific exception type
                exception_node = except_clause.child_by_field_name("type")
                if exception_node:
                    # Generate code to match exception type
                    bytecode.extend(
                        self._generate_bytecode(
                            exception_node, source_code_bytes, file_path
                        )
                    )
                    bytecode.append((OpCode.BINARY_OPERATION, None))  # Exception match

                # Handle exception variable binding (as e)
                name_node = except_clause.child_by_field_name("name")
                if name_node:
                    var_name = self._get_node_text(name_node, source_code_bytes)
                    bytecode.append((OpCode.STORE_NAME, var_name))

                # Generate except block body
                body_node = except_clause.child_by_field_name("body")
                if body_node:
                    bytecode.extend(
                        self._generate_bytecode(body_node, source_code_bytes, file_path)
                    )

                # Jump to finally/end
                bytecode.append((OpCode.JUMP_FORWARD, jump_to_finally))

            # Patch jump to finally
            finally_start = len(bytecode)
            bytecode[jump_to_finally] = (OpCode.JUMP_FORWARD, finally_start)

            # Generate finally clause
            if finally_clause:
                body_node = finally_clause.child_by_field_name("body")
                if body_node:
                    bytecode.extend(
                        self._generate_bytecode(body_node, source_code_bytes, file_path)
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

        elif node_type == "named_expression":
            # Handle walrus operator (:=) in Python
            target_node = node.child_by_field_name("name")
            value_node = node.child_by_field_name("value")

            if value_node:
                # Generate bytecode for the value expression
                bytecode.extend(
                    self._generate_bytecode(value_node, source_code_bytes, file_path)
                )

                # Store the value in the target variable
                if target_node:
                    target_name = self._get_node_text(target_node, source_code_bytes)
                    bytecode.append((OpCode.STORE_NAME, target_name))
                    # Load the variable back onto the stack (walrus returns the value)
                    bytecode.append((OpCode.LOAD_NAME, target_name))

        elif node_type in ["subscript", "subscript_expression"]:
            # Handle array/dict subscript access and slicing: obj[key] or obj[start:end:step]
            object_node = node.child_by_field_name(
                "object"
            ) or node.child_by_field_name("value")
            index_node = node.child_by_field_name("index") or node.child_by_field_name(
                "subscript"
            )

            if object_node:
                bytecode.extend(
                    self._generate_bytecode(object_node, source_code_bytes, file_path)
                )

            if index_node:
                if index_node.type == "slice":
                    # Handle slice notation [start:stop:step]
                    start_node = index_node.child_by_field_name("start")
                    stop_node = index_node.child_by_field_name("stop")
                    step_node = index_node.child_by_field_name("step")

                    # Load slice components (None for missing parts)
                    if start_node:
                        bytecode.extend(
                            self._generate_bytecode(
                                start_node, source_code_bytes, file_path
                            )
                        )
                    else:
                        bytecode.append((OpCode.LOAD_CONST, None))

                    if stop_node:
                        bytecode.extend(
                            self._generate_bytecode(
                                stop_node, source_code_bytes, file_path
                            )
                        )
                    else:
                        bytecode.append((OpCode.LOAD_CONST, None))

                    if step_node:
                        bytecode.extend(
                            self._generate_bytecode(
                                step_node, source_code_bytes, file_path
                            )
                        )
                    else:
                        bytecode.append((OpCode.LOAD_CONST, None))

                    bytecode.append((OpCode.BINARY_OPERATION, None))  # BUILD_SLICE
                    bytecode.append((OpCode.BINARY_SUBSCR, None))
                else:
                    # Regular subscript access
                    bytecode.extend(
                        self._generate_bytecode(
                            index_node, source_code_bytes, file_path
                        )
                    )
                    bytecode.append((OpCode.BINARY_SUBSCR, None))

        elif node_type == "attribute":
            # Handle attribute access: obj.attr
            object_node = node.child_by_field_name(
                "object"
            ) or node.child_by_field_name("value")
            attribute_node = node.child_by_field_name(
                "attribute"
            ) or node.child_by_field_name("property")

            if object_node:
                bytecode.extend(
                    self._generate_bytecode(object_node, source_code_bytes, file_path)
                )

            if attribute_node:
                attr_name = self._get_node_text(attribute_node, source_code_bytes)
                bytecode.append((OpCode.LOAD_ATTR, attr_name))

        elif node_type in ["f_string", "formatted_string_literal"]:
            # Handle f-string with interpolation: f"Hello {name}!"
            string_parts = 0
            for child in node.named_children:
                if child.type == "interpolation":
                    # Handle {expression} in f-string
                    expr_node = (
                        child.named_children[0] if child.named_children else None
                    )
                    if expr_node:
                        bytecode.extend(
                            self._generate_bytecode(
                                expr_node, source_code_bytes, file_path
                            )
                        )
                        string_parts += 1
                else:
                    # Handle regular string parts
                    text_content = self._get_node_text(child, source_code_bytes)
                    bytecode.append((OpCode.LOAD_CONST, text_content))
                    string_parts += 1

            # Build the formatted string
            if string_parts > 1:
                bytecode.append((OpCode.BINARY_OPERATION, None))  # String format/join

        elif node_type == "concatenated_string":
            # Handle implicit string concatenation: "hello" "world"
            for child in node.named_children:
                if child.type == "string":
                    bytecode.extend(
                        self._generate_bytecode(child, source_code_bytes, file_path)
                    )
            # Concatenate strings
            bytecode.append((OpCode.BINARY_ADD, None))

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
            # Process comprehensions with for_in_clause and if_clause support
            element_expr = None
            for_clauses = []
            if_clauses = []

            for child in node.named_children:
                if child.type == "for_in_clause":
                    # Handle: for var in iterable
                    var_node = child.child_by_field_name("left")
                    iterable_node = child.child_by_field_name("right")
                    for_clauses.append((var_node, iterable_node))
                elif child.type == "if_clause":
                    # Handle: if condition
                    condition_node = (
                        child.child_by_field_name("condition")
                        or child.named_children[0]
                    )
                    if_clauses.append(condition_node)
                elif child.type in ["pair"]:
                    # Dictionary comprehension key:value pair
                    element_expr = child
                else:
                    # Expression to evaluate (list/set element)
                    if not element_expr:
                        element_expr = child

            # Generate bytecode for comprehension
            # Start with empty collection
            if node_type == "list_comprehension":
                bytecode.append((OpCode.BUILD_LIST, 0))
            elif node_type == "dictionary_comprehension":
                bytecode.append((OpCode.BUILD_MAP, 0))
            elif node_type == "set_comprehension":
                bytecode.append((OpCode.BUILD_SET, 0))

            # Process for clauses (nested loops)
            for var_node, iterable_node in for_clauses:
                if iterable_node:
                    bytecode.extend(
                        self._generate_bytecode(
                            iterable_node, source_code_bytes, file_path
                        )
                    )
                    bytecode.append((OpCode.GET_ITER, None))

                    # Loop start
                    loop_start = len(bytecode)
                    bytecode.append((OpCode.FOR_ITER, -1))  # Will be patched

                    if var_node:
                        var_name = self._get_node_text(var_node, source_code_bytes)
                        bytecode.append((OpCode.STORE_NAME, var_name))

                    # Process if clauses (filters)
                    for condition_node in if_clauses:
                        bytecode.extend(
                            self._generate_bytecode(
                                condition_node, source_code_bytes, file_path
                            )
                        )
                        bytecode.append((OpCode.POP_JUMP_IF_FALSE, loop_start))

                    # Generate element expression
                    if element_expr:
                        bytecode.extend(
                            self._generate_bytecode(
                                element_expr, source_code_bytes, file_path
                            )
                        )
                        # Add to collection (simplified)
                        bytecode.append((OpCode.BINARY_OPERATION, None))

                    # Jump back to loop start
                    bytecode.append((OpCode.JUMP_FORWARD, loop_start))

                    # Patch FOR_ITER to jump here when done
                    bytecode[loop_start] = (OpCode.FOR_ITER, len(bytecode))

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
                if child.type in ["case_clause", "case", "switch_case"]:
                    # Process case value/pattern
                    value_node = child.child_by_field_name(
                        "value"
                    ) or child.child_by_field_name("pattern")
                    if value_node:
                        bytecode.extend(
                            self._generate_bytecode(
                                value_node, source_code_bytes, file_path
                            )
                        )
                        bytecode.append(
                            (OpCode.BINARY_OPERATION, None)
                        )  # Compare with subject

                    # Process case body
                    body_node = child.child_by_field_name("body")
                    if body_node:
                        bytecode.extend(
                            self._generate_bytecode(
                                body_node, source_code_bytes, file_path
                            )
                        )
                elif child.type in ["switch_default", "else_clause"]:
                    # Process default case
                    body_node = child.child_by_field_name("body")
                    if body_node:
                        bytecode.extend(
                            self._generate_bytecode(
                                body_node, source_code_bytes, file_path
                            )
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
