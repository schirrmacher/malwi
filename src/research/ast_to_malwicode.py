import logging
import argparse
import hashlib
from enum import Enum, auto
from pathlib import Path
from tree_sitter import Node
from typing import Optional, Any, List, Tuple, Dict

from tree_sitter import Parser, Language
from tqdm import tqdm
from research.csv_writer import CSVWriter
from research.mapping import (
    FUNCTION_MAPPING,
    IMPORT_MAPPING,
    COMMON_TARGET_FILES,
    reduce_whitespace,
    remove_newlines,
    SpecialCases,
    map_entropy_to_token,
    map_string_length_to_token,
    clean_string_literal,
    calculate_shannon_entropy,
    is_valid_encoding_name,
    is_valid_ip,
    is_base64,
    is_hex,
    is_valid_url,
    is_version,
    is_escaped_hex,
    is_file_path,
    contains_url,
    is_localhost,
    SENSITIVE_PATHS,
)

# Import both language bindings
import tree_sitter_python as tspython
import tree_sitter_javascript as tsjavascript


class OpCode(Enum):
    """
    Defines the set of all possible bytecode operations for Malwicode.
    """

    LOAD_CONST = auto()
    LOAD_NAME = auto()
    LOAD_GLOBAL = auto()  # Explicitly for global variables
    LOAD_PARAM = auto()
    STORE_NAME = auto()
    STORE_GLOBAL = auto()  # Explicitly for global variables
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
    BINARY_OPERATION = auto()
    CALL_FUNCTION = auto()
    MAKE_FUNCTION = auto()
    MAKE_CLASS = auto()
    RETURN_VALUE = auto()
    POP_JUMP_IF_FALSE = auto()
    POP_JUMP_IF_TRUE = auto()
    JUMP_FORWARD = auto()
    GET_ITER = auto()
    FOR_ITER = auto()
    BUILD_LIST = auto()
    BUILD_TUPLE = auto()
    BUILD_SET = auto()
    BUILD_MAP = auto()
    BINARY_SUBSCR = auto()
    STORE_SUBSCR = auto()  # For subscript assignment like obj[key] = value
    LOAD_ATTR = auto()
    STORE_ATTR = auto()  # For attribute assignment like obj.attr = value
    UNARY_NEGATIVE = auto()
    UNARY_NOT = auto()
    UNARY_INVERT = auto()
    UNARY_POSITIVE = auto()  # For unary plus operator
    IMPORT_NAME = auto()
    IMPORT_FROM = auto()
    EXPORT_DEFAULT = auto()
    EXPORT_NAMED = auto()
    AWAIT_EXPRESSION = auto()
    ASYNC_FUNCTION = auto()
    GENERATOR_FUNCTION = auto()
    WITH_CONTEXT = auto()
    ENTER_CONTEXT = auto()
    EXIT_CONTEXT = auto()
    TYPEOF_OPERATOR = auto()
    VOID_OPERATOR = auto()
    DELETE_OPERATOR = auto()
    # Critical missing opcodes for better Python bytecode representation
    UNPACK_SEQUENCE = auto()  # For tuple/list unpacking: a, b = (1, 2)
    BUILD_STRING = auto()  # For f-string building
    FORMAT_VALUE = auto()  # For f-string value formatting
    LIST_APPEND = auto()  # For list comprehension optimization
    SET_ADD = auto()  # For set comprehension optimization
    MAP_ADD = auto()  # For dict comprehension optimization
    YIELD_VALUE = auto()  # For yield statements
    DELETE_NAME = auto()  # For del variable (more specific than DELETE_OPERATOR)
    DELETE_SUBSCR = auto()  # For del list[i] or del dict[key]
    # Additional missing opcodes for better Python bytecode representation
    COPY = auto()  # For internal stack copy operations
    KW_NAMES = auto()  # For keyword argument names in function calls
    POP_TOP = auto()  # For discarding top of stack value
    PUSH_NULL = auto()  # For pushing NULL value to stack

    # High-priority missing opcodes based on analysis
    RESUME = auto()  # For Python 3.11+ debugging/tracing support
    RETURN_CONST = auto()  # For returning constant values
    CALL = auto()  # New unified CALL opcode (Python 3.11+)
    NOP = auto()  # No operation
    BINARY_OP = auto()  # Generic binary operation with arg
    JUMP_BACKWARD = auto()  # For loop optimization
    LIST_EXTEND = auto()  # For efficient list building
    END_FOR = auto()  # For loop cleanup
    SWAP = auto()  # For stack manipulation
    STORE_FAST = auto()  # For fast local variable storage
    LOAD_FAST = auto()  # For fast local variable loading
    LOAD_FAST_AND_CLEAR = auto()  # For comprehensions
    RERAISE = auto()  # For exception re-raising
    BUILD_SLICE = auto()  # For slice objects
    STORE_SLICE = auto()  # For slice assignment
    BINARY_SLICE = auto()  # For slicing operations
    STORE_DEREF = auto()  # For nonlocal variable storage
    LOAD_DEREF = auto()  # For nonlocal variable loading
    UNPACK_EX = auto()  # For extended unpacking
    PUSH_EXC_INFO = auto()  # For exception handling
    POP_EXCEPT = auto()  # For exception cleanup
    CHECK_EXC_MATCH = auto()  # For exception matching
    LOAD_BUILD_CLASS = auto()  # For class building
    BEFORE_WITH = auto()  # For context manager setup
    WITH_EXCEPT_START = auto()  # For context manager exceptions


class Instruction:
    """
    Represents a single bytecode instruction with opcode and argument.
    Provides flexible string formatting for different output modes.
    """

    def __init__(self, opcode: "OpCode", arg: Any = None, language: str = "python"):
        self.opcode = opcode
        self.arg = arg
        self.language = language

    def __repr__(self) -> str:
        return f"Instruction({self.opcode.name}, {self.arg})"

    @classmethod
    def map_argument(
        cls, op_code: OpCode, arg: Any, language: str, for_hashing: bool = False
    ) -> str:
        """
        Maps opcode arguments to normalized tokens for machine learning model training.

        This is the most critical function for training! The mapping was optimized
        through hundreds of iterations to maximize the F1 score of the malware
        detection model.

        Args:
            op_code: The operation code (e.g., LOAD_CONST, STORE_NAME, CALL_FUNCTION)
            arg: The argument value to be mapped (string, number, identifier, etc.)
            language: Programming language context ("python" or "javascript")
            for_hashing: If True, removes variable parts to create stable hashes
                        for deduplication of similar code patterns

        Returns:
            Normalized token string in format: "{opcode_name} {mapped_argument}"
            Examples:
            - "LOAD_CONST STRING_LEN_M_ENT_HIGH" (for long strings)
            - "STORE_NAME requests" (for known function names)
            - "LOAD_CONST BOOLEAN" (for boolean values)
            - "CALL_FUNCTION 2" (for function calls with arg count)

        Mapping Strategy:
        1. **Data Type Normalization**: Converts literals (bool, int, float) to type tokens
        2. **Function/Import Recognition**: Maps known functions/imports using predefined dictionaries
        3. **Security Pattern Detection**: Identifies IPs, URLs, file paths, sensitive patterns
        4. **String Analysis**: For long strings, analyzes length, entropy, and encoding type

        Performance Learnings:
        - String length (STRING_MAX_LENGTH=20) has huge impact on model performance
          Shorter strings led to worse performance due to loss of context
        - Import mapping provides ~20% improvement in F1 score by reducing name variations
        - LOAD_ATTR_CHAIN was removed: chained attribute access like obj.prop1.func1
          decreased model performance, now generates individual LOAD_ATTR operations
          and creating more unique training samples for better generalization
        - Tokenization granularity is critical - splitting instructions can destroy
          context understanding and hurt model performance
        - Without function mapping the performance is around 85% (F1)

        Hashing Mode:
        When for_hashing=True, removes variable content (actual string values, numbers)
        to create stable hashes for similar code structures. This enables:
        - Deduplication of functionally identical code samples
        - Better training data quality by focusing on behavioral patterns
        - Consistent hash generation across different variable names/values
        """

        STRING_MAX_LENGTH = 15
        prefix = "STRING"
        function_mapping = FUNCTION_MAPPING.get(language, {})
        import_mapping = IMPORT_MAPPING.get(language, {})

        if not arg:
            return op_code.name

        argval = clean_string_literal(reduce_whitespace(remove_newlines(str(arg))))

        # Map basic data types
        if op_code == OpCode.LOAD_CONST and isinstance(arg, bool):
            return f"{op_code.name} {SpecialCases.BOOLEAN.value}"
        elif op_code == OpCode.LOAD_CONST and isinstance(arg, int):
            return f"{op_code.name} {SpecialCases.INTEGER.value}"
        elif op_code == OpCode.LOAD_CONST and isinstance(arg, float):
            return f"{op_code.name} {SpecialCases.FLOAT.value}"
        # Map jumps for conditional logic
        elif op_code in (
            OpCode.POP_JUMP_IF_FALSE,
            OpCode.POP_JUMP_IF_TRUE,
            OpCode.JUMP_FORWARD,
        ):
            return f"{op_code.name}"
        elif op_code in [OpCode.MAKE_CLASS, OpCode.MAKE_FUNCTION]:
            return f"{op_code.name}"
        elif (
            op_code in [OpCode.IMPORT_FROM, OpCode.IMPORT_NAME]
            and argval in import_mapping
        ):
            return f"{op_code.name} {import_mapping.get(argval)}"
        # The function can be fully replaced by a single token
        elif (
            op_code
            in [
                OpCode.STORE_NAME,
                OpCode.LOAD_NAME,
                OpCode.STORE_GLOBAL,
                OpCode.LOAD_GLOBAL,
            ]
            and argval in function_mapping
        ):
            return f"{op_code.name} {function_mapping.get(argval)}"
        elif op_code in [OpCode.CALL_FUNCTION]:
            return f"{op_code.name} {argval}"
        elif op_code in [OpCode.POP_TOP]:
            # POP_TOP discards top of stack, no argument needed
            return f"{op_code.name}"
        elif op_code in [OpCode.PUSH_NULL]:
            # PUSH_NULL pushes NULL value to stack, no argument needed
            return f"{op_code.name}"
        elif op_code in [OpCode.COPY]:
            # COPY duplicates stack values, argument indicates copy depth
            return f"{op_code.name} {argval if argval is not None else '1'}"
        elif op_code == OpCode.KW_NAMES:
            # Handle keyword argument names tuple - concatenate with underscores
            if isinstance(arg, tuple):
                kw_names_str = "_".join(str(name) for name in arg)
                return f"{op_code.name} {kw_names_str}"
            else:
                return f"{op_code.name} {argval}"
        elif argval in SENSITIVE_PATHS:
            return f"{op_code.name} {SpecialCases.STRING_SENSITIVE_FILE_PATH.value}"
        elif is_localhost(argval):
            return f"{op_code.name} {SpecialCases.STRING_LOCALHOST.value}"
        elif is_valid_ip(argval):
            return f"{op_code.name} {SpecialCases.STRING_IP.value}"
        elif is_valid_url(argval):
            return f"{op_code.name} {SpecialCases.STRING_URL.value}"
        elif contains_url(argval):
            # String contains a URL but isn't a URL itself
            return f"{op_code.name} {SpecialCases.STRING_CONTAINS_URL.value}"
        elif is_version(argval):
            return f"{op_code.name} {SpecialCases.STRING_VERSION.value}"
        elif is_valid_encoding_name(argval):
            return f"{op_code.name} {SpecialCases.STRING_ENCODING.value}"
        elif is_file_path(argval):
            return f"{op_code.name} {SpecialCases.STRING_FILE_PATH.value}"

        # Cut strings when too long
        if len(argval) <= STRING_MAX_LENGTH:
            return f"{op_code.name} {argval}"

        if is_escaped_hex(argval):
            prefix = SpecialCases.STRING_ESCAPED_HEX.value
        elif is_hex(argval):
            prefix = SpecialCases.STRING_HEX.value
        elif is_base64(argval):
            prefix = SpecialCases.STRING_BASE64.value

        # Generate length and entropy suffix for all the above cases
        length_suffix = map_string_length_to_token(len(argval))
        try:
            entropy = calculate_shannon_entropy(argval.encode("utf-8", errors="ignore"))
        except Exception:
            entropy = 0.0
        entropy_suffix = map_entropy_to_token(entropy)
        return f"{op_code.name} {prefix}_{length_suffix}_{entropy_suffix}"

    def to_string(self, mapped: bool, for_hashing: bool = False) -> str:
        if mapped and for_hashing:
            return Instruction.map_argument(
                op_code=self.opcode,
                arg=self.arg,
                language=self.language,
                for_hashing=True,
            )
        elif mapped:
            return Instruction.map_argument(
                op_code=self.opcode,
                arg=self.arg,
                language=self.language,
                for_hashing=for_hashing,
            )
        else:
            return f"{self.opcode.name} {self.arg}"


class CodeObject:
    """
    A container for a compiled piece of code, including its bytecode,
    source, and location.
    """

    def __init__(
        self,
        name: str,
        byte_code: List[Instruction],
        source_code: str,
        path: Path,
        location: Tuple[int, int],
        language: str = "python",
    ):
        self.name = name
        self.byte_code = byte_code
        self.source_code = source_code
        self.path = path
        self.location = location
        self.language = language

    def __repr__(self) -> str:
        return (
            f"CodeObject(name={self.name}, path={self.path}, location={self.location})"
        )

    def to_string(self, mapped: bool = True, one_line=True, for_hashing=False) -> str:
        instructions = []

        if Path(self.path).name in COMMON_TARGET_FILES.get(self.language, []):
            instructions += [SpecialCases.TARGETED_FILE.value]

        for instruction in self.byte_code:
            instructions.append(
                instruction.to_string(mapped=mapped, for_hashing=for_hashing)
            )

        return (" " if one_line else "\n").join(instructions)

    def to_hash(self) -> str:
        """
        Generate SHA256 hash of the oneline_mapped string representation.

        Returns:
            Hexadecimal SHA256 hash string
        """
        token_string = self.to_string(mapped=True, for_hashing=True, one_line=True)
        encoded_string = token_string.encode("utf-8", errors="replace")
        sha256_hash = hashlib.sha256()
        sha256_hash.update(encoded_string)
        return sha256_hash.hexdigest()

    def get_tokens(self, mapped: bool = True) -> List[str]:
        """
        Get list of tokens from the bytecode instructions.

        Args:
            mapped: Whether to apply special token mapping

        Returns:
            List of token strings
        """
        tokens = []

        # Add file targeting warning if applicable
        if Path(self.path).name in COMMON_TARGET_FILES.get(self.language, []):
            tokens.append(SpecialCases.TARGETED_FILE.value)

        # Extract tokens from each instruction
        for instruction in self.byte_code:
            instruction_str = instruction.to_string(mapped=mapped, for_hashing=False)
            # Split instruction into opcode and argument tokens
            parts = instruction_str.split(" ", 1)
            tokens.append(parts[0].lower())  # Convert opcode to lowercase
            if len(parts) > 1 and parts[1]:
                tokens.append(parts[1])

        return tokens


def emit(opcode: "OpCode", arg: Any = None, language: str = "python") -> Instruction:
    """Helper function to create Instruction objects."""
    return Instruction(opcode, arg, language)


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

        # Track function parameters for LOAD_PARAM vs LOAD_NAME distinction
        self.current_function_params = set()
        # Track global variables for LOAD_GLOBAL/STORE_GLOBAL distinction
        self.global_variables = set()
        # Track whether we're currently inside a function scope
        self._in_function_scope = False
        # Track comprehension variables for LOAD_FAST/STORE_FAST distinction
        self.comprehension_variables = set()
        # Track nonlocal variables for STORE_DEREF/LOAD_DEREF distinction
        self.nonlocal_variables = set()
        # Track nesting depth: 0 = module level, 1+ = nested
        self._nesting_depth = 0
        # Collection to store all CodeObjects (root, functions, classes)
        self.code_objects = []
        # Counter for generating unique reference names
        self._next_ref_id = 0

    def treesitter_ast_to_malwicode(
        self, root_node: Node, source_code_bytes: bytes, file_path: Path
    ) -> List[CodeObject]:
        """
        Public method to initiate the compilation of an AST to multiple CodeObjects.
        Returns a list with the root CodeObject first, followed by function and class CodeObjects.
        """
        # Reset collections for each compilation
        self.code_objects = []
        self._next_ref_id = 0

        # First pass: Collect all variables that are declared global anywhere in the module
        self.global_variables = self._collect_global_variables(
            root_node, source_code_bytes
        )

        source_code = source_code_bytes.decode("utf-8", errors="replace")
        location = (root_node.start_point[0] + 1, root_node.end_point[0] + 1)

        # Generate bytecode with RESUME at start and RETURN_CONST at end
        bytecode = []
        # Add RESUME instruction at the start (for Python 3.11+ compatibility)
        bytecode.append(emit(OpCode.RESUME, 0))

        # Generate main bytecode
        module_bytecode = self._generate_bytecode(
            root_node, source_code_bytes, file_path
        )
        bytecode.extend(module_bytecode)

        # Add RETURN_CONST at the end instead of leaving it open
        bytecode.append(emit(OpCode.RETURN_CONST, None))

        # Create root CodeObject
        root_code_obj = CodeObject(
            name="<module>",
            byte_code=bytecode,
            source_code=source_code,
            path=file_path,
            location=location,
            language=self.language_name,
        )

        # Return root CodeObject first, followed by function/class CodeObjects
        return [root_code_obj] + self.code_objects

    def _generate_ref_name(self, base_name: str) -> str:
        """Generate a unique reference name for a CodeObject."""
        ref_name = f"{base_name}_ref_{self._next_ref_id}"
        self._next_ref_id += 1
        return ref_name

    def _get_node_text(self, node: Node, source_code_bytes: bytes) -> str:
        """Helper to extract text from a node."""
        return source_code_bytes[node.start_byte : node.end_byte].decode(
            "utf-8", errors="replace"
        )

    def _contains_yield(self, node: Node, source_code_bytes: bytes) -> bool:
        """Check if a node contains yield expressions (indicating a generator function)."""
        if node.type in ["yield", "yield_expression", "yield_from_expression"]:
            return True

        for child in node.children:
            if self._contains_yield(child, source_code_bytes):
                return True

        return False

    def _extract_function_parameters(self, node: Node, source_code_bytes: bytes) -> set:
        """Extract parameter names from function definition node."""
        params = set()

        # Handle different function types
        if node.type == "arrow_function":
            params.update(self._extract_arrow_function_params(node, source_code_bytes))
        elif node.type in ["lambda"]:
            params.update(self._extract_lambda_params(node, source_code_bytes))
        else:
            # Regular function definitions
            params.update(
                self._extract_regular_function_params(node, source_code_bytes)
            )

        return params

    def _extract_arrow_function_params(
        self, node: Node, source_code_bytes: bytes
    ) -> set:
        """Extract parameters from JavaScript arrow functions."""
        params = set()

        # Check for parameter/parameters field
        param_node = node.child_by_field_name("parameter") or node.child_by_field_name(
            "parameters"
        )
        if param_node:
            if param_node.type == "identifier":
                # Single parameter: x => x * 2
                param_name = self._get_node_text(param_node, source_code_bytes)
                params.add(param_name)
            elif param_node.type == "formal_parameters":
                # Multiple parameters: (x, y) => x + y
                params.update(
                    self._extract_from_formal_parameters(param_node, source_code_bytes)
                )

        # Fallback: check direct children for single identifier
        for child in node.named_children:
            if child.type == "identifier":
                param_name = self._get_node_text(child, source_code_bytes)
                params.add(param_name)

        return params

    def _extract_lambda_params(self, node: Node, source_code_bytes: bytes) -> set:
        """Extract parameters from Python lambda functions."""
        params = set()

        # Look for parameters in lambda
        for child in node.named_children:
            if child.type in ["parameters", "lambda_parameters"]:
                if child.type == "lambda_parameters":
                    # Lambda uses lambda_parameters, extract identifiers directly
                    for param_child in child.named_children:
                        if param_child.type == "identifier":
                            param_name = self._get_node_text(
                                param_child, source_code_bytes
                            )
                            params.add(param_name)
                else:
                    params.update(
                        self._extract_from_parameters(child, source_code_bytes)
                    )
            elif child.type == "identifier":
                # Single parameter lambda
                param_name = self._get_node_text(child, source_code_bytes)
                params.add(param_name)

        return params

    def _extract_regular_function_params(
        self, node: Node, source_code_bytes: bytes
    ) -> set:
        """Extract parameters from regular function definitions."""
        params = set()

        for child in node.named_children:
            if child.type in ["parameters", "formal_parameters"]:
                if child.type == "parameters":
                    params.update(
                        self._extract_from_parameters(child, source_code_bytes)
                    )
                else:  # formal_parameters
                    params.update(
                        self._extract_from_formal_parameters(child, source_code_bytes)
                    )

        return params

    def _extract_from_parameters(
        self, params_node: Node, source_code_bytes: bytes
    ) -> set:
        """Extract parameter names from Python parameters node."""
        params = set()

        for param_child in params_node.named_children:
            param_name = self._extract_single_parameter_name(
                param_child, source_code_bytes
            )
            if param_name:
                params.add(param_name)

        return params

    def _extract_from_formal_parameters(
        self, params_node: Node, source_code_bytes: bytes
    ) -> set:
        """Extract parameter names from JavaScript formal_parameters node."""
        params = set()

        for param_child in params_node.named_children:
            if param_child.type == "identifier":
                param_name = self._get_node_text(param_child, source_code_bytes)
                params.add(param_name)

        return params

    def _extract_single_parameter_name(
        self, param_node: Node, source_code_bytes: bytes
    ) -> str:
        """Extract parameter name from a single parameter node (Python)."""
        if param_node.type == "identifier":
            # Simple parameter: def func(param):
            return self._get_node_text(param_node, source_code_bytes)

        elif param_node.type in [
            "parameter",
            "required_parameter",
            "optional_parameter",
        ]:
            # Python typed parameters: def func(param: int):
            for child in param_node.named_children:
                if child.type == "identifier":
                    return self._get_node_text(child, source_code_bytes)

        elif param_node.type in [
            "default_parameter",
            "typed_parameter",
            "typed_default_parameter",
        ]:
            # Parameters with defaults/types: def func(param: int = 1):
            name_node = param_node.child_by_field_name("name")
            if name_node:
                return self._get_node_text(name_node, source_code_bytes)

        elif param_node.type in ["list_splat_pattern", "dictionary_splat_pattern"]:
            # Handle *args, **kwargs
            for child in param_node.named_children:
                if child.type == "identifier":
                    return self._get_node_text(child, source_code_bytes)

        # Fallback: try to get any identifier in the parameter node
        for child in param_node.named_children:
            if child.type == "identifier":
                return self._get_node_text(child, source_code_bytes)

        return None

    def _emit(self, opcode: "OpCode", arg: Any = None) -> Instruction:
        """Helper method to create Instruction objects with the compiler's language."""
        return emit(opcode, arg, self.language_name)

    def _collect_global_variables(self, node: Node, source_code_bytes: bytes) -> set:
        """
        First pass: collect all variables that are declared global anywhere in the module.
        This mimics Python's two-pass compilation where global declarations affect
        the entire module scope.
        """
        global_vars = set()

        def _traverse_for_globals(n: Node):
            if n.type == "global_statement":
                for child in n.named_children:
                    if child.type == "identifier":
                        var_name = self._get_node_text(child, source_code_bytes)
                        global_vars.add(var_name)

            # Recursively traverse all children
            for child in n.children:
                _traverse_for_globals(child)

        _traverse_for_globals(node)
        return global_vars

    def _emit_store(self, var_name: str) -> Instruction:
        """Helper method to emit appropriate store instruction based on variable scope."""
        if var_name in self.nonlocal_variables:
            # Nonlocal variables use STORE_DEREF for closure access
            return emit(OpCode.STORE_DEREF, var_name, self.language_name)
        elif var_name in self.global_variables:
            # Global variables use STORE_GLOBAL
            return emit(OpCode.STORE_GLOBAL, var_name, self.language_name)
        elif hasattr(self, "_in_function_scope") and self._in_function_scope:
            # Inside a function: other variables use STORE_GLOBAL for malware analysis consistency
            return emit(OpCode.STORE_GLOBAL, var_name, self.language_name)
        else:
            # Module level: other variables use STORE_NAME
            return emit(OpCode.STORE_NAME, var_name, self.language_name)

    def _emit_load(self, var_name: str) -> Instruction:
        """Helper method to emit appropriate load instruction based on variable scope."""
        # Check if this identifier is a comprehension variable first
        if var_name in self.comprehension_variables:
            return emit(OpCode.LOAD_FAST, var_name, self.language_name)
        # Check if this identifier is a nonlocal variable
        elif var_name in self.nonlocal_variables:
            return emit(OpCode.LOAD_DEREF, var_name, self.language_name)
        # Check if this identifier is a function parameter
        elif var_name in self.current_function_params:
            return emit(OpCode.LOAD_PARAM, var_name, self.language_name)
        elif var_name in self.global_variables:
            # Global variables use LOAD_GLOBAL
            return emit(OpCode.LOAD_GLOBAL, var_name, self.language_name)
        elif hasattr(self, "_in_function_scope") and self._in_function_scope:
            # Inside a function: other variables use LOAD_GLOBAL for malware analysis consistency
            return emit(OpCode.LOAD_GLOBAL, var_name, self.language_name)
        else:
            # Module level: other variables use LOAD_NAME
            return emit(OpCode.LOAD_NAME, var_name, self.language_name)

    def _generate_bytecode(
        self, node: Node, source_code_bytes: bytes, file_path: Path
    ) -> List[Instruction]:
        """
        Recursively traverses a Python or JavaScript AST and generates bytecode.
        """
        bytecode = []
        node_type = node.type

        # Python 3.11+ uses unified BINARY_OP with numeric arguments
        binary_operator_mapping = {
            # Arithmetic operators - Python 3.11+ BINARY_OP codes
            "+": (OpCode.BINARY_OP, 0),  # BINARY_OP 0 = add
            "-": (OpCode.BINARY_OP, 2),  # BINARY_OP 2 = subtract
            "*": (OpCode.BINARY_OP, 5),  # BINARY_OP 5 = multiply
            "/": (OpCode.BINARY_OP, 11),  # BINARY_OP 11 = true_divide
            "%": (OpCode.BINARY_OP, 6),  # BINARY_OP 6 = remainder
            "**": (OpCode.BINARY_OP, 8),  # BINARY_OP 8 = power
            "//": (OpCode.BINARY_OP, 12),  # BINARY_OP 12 = floor_divide
            # Bitwise operators
            "&": (OpCode.BINARY_OP, 1),  # BINARY_OP 1 = and
            "|": (OpCode.BINARY_OP, 4),  # BINARY_OP 4 = or
            "^": (OpCode.BINARY_OP, 7),  # BINARY_OP 7 = xor
            "<<": (OpCode.BINARY_OP, 9),  # BINARY_OP 9 = lshift
            ">>": (OpCode.BINARY_OP, 10),  # BINARY_OP 10 = rshift
            "@": (OpCode.BINARY_OP, 3),  # BINARY_OP 3 = matmul
            # JavaScript/fallback operators (keep old approach)
            ">>>": OpCode.BINARY_UNSIGNED_RSHIFT,  # JavaScript unsigned right shift
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
            "+": OpCode.UNARY_POSITIVE,  # Unary plus
            # Bitwise unary operators
            "~": OpCode.UNARY_INVERT,
            # Logical unary operators
            "not": OpCode.LOGICAL_NOT,
            "!": OpCode.LOGICAL_NOT,  # JavaScript
            # JavaScript-specific unary operators
            "typeof": OpCode.TYPEOF_OPERATOR,  # JavaScript typeof
            "void": OpCode.VOID_OPERATOR,  # JavaScript void
            "delete": OpCode.DELETE_OPERATOR,  # JavaScript delete
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
                bytecode.append(emit(OpCode.LOAD_CONST, value))
            except ValueError:
                # Fallback: treat as string if conversion fails
                bytecode.append(emit(OpCode.LOAD_CONST, text))
        elif node_type == "string":
            # Check if this string has interpolation children (f-string)
            has_interpolation = any(
                child.type == "interpolation" for child in node.children
            )

            if has_interpolation:
                # Handle f-string with proper BUILD_STRING/FORMAT_VALUE
                parts = []

                # Check if it's an f-string by looking at string_start
                if node.children and node.children[0].type == "string_start":
                    string_start = self._get_node_text(
                        node.children[0], source_code_bytes
                    )
                    if string_start.startswith("f"):
                        # Process f-string children
                        for child in node.children[
                            1:-1
                        ]:  # Skip string_start and string_end
                            if child.type == "string_content":
                                # Regular string part
                                text = self._get_node_text(child, source_code_bytes)
                                if text:  # Only add non-empty strings
                                    bytecode.append(emit(OpCode.LOAD_CONST, text))
                                    parts.append("str")
                            elif child.type == "interpolation":
                                # Expression to format
                                for expr_child in child.children:
                                    if expr_child.type not in ["{", "}"]:
                                        bytecode.extend(
                                            self._generate_bytecode(
                                                expr_child, source_code_bytes, file_path
                                            )
                                        )
                                        bytecode.append(emit(OpCode.FORMAT_VALUE, None))
                                        parts.append("fmt")
                                        break

                        # Build the final string
                        if len(parts) > 0:
                            bytecode.append(emit(OpCode.BUILD_STRING, len(parts)))
                        return bytecode

                # Fallback for other interpolation patterns
                string_parts = 0
                for child in node.children:
                    if child.type == "interpolation":
                        # Handle {expression} in f-string
                        for expr_child in child.children:
                            if expr_child.type not in ["{", "}"]:
                                bytecode.extend(
                                    self._generate_bytecode(
                                        expr_child, source_code_bytes, file_path
                                    )
                                )
                                string_parts += 1
                                break
                    elif child.type == "string_content":
                        # Handle regular string parts
                        text_content = self._get_node_text(child, source_code_bytes)
                        if text_content.strip():  # Only add non-empty content
                            bytecode.append(emit(OpCode.LOAD_CONST, text_content))
                            string_parts += 1

                # Build the formatted string if we have multiple parts
                if string_parts > 1:
                    bytecode.append(
                        emit(OpCode.BINARY_OPERATION, None)
                    )  # String format/join
                elif string_parts == 0:
                    # Fallback if no parts were processed
                    str_content = self._get_node_text(node, source_code_bytes)
                    bytecode.append(emit(OpCode.LOAD_CONST, str_content))
            else:
                # Regular string without interpolation
                str_content = self._get_node_text(node, source_code_bytes)
                bytecode.append(emit(OpCode.LOAD_CONST, str_content))
        elif node_type == "identifier":
            identifier_name = self._get_node_text(node, source_code_bytes)
            bytecode.append(self._emit_load(identifier_name))
        # Boolean and None literals
        elif node_type in ["true", "false"]:
            bytecode.append(emit(OpCode.LOAD_CONST, node_type == "true"))
        elif node_type in ["none", "null"]:
            bytecode.append(emit(OpCode.LOAD_CONST, None))
        elif node_type == "ellipsis":
            bytecode.append(emit(OpCode.LOAD_CONST, "..."))

        # --- Handle Data Structures ---
        elif node_type in ["list", "array"]:
            element_count = 0
            for element in node.children:
                if element.type not in ["[", "]", ","]:
                    bytecode.extend(
                        self._generate_bytecode(element, source_code_bytes, file_path)
                    )
                    element_count += 1
            bytecode.append(emit(OpCode.BUILD_LIST, element_count))
        elif node_type == "tuple":
            element_count = 0
            for element in node.children:
                if element.type not in ["(", ")", ","]:
                    bytecode.extend(
                        self._generate_bytecode(element, source_code_bytes, file_path)
                    )
                    element_count += 1
            bytecode.append(emit(OpCode.BUILD_TUPLE, element_count))
        elif node_type == "set":
            element_count = 0
            for element in node.children:
                if element.type not in ["{", "}", ","]:
                    bytecode.extend(
                        self._generate_bytecode(element, source_code_bytes, file_path)
                    )
                    element_count += 1
            bytecode.append(emit(OpCode.BUILD_SET, element_count))
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
            bytecode.append(emit(OpCode.BUILD_MAP, pair_count))

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
                # Get operator mapping (returns tuple for BINARY_OP or single opcode for fallback)
                op_mapping = binary_operator_mapping.get(
                    op_text, OpCode.BINARY_OPERATION
                )
                if isinstance(op_mapping, tuple):
                    # New BINARY_OP format: (OpCode.BINARY_OP, argument)
                    op_code, op_arg = op_mapping
                    bytecode.append(emit(op_code, op_arg))
                else:
                    # Old format or fallback
                    bytecode.append(
                        emit(
                            op_mapping,
                            op_text if op_mapping == OpCode.BINARY_OPERATION else None,
                        )
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
                    emit(
                        op_code, op_text if op_code == OpCode.BINARY_OPERATION else None
                    )
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
                    # Get operator mapping (returns tuple for BINARY_OP or single opcode for fallback)
                    op_mapping = binary_operator_mapping.get(
                        op_text, OpCode.BINARY_OPERATION
                    )
                    if isinstance(op_mapping, tuple):
                        # New BINARY_OP format: (OpCode.BINARY_OP, argument)
                        op_code, op_arg = op_mapping
                        bytecode.append(emit(op_code, op_arg))
                    else:
                        # Old format or fallback
                        bytecode.append(
                            emit(
                                op_mapping,
                                op_text
                                if op_mapping == OpCode.BINARY_OPERATION
                                else None,
                            )
                        )
                else:
                    bytecode.append(emit(OpCode.BINARY_OPERATION, None))
        elif node_type in ["comparison_operator"]:
            # Handle comparison chains like 'a < b < c'
            children = list(node.named_children)
            for i, child in enumerate(children):
                bytecode.extend(
                    self._generate_bytecode(child, source_code_bytes, file_path)
                )
                # For comparison chains with multiple comparisons, copy intermediate values
                if i > 0 and i < len(children) - 1:
                    bytecode.append(emit(OpCode.COPY, 1))
            # For comparison chains, we'll use the generic COMPARE_OP
            bytecode.append(emit(OpCode.COMPARE_OP, None))
        elif node_type in ["not_operator"]:
            operand_node = node.child_by_field_name("operand") or node.children[-1]
            bytecode.extend(
                self._generate_bytecode(operand_node, source_code_bytes, file_path)
            )
            bytecode.append(emit(OpCode.LOGICAL_NOT, None))

        elif node_type in ["call", "call_expression"]:
            func_node = node.child_by_field_name("function")
            args_node = node.child_by_field_name("arguments")

            # Push NULL for function call optimization (Python 3.11+)
            bytecode.append(emit(OpCode.PUSH_NULL, None))

            if func_node:
                bytecode.extend(
                    self._generate_bytecode(func_node, source_code_bytes, file_path)
                )

            arg_count = 0
            kwarg_count = 0
            has_starargs = False
            has_kwargs = False
            kw_names = []  # Collect keyword names for KW_NAMES

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
                            # Handle key=value - Python approach: load values only, names in KW_NAMES
                            name_node = arg.child_by_field_name("name")
                            value_node = arg.child_by_field_name("value")
                            if name_node and value_node:
                                key_name = self._get_node_text(
                                    name_node, source_code_bytes
                                )
                                # Collect keyword name for KW_NAMES tuple
                                kw_names.append(key_name)
                                # Load only the value (not the name)
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
            if kwarg_count > 0:
                # For calls with keyword arguments, emit KW_NAMES with actual tuple
                kw_names_tuple = tuple(kw_names)
                bytecode.append(emit(OpCode.KW_NAMES, kw_names_tuple))
                # Use CALL opcode for Python 3.11+ compatibility
                bytecode.append(emit(OpCode.CALL, arg_count + kwarg_count))
            elif has_starargs:
                bytecode.append(
                    emit(OpCode.BINARY_OPERATION, None)
                )  # CALL_FUNCTION_VAR
            else:
                # Use CALL opcode for Python 3.11+ compatibility
                bytecode.append(emit(OpCode.CALL, arg_count))

        elif node_type in ["update_expression"]:
            # Handle ++, -- operators (JavaScript)
            argument_node = node.child_by_field_name("argument")
            if argument_node:
                # Load current value
                bytecode.extend(
                    self._generate_bytecode(argument_node, source_code_bytes, file_path)
                )
                # Perform increment/decrement
                bytecode.append(emit(OpCode.LOAD_CONST, 1.0))
                op_text = self._get_node_text(node, source_code_bytes)
                if "++" in op_text:
                    bytecode.append(emit(OpCode.BINARY_ADD, None))
                else:  # "--"
                    bytecode.append(emit(OpCode.BINARY_SUBTRACT, None))
                # Store back
                var_name = self._get_node_text(argument_node, source_code_bytes)
                bytecode.append(self._emit_store(var_name))

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
            # Use CALL opcode for Python 3.11+ compatibility
            bytecode.append(emit(OpCode.CALL, arg_count))

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
                bytecode.append(emit(OpCode.LOAD_CONST, None))

            # Emit proper YIELD_VALUE opcode
            bytecode.append(emit(OpCode.YIELD_VALUE, None))

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
                emit(OpCode.BINARY_OPERATION, None)
            )  # Placeholder for string formatting

        elif node_type == "regex":
            # Handle regex literals
            pattern_text = self._get_node_text(node, source_code_bytes)
            bytecode.append(emit(OpCode.LOAD_CONST, pattern_text))

        elif node_type in ["spread_element"]:
            # Handle ...spread syntax
            argument_node = node.child_by_field_name("argument")
            if argument_node:
                bytecode.extend(
                    self._generate_bytecode(argument_node, source_code_bytes, file_path)
                )
                bytecode.append(
                    emit(OpCode.BINARY_OPERATION, None)
                )  # Placeholder for spread

        elif node_type in ["optional_chain"]:
            # Handle ?. optional chaining
            for child in node.named_children:
                bytecode.extend(
                    self._generate_bytecode(child, source_code_bytes, file_path)
                )
            bytecode.append(
                emit(OpCode.BINARY_OPERATION, None)
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
                # Check if this is tuple/list unpacking (Python)
                if name_node.type == "pattern_list":
                    # First evaluate the right side
                    bytecode.extend(
                        self._generate_bytecode(
                            value_node, source_code_bytes, file_path
                        )
                    )
                    # Count the number of targets
                    target_count = len(
                        [
                            child
                            for child in name_node.named_children
                            if child.type == "identifier"
                        ]
                    )
                    # Emit UNPACK_SEQUENCE
                    bytecode.append(emit(OpCode.UNPACK_SEQUENCE, target_count))
                    # Store each unpacked value
                    for child in name_node.named_children:
                        if child.type == "identifier":
                            var_name = self._get_node_text(child, source_code_bytes)
                            bytecode.append(self._emit_store(var_name))
                else:
                    # For other patterns, evaluate right side first
                    bytecode.extend(
                        self._generate_bytecode(
                            value_node, source_code_bytes, file_path
                        )
                    )

                # Handle destructuring patterns (e.g., const { exec, spawn } = ...)
                if name_node.type == "object_pattern":
                    # Extract individual identifiers from destructuring pattern
                    for child in name_node.named_children:
                        if child.type == "shorthand_property_identifier_pattern":
                            identifier_name = self._get_node_text(
                                child, source_code_bytes
                            )
                            bytecode.append(emit(OpCode.STORE_NAME, identifier_name))
                        elif child.type == "pair_pattern":
                            # Handle { key: alias } patterns
                            value_child = child.child_by_field_name("value")
                            if value_child and value_child.type == "identifier":
                                identifier_name = self._get_node_text(
                                    value_child, source_code_bytes
                                )
                                bytecode.append(
                                    emit(OpCode.STORE_NAME, identifier_name)
                                )
                elif name_node.type == "array_pattern":
                    # Handle array destructuring [a, b] = ...
                    for child in name_node.named_children:
                        if child.type == "identifier":
                            identifier_name = self._get_node_text(
                                child, source_code_bytes
                            )
                            bytecode.append(emit(OpCode.STORE_NAME, identifier_name))
                elif name_node.type in ["subscript_expression", "subscript"]:
                    # Handle subscript assignment: obj[key] = value
                    # First load the object
                    object_node = name_node.child_by_field_name(
                        "object"
                    ) or name_node.child_by_field_name("value")
                    index_node = name_node.child_by_field_name(
                        "index"
                    ) or name_node.child_by_field_name("subscript")

                    if object_node and index_node:
                        # Load object
                        bytecode.extend(
                            self._generate_bytecode(
                                object_node, source_code_bytes, file_path
                            )
                        )
                        # Load index/key
                        bytecode.extend(
                            self._generate_bytecode(
                                index_node, source_code_bytes, file_path
                            )
                        )
                        # Store subscript
                        bytecode.append(emit(OpCode.STORE_SUBSCR, None))
                elif name_node.type in ["attribute", "member_expression"]:
                    # Handle attribute assignment: obj.attr = value
                    object_node = name_node.child_by_field_name(
                        "object"
                    ) or name_node.child_by_field_name("value")
                    attribute_node = name_node.child_by_field_name(
                        "attribute"
                    ) or name_node.child_by_field_name("property")

                    if object_node and attribute_node:
                        # Load object
                        bytecode.extend(
                            self._generate_bytecode(
                                object_node, source_code_bytes, file_path
                            )
                        )
                        # Get attribute name
                        attr_name = self._get_node_text(
                            attribute_node, source_code_bytes
                        )
                        # Store attribute
                        bytecode.append(emit(OpCode.STORE_ATTR, attr_name))
                else:
                    # Regular single variable assignment
                    var_name = self._get_node_text(name_node, source_code_bytes)
                    bytecode.append(self._emit_store(var_name))

        elif node_type == "return_statement":
            if node.child_count > 1 and node.children[1].type not in [";"]:
                return_val_node = node.children[1]
                bytecode.extend(
                    self._generate_bytecode(
                        return_val_node, source_code_bytes, file_path
                    )
                )
            bytecode.append(emit(OpCode.RETURN_VALUE, None))

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
                # Perform operation - use BINARY_OP to match Python's pattern
                bytecode.append(emit(OpCode.BINARY_OP, None))
                # Store result
                var_name = self._get_node_text(target_node, source_code_bytes)
                bytecode.append(self._emit_store(var_name))

        elif node_type == "pass_statement":
            # Pass is a no-op, but we'll add a placeholder
            pass

        elif node_type == "break_statement":
            bytecode.append(
                emit(OpCode.BINARY_OPERATION, None)
            )  # Placeholder for break

        elif node_type == "continue_statement":
            bytecode.append(
                emit(OpCode.BINARY_OPERATION, None)
            )  # Placeholder for continue

        elif node_type == "assert_statement":
            # Process the assertion condition
            condition_node = node.children[1] if len(node.children) > 1 else None
            if condition_node:
                bytecode.extend(
                    self._generate_bytecode(
                        condition_node, source_code_bytes, file_path
                    )
                )
            bytecode.append(
                emit(OpCode.BINARY_OPERATION, None)
            )  # Placeholder for assert

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
                emit(OpCode.BINARY_OPERATION, None)
            )  # Placeholder for raise/throw

        elif node_type in [
            "import_statement",
            "import_from_statement",
            "import_declaration",
        ]:
            # Process import with proper Python structure: LOAD_CONST + LOAD_CONST + IMPORT_NAME + STORE_NAME
            # Handles both Python imports and JavaScript ES6 imports

            if node_type == "import_statement":
                # Handle "import module" or "import module as alias"
                for child in node.named_children:
                    if child.type == "dotted_name" or child.type == "identifier":
                        module_name = self._get_node_text(child, source_code_bytes)
                        # Python import pattern: LOAD_CONST 0 + LOAD_CONST None + IMPORT_NAME + STORE_NAME
                        bytecode.append(
                            emit(OpCode.LOAD_CONST, 0)
                        )  # Import level (0 = absolute)
                        bytecode.append(
                            emit(OpCode.LOAD_CONST, None)
                        )  # fromlist (None for simple import)
                        bytecode.append(emit(OpCode.IMPORT_NAME, module_name))
                        bytecode.append(emit(OpCode.STORE_NAME, module_name))
                    elif child.type == "aliased_import":
                        # Handle "import module as alias"
                        module_node = child.child_by_field_name("name")
                        alias_node = child.child_by_field_name("alias")
                        if module_node and alias_node:
                            module_name = self._get_node_text(
                                module_node, source_code_bytes
                            )
                            alias_name = self._get_node_text(
                                alias_node, source_code_bytes
                            )
                            bytecode.append(emit(OpCode.LOAD_CONST, 0))
                            bytecode.append(emit(OpCode.LOAD_CONST, None))
                            bytecode.append(emit(OpCode.IMPORT_NAME, module_name))
                            bytecode.append(
                                emit(OpCode.STORE_NAME, alias_name)
                            )  # Store with alias name

            elif node_type == "import_from_statement":
                # Handle "from module import name" or "from module import name1, name2"
                module_node = node.child_by_field_name("module_name")

                if module_node:
                    module_name = self._get_node_text(module_node, source_code_bytes)

                    # Collect all imported names (there can be multiple with same field name)
                    imported_names = []
                    for i in range(node.child_count):
                        if node.field_name_for_child(i) == "name":
                            name_node = node.child(i)
                            imported_names.append(
                                self._get_node_text(name_node, source_code_bytes)
                            )

                    if imported_names:
                        # Create fromlist tuple for the import
                        bytecode.append(emit(OpCode.LOAD_CONST, 0))  # Import level
                        bytecode.append(
                            emit(OpCode.LOAD_CONST, tuple(imported_names))
                        )  # fromlist as tuple
                        bytecode.append(emit(OpCode.IMPORT_NAME, module_name))

                        # Import each name and store it
                        for imported_name in imported_names:
                            bytecode.append(emit(OpCode.IMPORT_FROM, imported_name))
                            bytecode.append(emit(OpCode.STORE_NAME, imported_name))
                        bytecode.append(
                            emit(OpCode.POP_TOP, None)
                        )  # Clean up module object

            else:  # JavaScript import_declaration
                for child in node.named_children:
                    if child.type == "identifier" or child.type == "dotted_name":
                        name = self._get_node_text(child, source_code_bytes)
                        bytecode.append(emit(OpCode.LOAD_CONST, 0))
                        bytecode.append(emit(OpCode.LOAD_CONST, None))
                        bytecode.append(emit(OpCode.IMPORT_NAME, name))
                        bytecode.append(emit(OpCode.STORE_NAME, name))
                # Handle other cases as needed
                pass

        elif node_type in ["export_statement", "export_default"]:
            # Process exports - for malware analysis, we track exported names
            # Handle both named exports and default exports
            for child in node.named_children:
                if child.type == "identifier":
                    name = self._get_node_text(child, source_code_bytes)
                    if node_type == "export_default":
                        bytecode.append(emit(OpCode.EXPORT_DEFAULT, name))
                    else:
                        bytecode.append(emit(OpCode.EXPORT_NAMED, name))
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
                        bytecode.append(emit(OpCode.EXPORT_NAMED, func_name))
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
                                    bytecode.append(emit(OpCode.EXPORT_NAMED, name))
                    bytecode.extend(
                        self._generate_bytecode(child, source_code_bytes, file_path)
                    )
                else:
                    bytecode.extend(
                        self._generate_bytecode(child, source_code_bytes, file_path)
                    )

        elif node_type in ["global_statement", "nonlocal_statement"]:
            # Process global/nonlocal declarations
            # These are just declarations and don't generate load/store instructions
            for child in node.named_children:
                if child.type == "identifier":
                    name = self._get_node_text(child, source_code_bytes)
                    if node_type == "global_statement":
                        # Track this as a global variable for future references
                        self.global_variables.add(name)
                        # No bytecode generated - this is just a declaration
                    elif node_type == "nonlocal_statement":
                        # Track this as a nonlocal variable for future references
                        self.nonlocal_variables.add(name)
                        # No bytecode generated - this is just a declaration

        elif node_type == "delete_statement":
            # Process delete targets with specific DELETE opcodes
            for child in node.named_children:
                if child.type == "identifier":
                    # Simple variable deletion: del x
                    var_name = self._get_node_text(child, source_code_bytes)
                    bytecode.append(emit(OpCode.DELETE_NAME, var_name))
                elif child.type in ["subscript", "subscript_expression"]:
                    # Subscript deletion: del lst[i] or del dict[key]
                    obj_node = child.child_by_field_name(
                        "value"
                    ) or child.child_by_field_name("object")
                    index_node = child.child_by_field_name(
                        "index"
                    ) or child.child_by_field_name("subscript")

                    if obj_node and index_node:
                        # Load object
                        bytecode.extend(
                            self._generate_bytecode(
                                obj_node, source_code_bytes, file_path
                            )
                        )
                        # Load index/key
                        bytecode.extend(
                            self._generate_bytecode(
                                index_node, source_code_bytes, file_path
                            )
                        )
                        # Delete subscript
                        bytecode.append(emit(OpCode.DELETE_SUBSCR, None))
                elif child.type in ["attribute", "member_expression"]:
                    # Attribute deletion: del obj.attr
                    obj_node = child.child_by_field_name(
                        "object"
                    ) or child.child_by_field_name("value")
                    attr_node = child.child_by_field_name(
                        "attribute"
                    ) or child.child_by_field_name("property")

                    if obj_node and attr_node:
                        # Load object
                        bytecode.extend(
                            self._generate_bytecode(
                                obj_node, source_code_bytes, file_path
                            )
                        )
                        # Get attribute name
                        attr_name = self._get_node_text(attr_node, source_code_bytes)
                        # Delete attribute (using generic DELETE_OPERATOR for now)
                        bytecode.append(emit(OpCode.DELETE_OPERATOR, attr_name))
                else:
                    # For other delete targets, fall back to processing the expression
                    bytecode.extend(
                        self._generate_bytecode(child, source_code_bytes, file_path)
                    )
                    bytecode.append(emit(OpCode.DELETE_OPERATOR, None))

        # --- Control Flow ---
        elif node_type == "if_statement":
            condition_node = node.child_by_field_name("condition")
            consequence_node = node.child_by_field_name("consequence")
            alternative_node = node.child_by_field_name("alternative")

            bytecode.extend(
                self._generate_bytecode(condition_node, source_code_bytes, file_path)
            )

            jump_instr_index = len(bytecode)
            bytecode.append(emit(OpCode.POP_JUMP_IF_FALSE, -1))

            consequence_bytecode = self._generate_bytecode(
                consequence_node, source_code_bytes, file_path
            )
            bytecode.extend(consequence_bytecode)

            if alternative_node:
                jump_over_else_index = len(bytecode)
                bytecode.append(emit(OpCode.JUMP_FORWARD, -1))
                # Set jump target for the initial if to point after the 'then' block
                bytecode[jump_instr_index] = emit(
                    OpCode.POP_JUMP_IF_FALSE, len(bytecode)
                )

                alternative_bytecode = self._generate_bytecode(
                    alternative_node, source_code_bytes, file_path
                )
                bytecode.extend(alternative_bytecode)
                # Set the jump to point after the 'else' block
                bytecode[jump_over_else_index] = emit(
                    OpCode.JUMP_FORWARD, len(bytecode)
                )

            else:
                # If no 'else', the jump just goes to the end of the 'then' block
                bytecode[jump_instr_index] = emit(
                    OpCode.POP_JUMP_IF_FALSE, len(bytecode)
                )

        elif node_type in ["for_statement", "for_in_statement"]:
            # Process for loops with proper Python iteration protocol: GET_ITER → FOR_ITER → body → JUMP_BACKWARD → END_FOR
            iterable_node = node.child_by_field_name(
                "right"
            ) or node.child_by_field_name("iterable")
            left_node = node.child_by_field_name("left") or node.child_by_field_name(
                "variable"
            )
            body_node = node.child_by_field_name("body")

            if iterable_node:
                # Generate iterable expression (e.g., [1, 2, 3] or range(5))
                bytecode.extend(
                    self._generate_bytecode(iterable_node, source_code_bytes, file_path)
                )
                # Get iterator from iterable
                bytecode.append(emit(OpCode.GET_ITER, None))

                # FOR_ITER instruction - will jump to end when iteration is complete
                for_iter_jump_pos = len(bytecode)
                bytecode.append(
                    emit(OpCode.FOR_ITER, -1)
                )  # Placeholder, will fix later

                # Store loop variable (e.g., 'i' in 'for i in ...')
                if left_node:
                    # Handle different types of loop variables
                    if left_node.type == "identifier":
                        var_name = self._get_node_text(left_node, source_code_bytes)
                        bytecode.append(emit(OpCode.STORE_NAME, var_name))
                    elif (
                        left_node.type == "pattern_list"
                        or left_node.type == "tuple_pattern"
                    ):
                        # Handle tuple unpacking: for x, y in items
                        var_count = len(
                            [
                                child
                                for child in left_node.named_children
                                if child.type == "identifier"
                            ]
                        )
                        bytecode.append(emit(OpCode.UNPACK_SEQUENCE, var_count))
                        for child in left_node.named_children:
                            if child.type == "identifier":
                                var_name = self._get_node_text(child, source_code_bytes)
                                bytecode.append(emit(OpCode.STORE_NAME, var_name))

                # Generate loop body
                if body_node:
                    bytecode.extend(
                        self._generate_bytecode(body_node, source_code_bytes, file_path)
                    )

                # Jump back to FOR_ITER for next iteration
                bytecode.append(
                    emit(OpCode.JUMP_BACKWARD, len(bytecode) - for_iter_jump_pos + 1)
                )

                # END_FOR - target for FOR_ITER when iteration completes
                end_for_pos = len(bytecode)
                bytecode.append(emit(OpCode.END_FOR, None))

                # Fix the FOR_ITER jump target to point to END_FOR
                bytecode[for_iter_jump_pos] = emit(
                    OpCode.FOR_ITER, end_for_pos - for_iter_jump_pos - 1
                )

        elif node_type == "while_statement":
            # Process while loops with proper Python pattern: condition → POP_JUMP_IF_FALSE → body → JUMP_BACKWARD
            condition_node = node.child_by_field_name("condition")
            body_node = node.child_by_field_name("body")

            # Mark the start of the loop for JUMP_BACKWARD
            loop_start = len(bytecode)

            if condition_node:
                # Generate condition check
                bytecode.extend(
                    self._generate_bytecode(
                        condition_node, source_code_bytes, file_path
                    )
                )

                # Jump out of loop if condition is false (will patch later)
                exit_jump_pos = len(bytecode)
                bytecode.append(emit(OpCode.POP_JUMP_IF_FALSE, -1))  # Placeholder

            if body_node:
                # Generate loop body
                bytecode.extend(
                    self._generate_bytecode(body_node, source_code_bytes, file_path)
                )

            # Jump back to condition check
            bytecode.append(emit(OpCode.JUMP_BACKWARD, len(bytecode) - loop_start + 1))

            # Fix the exit jump to point here (after the loop)
            if condition_node:
                bytecode[exit_jump_pos] = emit(
                    OpCode.POP_JUMP_IF_FALSE, len(bytecode) - exit_jump_pos - 1
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
                    emit(OpCode.POP_JUMP_IF_TRUE, len(bytecode) - 10)
                )  # Jump back to start

        elif node_type == "debugger_statement":
            # JavaScript debugger statement
            bytecode.append(
                emit(OpCode.BINARY_OPERATION, None)
            )  # Placeholder for debugger

        elif node_type == "labeled_statement":
            # Process labeled statements (JavaScript)
            label_node = node.child_by_field_name("label")
            statement_node = node.child_by_field_name("body")

            if label_node:
                label_name = self._get_node_text(label_node, source_code_bytes)
                bytecode.append(emit(OpCode.LOAD_CONST, label_name))

            if statement_node:
                bytecode.extend(
                    self._generate_bytecode(
                        statement_node, source_code_bytes, file_path
                    )
                )

        elif node_type in ["try_statement"]:
            # Process try/except/finally blocks with Python exception protocol
            body_node = node.child_by_field_name("body")
            except_clauses = []
            finally_clause = None

            # Collect except and finally clauses
            for child in node.children:
                if child.type in ["except_clause", "catch_clause"]:
                    except_clauses.append(child)
                elif child.type == "finally_clause":
                    finally_clause = child

            # Add NOP for try block start (Python pattern)
            bytecode.append(emit(OpCode.NOP, None))

            # Generate try block
            if body_node:
                bytecode.extend(
                    self._generate_bytecode(body_node, source_code_bytes, file_path)
                )

            # Normal completion - return/exit
            bytecode.append(emit(OpCode.RETURN_CONST, None))

            # Exception handling starts here - PUSH_EXC_INFO
            exc_handler_start = len(bytecode)
            bytecode.append(emit(OpCode.PUSH_EXC_INFO, None))

            # Generate except clauses
            for except_clause in except_clauses:
                # Check if this except has a specific exception type
                exception_node = except_clause.child_by_field_name("value")
                except_body = None

                # Find the exception body (last block child)
                for child in except_clause.children:
                    if child.type == "block":
                        except_body = child

                if exception_node:
                    # Load exception type and check match
                    exception_name = self._get_node_text(
                        exception_node, source_code_bytes
                    )
                    bytecode.append(emit(OpCode.LOAD_NAME, exception_name))
                    bytecode.append(emit(OpCode.CHECK_EXC_MATCH, None))

                    # Jump if no match
                    no_match_jump = len(bytecode)
                    bytecode.append(emit(OpCode.POP_JUMP_IF_FALSE, -1))  # Will patch

                    # Pop exception info
                    bytecode.append(emit(OpCode.POP_TOP, None))

                    # Generate except body
                    if except_body:
                        bytecode.extend(
                            self._generate_bytecode(
                                except_body, source_code_bytes, file_path
                            )
                        )

                    # Clean up and return
                    bytecode.append(emit(OpCode.POP_EXCEPT, None))
                    bytecode.append(emit(OpCode.RETURN_CONST, None))

                    # Patch the no-match jump to point here
                    bytecode[no_match_jump] = emit(
                        OpCode.POP_JUMP_IF_FALSE, len(bytecode)
                    )

            # Re-raise if no handler matched
            bytecode.append(emit(OpCode.RERAISE, 0))

            # Exception cleanup (simplified)
            bytecode.append(emit(OpCode.COPY, 3))
            bytecode.append(emit(OpCode.POP_EXCEPT, None))
            bytecode.append(emit(OpCode.RERAISE, 1))
            # Note: Simplified exception handling - real Python uses exception tables
            # This provides basic structural compatibility

        elif node_type == "with_statement":
            # Process with statements - Python structure: context_expr + BEFORE_WITH + STORE_NAME + body + exception_handling
            with_items = []

            # Look for with_clause first, then extract with_items from it
            for child in node.children:
                if child.type == "with_clause":
                    for grandchild in child.children:
                        if grandchild.type == "with_item":
                            with_items.append(grandchild)

            # Process each context manager
            for with_item in with_items:
                # Generate bytecode for the context expression
                context_expr = None
                as_pattern = None

                for child in with_item.children:
                    if child.type == "as_pattern":
                        # Extract the expression and the target from as_pattern
                        for as_child in child.children:
                            if as_child.type not in ["as", "as_pattern_target"]:
                                context_expr = as_child
                            elif as_child.type == "as_pattern_target":
                                # Extract identifier from as_pattern_target
                                for target_child in as_child.children:
                                    if target_child.type == "identifier":
                                        as_pattern = target_child
                    elif child.type not in ["as", "identifier", ","]:
                        context_expr = child

                if context_expr:
                    # Generate context expression (e.g., open("file", "r"))
                    bytecode.extend(
                        self._generate_bytecode(
                            context_expr, source_code_bytes, file_path
                        )
                    )
                    # Python WITH protocol: BEFORE_WITH
                    bytecode.append(emit(OpCode.BEFORE_WITH, None))

                    # Handle 'as' variable if present (e.g., "as f:")
                    if as_pattern:
                        var_name = self._get_node_text(as_pattern, source_code_bytes)
                        bytecode.append(emit(OpCode.STORE_NAME, var_name))

            # Process the body
            body_node = node.child_by_field_name("body")
            if body_node:
                bytecode.extend(
                    self._generate_bytecode(body_node, source_code_bytes, file_path)
                )

            # Python WITH cleanup: Load None, None, None + CALL + POP_TOP (normal exit)
            bytecode.append(emit(OpCode.LOAD_CONST, None))
            bytecode.append(emit(OpCode.LOAD_CONST, None))
            bytecode.append(emit(OpCode.LOAD_CONST, None))
            bytecode.append(emit(OpCode.CALL, 2))
            bytecode.append(emit(OpCode.POP_TOP, None))

            # WITH exception handling protocol
            bytecode.append(emit(OpCode.PUSH_EXC_INFO, None))
            bytecode.append(emit(OpCode.WITH_EXCEPT_START, None))

            # Jump to cleanup if exception handler returns True
            cleanup_jump_pos = len(bytecode)
            bytecode.append(emit(OpCode.POP_JUMP_IF_TRUE, -1))  # Placeholder

            # Re-raise exception if handler returns False
            bytecode.append(emit(OpCode.RERAISE, 2))

            # Cleanup handler (jump target)
            cleanup_start = len(bytecode)
            bytecode.append(emit(OpCode.POP_TOP, None))
            bytecode.append(emit(OpCode.POP_EXCEPT, None))
            bytecode.append(emit(OpCode.POP_TOP, None))
            bytecode.append(emit(OpCode.POP_TOP, None))

            # Jump back to normal flow
            return_jump_pos = len(bytecode)
            bytecode.append(emit(OpCode.JUMP_BACKWARD, -1))  # Placeholder

            # Exception re-raise cleanup
            bytecode.append(emit(OpCode.COPY, 3))
            bytecode.append(emit(OpCode.POP_EXCEPT, None))
            bytecode.append(emit(OpCode.RERAISE, 1))

            # Fix jump targets
            bytecode[cleanup_jump_pos] = emit(OpCode.POP_JUMP_IF_TRUE, cleanup_start)
            bytecode[return_jump_pos] = emit(
                OpCode.JUMP_BACKWARD, len(bytecode) - return_jump_pos + 1
            )

        elif node_type in ["lambda", "arrow_function"]:
            # Process lambda/arrow functions
            body_node = node.child_by_field_name("body")
            if body_node:
                # Extract parameters and set context for this function
                params = self._extract_function_parameters(node, source_code_bytes)
                previous_params = self.current_function_params
                previous_in_function = self._in_function_scope
                self.current_function_params = params
                self._in_function_scope = True

                func_body_bytecode = self._generate_bytecode(
                    body_node, source_code_bytes, file_path
                )
                if (
                    not func_body_bytecode
                    or func_body_bytecode[-1].opcode != OpCode.RETURN_VALUE
                ):
                    func_body_bytecode.append(emit(OpCode.RETURN_VALUE, None))

                # Restore previous parameter context
                self.current_function_params = previous_params
                self._in_function_scope = previous_in_function

                func_source = self._get_node_text(body_node, source_code_bytes)
                location = (body_node.start_point[0] + 1, body_node.end_point[0] + 1)

                # Create separate CodeObject and add to collection
                func_code_obj = CodeObject(
                    "lambda",
                    func_body_bytecode,
                    func_source,
                    file_path,
                    location,
                    self.language_name,
                )
                self.code_objects.append(func_code_obj)

                # Use function name in bytecode instead of nested CodeObject
                bytecode.append(emit(OpCode.MAKE_FUNCTION, "lambda"))

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
            bytecode.append(emit(OpCode.POP_JUMP_IF_FALSE, -1))

            if consequence_node:
                bytecode.extend(
                    self._generate_bytecode(
                        consequence_node, source_code_bytes, file_path
                    )
                )

            jump_over_else = len(bytecode)
            bytecode.append(emit(OpCode.JUMP_FORWARD, -1))

            bytecode[jump_if_false] = emit(OpCode.POP_JUMP_IF_FALSE, len(bytecode))

            if alternative_node:
                bytecode.extend(
                    self._generate_bytecode(
                        alternative_node, source_code_bytes, file_path
                    )
                )

            bytecode[jump_over_else] = emit(OpCode.JUMP_FORWARD, len(bytecode))

        elif node_type == "named_expression":
            # Handle walrus operator (:=) in Python - proper pattern with COPY
            target_node = node.child_by_field_name("name")
            value_node = node.child_by_field_name("value")

            if value_node:
                # Generate bytecode for the value expression
                bytecode.extend(
                    self._generate_bytecode(value_node, source_code_bytes, file_path)
                )

                # Copy the value on stack (so one copy remains for return)
                bytecode.append(emit(OpCode.COPY, 1))

                # Store the copied value in the target variable
                if target_node:
                    target_name = self._get_node_text(target_node, source_code_bytes)
                    bytecode.append(emit(OpCode.STORE_NAME, target_name))
                # Original value remains on stack for parent expression

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
                        bytecode.append(emit(OpCode.LOAD_CONST, None))

                    if stop_node:
                        bytecode.extend(
                            self._generate_bytecode(
                                stop_node, source_code_bytes, file_path
                            )
                        )
                    else:
                        bytecode.append(emit(OpCode.LOAD_CONST, None))

                    if step_node:
                        bytecode.extend(
                            self._generate_bytecode(
                                step_node, source_code_bytes, file_path
                            )
                        )
                    else:
                        bytecode.append(emit(OpCode.LOAD_CONST, None))

                    bytecode.append(emit(OpCode.BINARY_OPERATION, None))  # BUILD_SLICE
                    bytecode.append(emit(OpCode.BINARY_SUBSCR, None))
                else:
                    # Regular subscript access
                    bytecode.extend(
                        self._generate_bytecode(
                            index_node, source_code_bytes, file_path
                        )
                    )
                    bytecode.append(emit(OpCode.BINARY_SUBSCR, None))

        elif node_type in ["attribute", "member_expression"]:
            # Handle attribute access: obj.attr (Python) or obj.prop (JavaScript)
            # Generate individual LOAD_ATTR operations for each step in the chain
            object_node = node.child_by_field_name(
                "object"
            ) or node.child_by_field_name("value")
            attribute_node = node.child_by_field_name(
                "attribute"
            ) or node.child_by_field_name("property")

            if object_node:
                # Load the object first (this may recursively handle chained attributes)
                bytecode.extend(
                    self._generate_bytecode(object_node, source_code_bytes, file_path)
                )

            if attribute_node:
                attr_name = self._get_node_text(attribute_node, source_code_bytes)
                bytecode.append(emit(OpCode.LOAD_ATTR, attr_name))

        elif node_type in ["f_string", "formatted_string_literal"]:
            # Handle f-string with interpolation: f"Hello {name}!"
            # Collect string parts and format positions
            parts = []
            format_count = 0

            # Handle f-strings more accurately
            if node_type == "string" and len(node.children) > 0:
                # Check if it's an f-string by looking at string_start
                first_child = node.children[0]
                if first_child.type == "string_start":
                    string_start = self._get_node_text(first_child, source_code_bytes)
                    if string_start.startswith("f"):
                        # Process f-string children
                        for child in node.children[
                            1:-1
                        ]:  # Skip string_start and string_end
                            if child.type == "string_content":
                                # Regular string part
                                text = self._get_node_text(child, source_code_bytes)
                                if text:  # Only add non-empty strings
                                    bytecode.append(emit(OpCode.LOAD_CONST, text))
                                    parts.append("str")
                            elif child.type == "interpolation":
                                # Expression to format
                                expr_node = child.child_by_field_name("expression")
                                if not expr_node and child.named_children:
                                    expr_node = child.named_children[0]
                                if expr_node:
                                    bytecode.extend(
                                        self._generate_bytecode(
                                            expr_node, source_code_bytes, file_path
                                        )
                                    )
                                    bytecode.append(emit(OpCode.FORMAT_VALUE, None))
                                    parts.append("fmt")
                                    format_count += 1

                        # Build the final string
                        if len(parts) > 0:
                            bytecode.append(emit(OpCode.BUILD_STRING, len(parts)))
                        return bytecode

            # Fallback to old behavior for other string types
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
                    bytecode.append(emit(OpCode.LOAD_CONST, text_content))
                    string_parts += 1

            # Build the formatted string
            if string_parts > 1:
                bytecode.append(
                    emit(OpCode.BINARY_OPERATION, None)
                )  # String format/join

        elif node_type == "concatenated_string":
            # Handle implicit string concatenation: "hello" "world"
            for child in node.named_children:
                if child.type == "string":
                    bytecode.extend(
                        self._generate_bytecode(child, source_code_bytes, file_path)
                    )
            # Concatenate strings
            bytecode.append(emit(OpCode.BINARY_ADD, None))

        # --- Decorated Definitions (Functions with decorators) ---
        elif node_type == "decorated_definition":
            # Handle @decorator def function() patterns - match Python's exact pattern
            decorators = []
            function_node = node.child_by_field_name("definition")

            # Collect decorators
            for child in node.children:
                if child.type == "decorator":
                    # Extract decorator name from @decorator_name
                    for decorator_child in child.children:
                        if decorator_child.type == "identifier":
                            decorator_name = self._get_node_text(
                                decorator_child, source_code_bytes
                            )
                            decorators.append(decorator_name)

            if function_node and decorators:
                func_name = self._get_node_text(
                    function_node.child_by_field_name("name"), source_code_bytes
                )

                # Load decorator (outermost first for nested decorators)
                for decorator_name in reversed(decorators):
                    bytecode.append(emit(OpCode.LOAD_NAME, decorator_name))

                # Generate function code object and MAKE_FUNCTION (but don't store yet)
                # This mimics Python's pattern: LOAD_CONST <code_object> + MAKE_FUNCTION
                body_node = function_node.child_by_field_name("body")
                if body_node:
                    # Extract function parameters
                    params = self._extract_function_parameters(
                        function_node, source_code_bytes
                    )

                    # Set context for this function
                    previous_params = self.current_function_params
                    previous_in_function = self._in_function_scope
                    self.current_function_params = params
                    self._in_function_scope = True

                    # Generate function body bytecode
                    func_body_bytecode = self._generate_bytecode(
                        body_node, source_code_bytes, file_path
                    )

                    # Ensure function ends with RETURN_VALUE
                    if (
                        not func_body_bytecode
                        or func_body_bytecode[-1].opcode != OpCode.RETURN_VALUE
                    ):
                        func_body_bytecode.append(emit(OpCode.RETURN_VALUE, None))

                    # Restore previous context
                    self.current_function_params = previous_params
                    self._in_function_scope = previous_in_function

                    # Get function source and location
                    func_source = self._get_node_text(function_node, source_code_bytes)
                    location = (
                        function_node.start_point[0] + 1,
                        function_node.end_point[0] + 1,
                    )

                    # Create separate CodeObject and add to collection
                    func_code_obj = CodeObject(
                        func_name,
                        func_body_bytecode,
                        func_source,
                        file_path,
                        location,
                        self.language_name,
                    )
                    self.code_objects.append(func_code_obj)

                    # Load function code object and make function
                    bytecode.append(emit(OpCode.LOAD_CONST, func_code_obj))
                    bytecode.append(emit(OpCode.MAKE_FUNCTION, 0))

                    # Apply decorator(s) - CALL with 0 args (function is on stack)
                    for i in range(len(decorators)):
                        bytecode.append(emit(OpCode.CALL, 0))

                    # Store the decorated function
                    bytecode.append(emit(OpCode.STORE_NAME, func_name))

        # --- High-Level Structures (Functions, Classes) ---
        elif node_type in [
            "function_definition",
            "function_declaration",
            "generator_function_declaration",
        ]:
            func_name = self._get_node_text(
                node.child_by_field_name("name"), source_code_bytes
            )
            body_node = node.child_by_field_name("body")

            # Check if this is an async or generator function
            is_async = False
            is_generator = False

            # Generator functions are explicitly marked by node type in JavaScript
            if node_type == "generator_function_declaration":
                is_generator = True

            for child in node.children:
                if (
                    child.type == "async"
                    or self._get_node_text(child, source_code_bytes) == "async"
                ):
                    is_async = True
                elif (
                    child.type == "*"
                    or self._get_node_text(child, source_code_bytes) == "*"
                ):
                    is_generator = True

            # Also check for generator functions by looking for yield in the body
            if not is_generator and body_node:
                is_generator = self._contains_yield(body_node, source_code_bytes)

            # Extract parameters and set context for this function
            params = self._extract_function_parameters(node, source_code_bytes)
            previous_params = self.current_function_params
            previous_in_function = self._in_function_scope
            previous_nesting_depth = self._nesting_depth
            self.current_function_params = params
            self._in_function_scope = True
            self._nesting_depth += 1

            func_body_bytecode = self._generate_bytecode(
                body_node, source_code_bytes, file_path
            )
            if (
                not func_body_bytecode
                or func_body_bytecode[-1].opcode != OpCode.RETURN_VALUE
            ):
                func_body_bytecode.append(emit(OpCode.RETURN_VALUE, None))

            # Restore previous parameter context
            self.current_function_params = previous_params
            self._in_function_scope = previous_in_function
            self._nesting_depth = previous_nesting_depth

            func_source = self._get_node_text(body_node, source_code_bytes)
            location = (body_node.start_point[0] + 1, body_node.end_point[0] + 1)

            # Only create separate CodeObject for top-level functions (nesting_depth == 0)
            if self._nesting_depth == 0:
                # Create separate CodeObject and add to collection
                func_code_obj = CodeObject(
                    func_name,
                    func_body_bytecode,
                    func_source,
                    file_path,
                    location,
                    self.language_name,
                )
                self.code_objects.append(func_code_obj)

                # Python-like structure: LOAD_CONST -> MAKE_FUNCTION -> STORE_NAME
                # Load the code object as a constant (similar to Python's approach)
                bytecode.append(emit(OpCode.LOAD_CONST, func_code_obj))

                # Use appropriate opcode based on function type with arg=0 (no defaults)
                if is_async and is_generator:
                    # Async generator function
                    bytecode.append(emit(OpCode.ASYNC_FUNCTION, 0))
                elif is_async:
                    bytecode.append(emit(OpCode.ASYNC_FUNCTION, 0))
                elif is_generator:
                    bytecode.append(emit(OpCode.GENERATOR_FUNCTION, 0))
                else:
                    bytecode.append(emit(OpCode.MAKE_FUNCTION, 0))
                bytecode.append(self._emit_store(func_name))
            else:
                # For nested functions, inline the bytecode directly
                # Use appropriate opcode based on function type (but inline the body)
                if is_async and is_generator:
                    bytecode.append(emit(OpCode.ASYNC_FUNCTION, func_name))
                elif is_async:
                    bytecode.append(emit(OpCode.ASYNC_FUNCTION, func_name))
                elif is_generator:
                    bytecode.append(emit(OpCode.GENERATOR_FUNCTION, func_name))
                else:
                    bytecode.append(emit(OpCode.MAKE_FUNCTION, func_name))

                # Inline the function body bytecode
                bytecode.extend(func_body_bytecode)
                bytecode.append(self._emit_store(func_name))

        elif node_type in ["class_definition", "class_declaration"]:
            class_name = self._get_node_text(
                node.child_by_field_name("name"), source_code_bytes
            )
            body_node = node.child_by_field_name("body")

            # Track nesting depth for classes too
            previous_nesting_depth = self._nesting_depth
            self._nesting_depth += 1

            class_body_bytecode = self._generate_bytecode(
                body_node, source_code_bytes, file_path
            )

            # Restore nesting depth
            self._nesting_depth = previous_nesting_depth

            class_source = self._get_node_text(body_node, source_code_bytes)
            location = (body_node.start_point[0] + 1, body_node.end_point[0] + 1)

            # Only create separate CodeObject for top-level classes (nesting_depth == 0)
            if self._nesting_depth == 0:
                # Create separate CodeObject and add to collection
                class_code_obj = CodeObject(
                    class_name,
                    class_body_bytecode,
                    class_source,
                    file_path,
                    location,
                    self.language_name,
                )
                self.code_objects.append(class_code_obj)

                # Python class protocol: PUSH_NULL + LOAD_BUILD_CLASS + LOAD_CONST + MAKE_FUNCTION + class_name + CALL
                bytecode.append(emit(OpCode.PUSH_NULL, None))
                bytecode.append(emit(OpCode.LOAD_BUILD_CLASS, None))
                bytecode.append(
                    emit(OpCode.LOAD_CONST, class_code_obj)
                )  # Class code object
                bytecode.append(emit(OpCode.MAKE_FUNCTION, 0))  # No defaults
                bytecode.append(emit(OpCode.LOAD_CONST, class_name))  # Class name
                bytecode.append(emit(OpCode.CALL, 2))  # Call build class with 2 args
                bytecode.append(self._emit_store(class_name))
            else:
                # For nested classes, inline the bytecode directly
                bytecode.append(emit(OpCode.MAKE_CLASS, class_name))
                # Inline the class body bytecode
                bytecode.extend(class_body_bytecode)
                bytecode.append(self._emit_store(class_name))

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
                bytecode.append(emit(OpCode.BUILD_LIST, 0))
            elif node_type == "dictionary_comprehension":
                bytecode.append(emit(OpCode.BUILD_MAP, 0))
            elif node_type == "set_comprehension":
                bytecode.append(emit(OpCode.BUILD_SET, 0))

            # Track comprehension variables for proper scoping
            comp_vars = set()

            # Process for clauses (nested loops)
            for var_node, iterable_node in for_clauses:
                if iterable_node:
                    bytecode.extend(
                        self._generate_bytecode(
                            iterable_node, source_code_bytes, file_path
                        )
                    )
                    bytecode.append(emit(OpCode.GET_ITER, None))

                    # Loop start
                    loop_start = len(bytecode)
                    bytecode.append(emit(OpCode.FOR_ITER, -1))  # Will be patched

                    if var_node:
                        var_name = self._get_node_text(var_node, source_code_bytes)
                        bytecode.append(emit(OpCode.STORE_FAST, var_name))
                        # Track this as comprehension variable
                        comp_vars.add(var_name)
                        self.comprehension_variables.add(var_name)

                    # Process if clauses (filters)
                    for condition_node in if_clauses:
                        bytecode.extend(
                            self._generate_bytecode(
                                condition_node, source_code_bytes, file_path
                            )
                        )
                        bytecode.append(emit(OpCode.POP_JUMP_IF_FALSE, loop_start))

                    # Generate element expression
                    if element_expr:
                        if node_type == "dictionary_comprehension":
                            # For dict comprehensions, element_expr is a pair node
                            key_node = element_expr.child_by_field_name("key")
                            value_node = element_expr.child_by_field_name("value")
                            if key_node and value_node:
                                # Load key
                                bytecode.extend(
                                    self._generate_bytecode(
                                        key_node, source_code_bytes, file_path
                                    )
                                )
                                # Load value
                                bytecode.extend(
                                    self._generate_bytecode(
                                        value_node, source_code_bytes, file_path
                                    )
                                )
                                # Add to dict
                                bytecode.append(emit(OpCode.MAP_ADD, 1))
                        else:
                            # For list/set comprehensions, generate the element
                            bytecode.extend(
                                self._generate_bytecode(
                                    element_expr, source_code_bytes, file_path
                                )
                            )
                            # Add to collection
                            if node_type == "list_comprehension":
                                bytecode.append(emit(OpCode.LIST_APPEND, 1))
                            elif node_type == "set_comprehension":
                                bytecode.append(emit(OpCode.SET_ADD, 1))

                    # Jump back to loop start
                    bytecode.append(emit(OpCode.JUMP_FORWARD, loop_start))

                    # Patch FOR_ITER to jump here when done
                    bytecode[loop_start] = emit(OpCode.FOR_ITER, len(bytecode))

            # Clean up comprehension variables from scope tracking
            for var_name in comp_vars:
                self.comprehension_variables.discard(var_name)

        elif node_type in ["await", "await_expression"]:
            # Process await expressions: await expression
            awaitable_node = node.child_by_field_name(
                "awaitable"
            ) or node.child_by_field_name("argument")
            if awaitable_node:
                bytecode.extend(
                    self._generate_bytecode(
                        awaitable_node, source_code_bytes, file_path
                    )
                )
            else:
                # Fallback: look for first expression child
                for child in node.named_children:
                    if child.type not in ["await"]:  # Skip await keyword
                        bytecode.extend(
                            self._generate_bytecode(child, source_code_bytes, file_path)
                        )
                        break
            bytecode.append(emit(OpCode.AWAIT_EXPRESSION, None))

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
                            emit(OpCode.BINARY_OPERATION, None)
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

        elif node_type == "expression_statement":
            # Handle expression statements - expressions whose values are discarded
            for child in node.children:
                if child.type not in [";", "\n"]:  # Skip semicolons and newlines
                    # Check if this is an assignment (which doesn't need POP_TOP)
                    if child.type not in [
                        "assignment",
                        "assignment_expression",
                        "augmented_assignment",
                    ]:
                        bytecode.extend(
                            self._generate_bytecode(child, source_code_bytes, file_path)
                        )
                        # Add POP_TOP to discard the expression result (but not for assignments)
                        bytecode.append(emit(OpCode.POP_TOP, None))
                    else:
                        # For assignments, just generate the bytecode without POP_TOP
                        bytecode.extend(
                            self._generate_bytecode(child, source_code_bytes, file_path)
                        )

        # --- Block, Module, and Program Handling ---
        elif node_type in [
            "block",
            "module",
            "program",
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

    def process_file(self, file_path: Path) -> List[CodeObject]:
        """Processes a single file and returns its generated CodeObjects."""
        try:
            source_code_bytes = file_path.read_bytes()

            ast = self.bytes_to_treesitter_ast(
                source_code_bytes=source_code_bytes,
                file_path=str(file_path),
            )

            if ast:
                malwicode_objects = self.treesitter_ast_to_malwicode(
                    root_node=ast,
                    source_code_bytes=source_code_bytes,
                    file_path=file_path,
                )
                return malwicode_objects

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
        default=[".py", ".js"],
        help="A list of file extensions to process (e.g., .py .js).",
    )
    parser.add_argument(
        "-f",
        "--format",
        type=str,
        choices=["console", "csv"],
        default="console",
        help="Output format (default: console). 'csv' outputs oneline_mapped format to console or file if --save is provided.",
    )
    parser.add_argument(
        "-s",
        "--save",
        type=str,
        default=None,
        metavar="FILEPATH",
        help="Path to save the output. When using --format csv, if not provided output goes to console.",
    )
    args = parser.parse_args()

    # CSV format no longer requires --save flag; will print to console if not specified

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

    # Initialize CSV writer if needed
    csv_writer_instance: Optional[CSVWriter] = None

    try:
        if args.format == "csv" and args.save:
            print("Setting up CSV output...")
            save_path = Path(args.save)
            save_path.parent.mkdir(parents=True, exist_ok=True)
            csv_writer_instance = CSVWriter(save_path)
            print(f"CSV output will be saved to: {save_path.resolve()}")
        elif args.format == "csv" and not args.save:
            # Print CSV header to console
            print("tokens,hash,language,filepath")

        for source in tqdm(source_files, desc="Processing files", unit="file"):
            lang = None
            if source.suffix == ".py":
                lang = "python"
            elif source.suffix == ".js":
                lang = "javascript"

            compiler_instance = compilers.get(lang)
            if compiler_instance:
                code_objects = compiler_instance.process_file(source)

                if args.format == "csv":
                    if csv_writer_instance:
                        # Write to CSV file
                        csv_writer_instance.write_code_objects(code_objects)
                    else:
                        # Print CSV to console
                        for obj in code_objects:
                            row = [
                                obj.to_string(one_line=True),
                                obj.to_hash(),
                                obj.language,
                                str(obj.path),
                            ]
                            # Escape quotes in tokens field if necessary
                            tokens = (
                                row[0].replace('"', '""') if '"' in row[0] else row[0]
                            )
                            print(f'"{tokens}",{row[1]},{row[2]},{row[3]}')
                else:
                    for i, code_obj in enumerate(code_objects):
                        print(f"{code_obj.to_string(one_line=False)}")
            else:
                if args.format == "console":
                    print(f"Skipping unsupported file extension: {source.name}")

        if args.format == "csv" and csv_writer_instance:
            csv_writer_instance.close()
            print(
                f"Successfully processed {sources_count} files to CSV: {save_path.resolve()}"
            )

    except Exception as e:
        print(f"Error during processing: {e}")
        if csv_writer_instance:
            csv_writer_instance.close()
        return


if __name__ == "__main__":
    main()
