# Python Grammar Mapping

See symbols: https://github.com/tree-sitter/tree-sitter-python/blob/master/src/grammar.json.

## 1. Top-Level & Statements

- `expression_statement`: A statement consisting primarily of an expression (e.g., a function call, assignment).
- `assert_statement`: The `assert` keyword and its conditions.
- `pass_statement`: The `pass` keyword.
- `delete_statement`: The `del` keyword and targets.
- `return_statement`: The `return` keyword and optional value.
- `raise_statement`: The `raise` keyword with optional exception and cause.
- `break_statement`: The `break` keyword.
- `continue_statement`: The `continue` keyword.
- `global_statement`: The `global` keyword and identifiers.
- `nonlocal_statement`: The `nonlocal` keyword and identifiers.
- `exec_statement`: The `exec` keyword (Python 2 syntax remnant).
- `print_statement`: The `print` keyword (Python 2 syntax remnant).

## 2. Compound Statements & Clauses

- `if_statement`: `if`/`elif`/`else` structure.
- `elif_clause`: An `elif` branch.
- `else_clause`: An `else` branch (used in `if`, `for`, `while`, `try`).
- `for_statement`: `for` loop structure.
- `while_statement`: `while` loop structure.
- `try_statement`: `try`/`except`/`else`/`finally` structure.
- `except_clause`: An `except` block.
- `except_group_clause`: An `except*` block.
- `finally_clause`: A `finally` block.
- `with_statement`: `with` statement structure.
- `with_clause`: The items following the `with` keyword.
- `with_item`: A single context manager item in a `with` statement.
- `match_statement`: `match`/`case` structure.
- `case_clause`: A `case` block within a `match` statement.
- `function_definition`: `def` statement structure.
- `class_definition`: `class` statement structure.
- `decorated_definition`: A definition preceded by decorators.
- `decorator`: `@` symbol followed by an expression.

## 3. Expressions

- `expression`: General category for expressions.
- `primary_expression`: Core building blocks of expressions (literals, identifiers, calls, etc.).
- `expression_list`: Comma-separated list of expressions.
- `comparison_operator`: Comparisons like `<`, `>`, `==`, `in`, `is`.
- `not_operator`: Logical `not`.
- `boolean_operator`: Logical `and`, `or`.
- `binary_operator`: Arithmetic, bitwise operators (`+`, `-`, `*`, `|`, `&`, `^`, `<<`, `>>`, etc.).
- `unary_operator`: Unary `+`, `-`, `~`.
- `lambda`: `lambda` function definition.
- `lambda_within_for_in_clause`: Special case for lambda in comprehension `if`.
- `conditional_expression`: Ternary `x if y else z` expression.
- `named_expression`: Walrus operator `:=`.
- `await`: `await` keyword for async operations.
- `yield`: `yield` or `yield from` expression.
- `attribute`: Accessing attributes with `.` (e.g., `obj.attr`).
- `subscript`: Indexing or slicing with `[]` (e.g., `lst[0]`, `d['key']`).
- `slice`: Represents a slice `[start:stop:step]`.
- `call`: Function or method call with `()`.
- `keyword_argument`: Arguments like `key=value` in calls.
- `chevron`: `>>` redirection in Python 2 `print` statement.

## 4. Literals & Basic Elements

- `identifier`: Variable, function, class names, etc..
- `keyword_identifier`: Keywords used as identifiers where context allows (e.g., `print`, `match`).
- `string`: String literal.
- `concatenated_string`: Implicit joining of adjacent string literals.
- `integer`: Integer literal.
- `float`: Floating-point literal.
- `true`: Boolean `True` literal.
- `false`: Boolean `False` literal.
- `none`: `None` literal.
- `ellipsis`: `...` literal.

## 5. Container Literals & Comprehensions

- `list`: List literal `[]` or list comprehension.
- `list_comprehension`: `[expr for x in iterable ...]`.
- `dictionary`: Dictionary literal `{}` or dict comprehension.
- `dictionary_comprehension`: `{key: val for ...}`.
- `set`: Set literal `{}` or set comprehension.
- `set_comprehension`: `{expr for x in iterable ...}`.
- `tuple`: Tuple literal `()`.
- `parenthesized_expression`: Expression enclosed in `()`.
- `generator_expression`: `(expr for x in iterable ...)`.
- `pair`: `key: value` pair in dictionary literals/comprehensions.
- `for_in_clause`: `for x in iterable` part of comprehensions.
- `if_clause`: `if condition` part of comprehensions or match guards.
- `list_splat`: `*expr` used inside lists, tuples, calls.
- `dictionary_splat`: `**expr` used inside dictionaries, calls.
- `parenthesized_list_splat`: `(*expr)` needed for precedence.

## 6. Imports

- `import_statement`: `import module` or `import module as alias`.
- `import_from_statement`: `from module import name` or `from . import name`.
- `future_import_statement`: `from __future__ import feature`.
- `import_prefix`: Leading dots `.` for relative imports.
- `relative_import`: Import path starting with dots.
- `dotted_name`: Name possibly containing dots (e.g., `module.submodule.name`).
- `aliased_import`: `name as alias`.
- `wildcard_import`: `*` in `from module import *`.

## 7. Definitions, Parameters & Arguments

- `parameters`: Formal parameters in `()` for function definition.
- `lambda_parameters`: Parameters for a `lambda`.
- `parameter`: A single parameter in a definition.
- `typed_parameter`: Parameter with a type hint (e.g., `x: int`).
- `default_parameter`: Parameter with a default value (e.g., `x=1`).
- `typed_default_parameter`: Parameter with type hint and default value.
- `list_splat_pattern`: `*args` parameter.
- `dictionary_splat_pattern`: `**kwargs` parameter.
- `positional_separator`: `/` separator in parameters.
- `keyword_separator`: `*` separator in parameters.
- `argument_list`: Actual arguments in `()` for a call.

## 8. Patterns (Assignment & Match)

- `pattern`: General category for patterns used in assignment and `match`.
- `pattern_list`: Comma-separated list of patterns (often on LHS of assignment).
- `assignment`: Standard assignment `=` or typed assignment `:`.
- `augmented_assignment`: Operators like `+=`, `-=` etc..
- `tuple_pattern`: Pattern matching a tuple `(a, b)`.
- `list_pattern`: Pattern matching a list `[a, b]`.
- `as_pattern`: Capturing a sub-pattern with `as` (in `match` or `with`).
- `case_pattern`: Pattern used in a `case` clause.
- `union_pattern`: `|` operator joining patterns in `case`.
- `dict_pattern`: Dictionary pattern `{...}` in `case`.
- `keyword_pattern`: `name=pattern` in `class_pattern` or `dict_pattern`.
- `splat_pattern`: `*name` or `**name` pattern in sequences or mappings.
- `class_pattern`: Pattern matching an object instance `ClassName(...)`.
- `complex_pattern`: Pattern matching complex numbers.

## 9. Types & Type Hinting

- `type`: Represents a type annotation.
- `type_parameter`: Generic type parameters in `[...]`.
- `type_alias_statement`: `type Name = TypeExpr`.
- `splat_type`: `*Ts` or `**P` in type hints.
- `generic_type`: Type with parameters like `list[int]`.
- `union_type`: `|` operator for types (e.g., `int | str`).
- `constrained_type`: Type variable bounds `T: Constraint`.
- `member_type`: Accessing types within types `X.Y`.

## 10. String Formatting & Internals

- `string_start`: Opening quote(s) of a string (`"`, `'`, `f"`, `r'`, etc.).
- `string_content`: Text content within a string.
- `interpolation`: Formatted expression `{expr}` inside f-string.
- `escape_interpolation`: Escaped braces `{{` or `}}` in f-strings.
- `escape_sequence`: Sequences like `\n`, `\t`, `\x...`.
- `format_specifier`: Part after `:` in f-string interpolation `{expr:spec}`.
- `type_conversion`: `!s`, `!r`, `!a` conversion flags in f-strings.
- `string_end`: Closing quote(s) of a string.

## 11. Structural & Helper Symbols

- `block`: An indented block of statements.
- `comment`: `#` followed by text (external token).
- `line_continuation`: Backslash `\` followed by newline.
