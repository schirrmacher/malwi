# JavaScript Grammar Mapping

See symbols: https://github.com/tree-sitter/tree-sitter-python/blob/master/src/grammar.json.

## 1. Top-Level & Program Structure

- `program`: The root node of the program.
- `hash_bang_line`: Shebang line (`#!/usr/bin/env node`).
- `statement`: General category for statements.

## 2. Statements

- `expression_statement`: A statement consisting of an expression.
- `statement_block`: A block of statements enclosed in `{}`.
- `empty_statement`: A lone semicolon `;`.
- `debugger_statement`: The `debugger` keyword.
- `if_statement`: `if (...) ... else ...` structure.
- `else_clause`: The `else` part of an `if` statement.
- `switch_statement`: `switch (...) { ... }` structure.
- `switch_body`: The `{...}` block containing cases in a `switch`.
- `switch_case`: `case value: ...` within a `switch`.
- `switch_default`: `default: ...` within a `switch`.
- `for_statement`: C-style `for (init; condition; increment) ...` loop.
- `for_in_statement`: `for (variable in object) ...` or `for (variable of iterable) ...` loop.
- `while_statement`: `while (condition) ...` loop.
- `do_statement`: `do { ... } while (condition);` loop.
- `try_statement`: `try { ... } catch (...) { ... } finally { ... }` structure.
- `catch_clause`: `catch (error) { ... }` part of a `try` statement.
- `finally_clause`: `finally { ... }` part of a `try` statement.
- `with_statement`: `with (object) ...` statement (deprecated).
- `break_statement`: `break label;`.
- `continue_statement`: `continue label;`.
- `return_statement`: `return value;`.
- `throw_statement`: `throw value;`.
- `labeled_statement`: `label: statement`.

## 3. Declarations

- `declaration`: General category for declarations.
- `variable_declaration`: `var name = value, ...;` declaration.
- `lexical_declaration`: `let name = value, ...;` or `const name = value, ...;` declaration.
- `variable_declarator`: `name = value` part within `var`, `let`, or `const`.
- `function_declaration`: `function name(...) { ... }` declaration.
- `generator_function_declaration`: `function* name(...) { ... }` declaration.
- `class_declaration`: `class Name { ... }` declaration.

## 4. Expressions

- `expression`: General category for expressions.

- `primary_expression`: Core building blocks (literals, identifiers, `this`, `super`, grouping, etc.).
- `parenthesized_expression`: `(expression)`.
- `assignment_expression`: `lhs = rhs`.
- `augmented_assignment_expression`: `lhs += rhs`, `lhs -= rhs`, etc.
- `await_expression`: `await expression`.
- `unary_expression`: `!expr`, `-expr`, `typeof expr`, `void expr`, `delete expr`.
- `binary_expression`: `a + b`, `a && b`, `a instanceof b`, etc.
- `ternary_expression`: `condition ? consequent : alternative`.
- `update_expression`: `expr++`, `expr--`, `++expr`, `--expr`.
- `new_expression`: `new Constructor(...)`.
- `yield_expression`: `yield value` or `yield* value`.
- `call_expression`: `func(...)` or `obj.method(...)` or `func` `` `template` ``.
- `member_expression`: `object.property` or `object?.property`.
- `subscript_expression`: `object[index]` or `object?.[index]`.
- `sequence_expression`: `expr1, expr2, expr3`.
- `arrow_function`: `(params) => body` or `param => body`.
- `function_expression`: `function name(...) { ... }` used as an expression.
- `generator_function`: `function* name(...) { ... }` used as an expression.
- `class`: `class Name { ... }` used as an expression.
- `class_heritage`: `extends expression` clause in a class definition.
- `spread_element`: `...expression` (in arrays, objects, arguments).
- `optional_chain`: `?.` operator.
- `arguments`: `(arg1, arg2, ...argN)` list in a function call.

## 5. Literals & Basic Elements

- `identifier`: Variable, function, property names.
- `private_property_identifier`: `#privateField`.
  `static`, `export`).
- `this`: The `this` keyword.
- `super`: The `super` keyword.
- `number`: Numeric literal (integer, float, hex, octal, binary, bigint).
- `string`: String literal (`"..."` or `'...'`).
- `template_string`: Template literal (`` ...${expr}...`  ``).
- `template_substitution`: `${expression}` inside a template literal.
- `regex`: Regular expression literal (`/pattern/flags`).
- `regex_pattern`: The pattern part of a regex literal (external token).
- `regex_flags`: The flags part (`g`, `i`, `m`, etc.) of a regex literal.
- `true`: Boolean `true` literal.
- `false`: Boolean `false` literal.
- `null`: The `null` literal.
- `undefined`: The `undefined` global property (treated like an identifier here).
- `escape_sequence`: `\n`, `\t`, `\uXXXX`, etc.
- `unescaped_double_string_fragment`: Content within `""`.
- `unescaped_single_string_fragment`: Content within `''`.
- `comment`: Line or block comment.
- `html_comment`: HTML-style comments (``) (external token, often for browser compatibility).

## 6. Objects & Arrays

- `object`: Object literal `{ key: value, ... }`.
- `array`: Array literal `[element1, element2, ...]`.
- `pair`: `key: value` pair within an object literal.
- `computed_property_name`: `[expression]` as a property name.
- `method_definition`: Method definition within an object literal or class.

## 7. Patterns (Destructuring & Parameters)

- `pattern`: General category for patterns (destructuring, function parameters).
- `object_pattern`: `{ prop1, prop2: alias, ...rest }` pattern.
- `array_pattern`: `[elem1, elem2, ...rest]` pattern.
- `pair_pattern`: `key: pattern` within an object pattern.
- `assignment_pattern`: `pattern = defaultValue` (in parameters or destructuring).
- `object_assignment_pattern`: Shorthand `{ identifier = defaultValue }` within object pattern.
- `rest_pattern`: `...identifier` (in array/object patterns, parameters).

## 8. Functions & Classes (Details)

- `formal_parameters`: `(param1, param2 = default, ...rest)` parameter list definition.
- `class_body`: The `{...}` block containing members of a class.
- `field_definition`: Class field definition (`propertyName = initializer`).
- `class_static_block`: `static { ... }` block within a class.
- `decorator`: `@decorator` syntax for classes and members.
- `decorator_member_expression`: Decorator involving member access (`@obj.prop`).
- `decorator_call_expression`: Decorator involving a function call (`@dec(arg)`).
- `meta_property`: `new.target` or `import.meta`.

## 9. Modules (Import/Export)

- `export_statement`: `export ...` statement.
- `namespace_export`: `* as name` in export/import.
- `export_clause`: `{ name1, name2 as alias }` part of an export statement.
- `export_specifier`: `name` or `name as alias` within an `export_clause`.
- `import_statement`: `import ...` statement.
- `import`: The `import` keyword itself (can be used in `import()` calls).
- `import_clause`: The bindings part of an import (`default, { named }, * as ns`).
- `namespace_import`: `* as name` import.
- `named_imports`: `{ name1, name2 as alias }` import.
- `import_specifier`: `name` or `name as alias` within `named_imports`.
- `import_attribute`: `with { type: "json" }` assertion/attribute.

## 10. JSX (JavaScript XML)

- `jsx_element`: `<tag>...</tag>`.
- `jsx_opening_element`: `<tag attr="val">`.
- `jsx_closing_element`: `</tag>`.
- `jsx_self_closing_element`: `<tag attr="val" />`.
- `jsx_text`: Plain text content within JSX (external token).
- `html_character_reference`: HTML entities like `&amp;`, `&#x20;`.
- `jsx_expression`: `{expression}` embedded within JSX.
- `jsx_attribute`: `name="value"` or `name={expr}` or just `name`.
- `unescaped_double_jsx_string_fragment`: Content within `""` in JSX attribute.
- `unescaped_single_jsx_string_fragment`: Content within `''` in JSX attribute.
- `jsx_identifier`: Identifier allowed in JSX tags/attributes (can contain hyphens).
- `nested_identifier`: `identifier.identifier` (used for JSX component names like `Namespace.Component`).
- `jsx_namespace_name`: `namespace:name` used in JSX tags/attributes.
