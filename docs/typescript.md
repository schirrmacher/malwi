# TypeScript Grammar Mapping

See symbols: https://github.com/tree-sitter/tree-sitter-typescript/blob/master/tsx/src/grammar.json.

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
- `catch_clause`: `catch (error: type) { ... }` part of a `try` statement (includes optional type annotation).
- `finally_clause`: `finally { ... }` part of a `try` statement.
- `with_statement`: `with (object) ...` statement (deprecated).
- `break_statement`: `break label;`.
- `continue_statement`: `continue label;`.
- `return_statement`: `return value;`.
- `throw_statement`: `throw value;`.
- `labeled_statement`: `label: statement`.

## 3. Declarations

- `declaration`: General category for declarations (includes JS + TS declarations).
- `variable_declaration`: `var name: type = value, ...;` declaration.
- `lexical_declaration`: `let name: type = value, ...;` or `const name: type = value, ...;` declaration.
- `variable_declarator`: `name: type = value` part within `var`, `let`, or `const` (includes optional type annotation and definite assignment assertion `!`).
- `function_declaration`: `function name<T>(...): type { ... }` declaration.
- `generator_function_declaration`: `function* name<T>(...): type { ... }` declaration.
- `class_declaration`: `class Name<T> extends Base implements I { ... }` declaration.
- `abstract_class_declaration`: `abstract class Name { ... }` declaration.
- `module`: `module 'name' { ... }` or `module name { ... }` (external module declaration).
- `internal_module`: `namespace name { ... }` declaration (also `module name { ... }` when not top-level or quoted).
- `type_alias_declaration`: `type Name<T> = Type;` declaration.
- `enum_declaration`: `enum Name { Member = value, ... }` declaration.
- `enum_body`: The `{...}` block of an enum.
- `enum_assignment`: `Member = value` within an enum.
- `interface_declaration`: `interface Name<T> extends Other { ... }` declaration.
- `extends_type_clause`: `extends Type1, Type2` clause for interfaces.
- `import_alias`: `import name = module.path;` declaration.
- `ambient_declaration`: `declare ...` statement for ambient context.
- `function_signature`: `function name<T>(...): type;` declaration (often in ambient contexts or interfaces).

## 4. Expressions

- `expression`: General category for expressions (includes JS + TS expressions).
- `primary_expression`: Core building blocks (includes `non_null_expression`).
- `parenthesized_expression`: `(expression: type)`.
- `assignment_expression`: `lhs = rhs`.
- `augmented_assignment_expression`: `lhs += rhs`, `lhs -= rhs`, etc.`non_null_expression`).
- `await_expression`: `await expression`.
- `unary_expression`: `!expr`, `-expr`, `typeof expr`, `void expr`, `delete expr`.
- `binary_expression`: `a + b`, `a && b`, `a instanceof b`, etc.
- `ternary_expression`: `condition ? consequent : alternative`.
- `update_expression`: `expr++`, `expr--`, `++expr`, `--expr`.
- `new_expression`: `new Constructor<T>(...)`.
- `yield_expression`: `yield value` or `yield* value`.
- `call_expression`: `func<T>(...)` or `obj.method<T>(...)` or `func` `` `template` ``.
- `member_expression`: `object.property` or `object?.property`.
- `subscript_expression`: `object[index]` or `object?.[index]`.`non_null_expression`).
- `sequence_expression`: `expr1, expr2, expr3`.
- `arrow_function`: `<T>(params: Type): RetType => body`.
- `function_expression`: `function name<T>(...): type { ... }` used as an expression.
- `generator_function`: `function* name<T>(...): type { ... }` used as an expression.
- `class`: `class Name<T> extends Base implements I { ... }` used as an expression.
- `class_heritage`: `extends expression<T>` and/or `implements Type1, Type2`.
- `extends_clause`: `extends expression<T>`.clause.
- `implements_clause`: `implements Type1, Type2`.
- `spread_element`: `...expression` (in arrays, objects, arguments).
- `optional_chain`: `?.` operator.
- `arguments`: `(arg1, arg2, ...argN)` list in a function call.
- `as_expression`: `expression as type` or `expression as const`.
- `satisfies_expression`: `expression satisfies type`.
- `non_null_expression`: `expression!`.
- `instantiation_expression`: `expression<TypeArg>`.

## 5. Literals & Basic Elements

- `identifier`: Variable, function, property, type names.
- `private_property_identifier`: `#privateField`.`declare`, `type`, access modifiers, `module`, `any`, etc.).
- `this`: The `this` keyword (can also be a type).
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
- `html_comment`: HTML-style comments (``) (external token).token).

## 6. Objects & Arrays

- `object`: Object literal `{ key: value, ... }`.
- `array`: Array literal `[element1, element2, ...]`.
- `pair`: `key: value` pair within an object literal.private).
- `computed_property_name`: `[expression]` as a property name.
- `method_definition`: Method definition within an object literal or class (includes TS modifiers).

## 7. Patterns (Destructuring & Parameters)

- `pattern`: General category for patterns (destructuring, function parameters).
- `object_pattern`: `{ prop1, prop2: alias, ...rest }` pattern.
- `array_pattern`: `[elem1, elem2, ...rest]` pattern.
- `pair_pattern`: `key: pattern` within an object pattern.
- `assignment_pattern`: `pattern = defaultValue` (in parameters or destructuring).
- `object_assignment_pattern`: Shorthand `{ identifier = defaultValue }` within object pattern.
- `rest_pattern`: `...identifier` (in array/object patterns, parameters).

## 8. Functions & Classes (Details)

- `formal_parameters`: `(param1: Type = default, ...rest: Type[])` parameter list definition.type parameters and return type annotation.`optional_parameter`).
- `required_parameter`: `modifier* pattern: Type = default`.
- `optional_parameter`: `modifier* pattern?: Type = default`.pattern/identifier.
- `class_body`: The `{...}` block containing members of a class (includes TS members like signatures, fields with modifiers).
- `public_field_definition`: Class field definition including TS modifiers (`public`, `private`, `protected`, `readonly`, `declare`, `override`, `accessor`).
- `field_definition`: Class field definition (JS version, used within `public_field_definition`).
- `class_static_block`: `static { ... }` block within a class.
- `decorator`: `@decorator` syntax for classes and members.
- `decorator_member_expression`: Decorator involving member access (`@obj.prop`).
- `decorator_call_expression`: Decorator involving a function call (`@dec(arg)`).
- `decorator_parenthesized_expression`: Decorator involving a parenthesized expression (`@(expr)`).
- `meta_property`: `new.target` or `import.meta`.
- `accessibility_modifier`: `public`, `private`, `protected`.
- `override_modifier`: `override` keyword.

## 9. Modules (Import/Export)

- `export_statement`: `export ...` statement (includes TS variations like `export type`, `export =`, `export as namespace`).
- `namespace_export`: `* as name` in export/import.
- `export_clause`: `{ name1, name2 as alias }` part of an export statement.
- `export_specifier`: `name` or `name as alias` within an `export_clause` (includes optional `type`/`typeof` keyword).
- `import_statement`: `import ...` statement (includes TS variations like `import type`, `import typeof`, `import require`).
- `import`: The `import` keyword itself (can be used in `import()` calls).
- `import_clause`: The bindings part of an import (`default, { named }, * as ns`).
- `namespace_import`: `* as name` import.
- `named_imports`: `{ name1, name2 as alias }` import.
- `import_specifier`: `name` or `name as alias` within `named_imports` (includes optional `type`/`typeof` keyword).
- `import_require_clause`: `name = require("source")`.
- `import_attribute`: `with { type: "json" }` or `assert { type: "json" }`.

## 10. Types

- `type`: General category for type annotations.
- `primary_type`: Core type constructs (primitives, object/array/tuple types, references, etc.).
- `predefined_type`: Built-in types like `any`, `number`, `boolean`, `void`, `unknown`, `never`, `object`.
- `nested_type_identifier`: `Namespace.TypeName`.
- `generic_type`: `Name<TypeArg1, TypeArg2>`.
- `parenthesized_type`: `(Type)`.
- `type_annotation`: `: Type`.
- `omitting_type_annotation`: `-?: Type` (Flow syntax?).
- `adding_type_annotation`: `+?: Type` (Flow syntax?).
- `opting_type_annotation`: `?: Type` (Flow syntax?).
- `asserts`: `asserts condition` used in return type position.
- `asserts_annotation`: `: asserts condition`.
- `type_predicate`: `param is Type`.
- `type_predicate_annotation`: `: param is Type`.
- `type_parameters`: `<T extends Constraint = Default>`.
- `type_parameter`: A single generic type parameter `T extends Constraint = Default`.
- `default_type`: `= Type` default for a type parameter.
- `constraint`: `extends Type` or `: Type` constraint on a type parameter.
- `type_arguments`: `<TypeArg1, TypeArg2>` provided to generics.
- `object_type`: `{ key: Type; method(...): Type; [index: string]: Type }`.
- `call_signature`: `<T>(params: Type): RetType` within an object/interface type.
- `property_signature`: `readonly? name?: Type` within an object/interface type.
- `construct_signature`: `new <T>(params: Type): RetType` within an object/interface type.
- `index_signature`: `readonly? [param: IndexType]: ValueType`.
- `mapped_type_clause`: `Key in Type as Alias` within index signatures.
- `array_type`: `Type[]`.
- `tuple_type`: `[Type1, Type2?, ...RestType[]]`.
- `tuple_parameter`: `name: Type` within a tuple type definition.
- `optional_tuple_parameter`: `name?: Type` within a tuple type definition.
- `optional_type`: `Type?`.
- `rest_type`: `...Type`.
- `readonly_type`: `readonly Type`.
- `union_type`: `TypeA | TypeB`.
- `intersection_type`: `TypeA & TypeB`.
- `function_type`: `<T>(params: Type) => RetType`.
- `constructor_type`: `new <T>(params: Type) => InstanceType`.
- `type_assertion`: `<Type>expression`.
- `type_query`: `typeof expression`.in type annotation context.type annotation context.
- `index_type_query`: `keyof Type`.
- `lookup_type`: `Type[IndexType]`.
- `literal_type`: `string`, `number`, `true`, `false`, `null`, `undefined`, `-number`.
- `existential_type`: `*` (Flow syntax?).
- `flow_maybe_type`: `?Type` (Flow syntax?).
- `conditional_type`: `Check extends Condition ? TrueType : FalseType`.
- `infer_type`: `infer Name extends Constraint`.
- `template_literal_type`: `` abc${Type}def`  ``.
- `template_type`: `${Type}` part within a template literal type.

## 11. JSX (JavaScript XML)

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
