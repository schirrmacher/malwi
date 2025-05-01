# Rust Grammar Mapping

See symbols: https://github.com/tree-sitter/tree-sitter-rust/blob/master/src/grammar.json.

## 1. Top-Level & Statements

- `source_file`: The root of the grammar.
- `expression_statement`: A statement consisting of an expression ending with a semicolon or a block.
- `empty_statement`: A lone semicolon.

## 2. Items & Declarations

- `const_item`: `const NAME: type = value;` declaration.
- `static_item`: `static NAME: type = value;` declaration.
- `let_declaration`: `let pattern = value;` or `let pattern: type = value;`.
- `mod_item`: `mod name;` or `mod name { ... }` module declaration.
- `foreign_mod_item`: `extern "ABI" { ... }` foreign module declaration.
- `struct_item`: `struct Name { ... }` or `struct Name(...);` declaration.
- `union_item`: `union Name { ... }` declaration.
- `enum_item`: `enum Name { ... }` declaration.
- `type_item`: `type Name = type;` type alias declaration.
- `function_item`: `fn name(...) -> type { ... }` function definition.
- `function_signature_item`: `fn name(...) -> type;` function signature declaration (often in traits or extern blocks).
- `impl_item`: `impl Trait for Type { ... }` or `impl Type { ... }` implementation block.
- `trait_item`: `trait Name { ... }` trait definition.
- `associated_type`: `type Name;` associated type declaration within a trait.
- `use_declaration`: `use path;` or `use path::{...};` import declaration.
- `scoped_use_list`: `path::{...}` usage.
- `use_list`: `{...}` group in a use declaration.
- `use_as_clause`: `path as alias` usage.
- `use_wildcard`: `path::*` usage.
- `extern_crate_declaration`: `extern crate name;` declaration.
- `declaration_list`: `{ ... }` block containing item declarations (e.g., in `impl`, `trait`, `mod`).
- `enum_variant_list`: `{...}` block containing enum variants.
- `enum_variant`: A variant within an `enum`.
- `field_declaration_list`: `{...}` block containing named fields (structs, unions).
- `field_declaration`: `name: type` declaration within a struct/union.
- `ordered_field_declaration_list`: `(...)` tuple-like fields (structs, enum variants).

## 3. Expressions

- `unary_expression`: `-`, `*`, `!` followed by an expression.
- `reference_expression`: `&expr` or `&mut expr`.
- `try_expression`: `expr?`.
- `binary_expression`: `a + b`, `a && b`, `a == b`, etc..
- `assignment_expression`: `a = b`.
- `compound_assignment_expr`: `a += b`, `a -= b`, etc..
- `type_cast_expression`: `expr as type`.
- `call_expression`: `func(arg1, arg2)`.
- `return_expression`: `return value` or `return`.
- `yield_expression`: `yield value` or `yield`.
- `await_expression`: `expr.await`.
- `field_expression`: `struct.field` or `tuple.0`.
- `array_expression`: `[a, b, c]` or `[val; len]`.
- `tuple_expression`: `(a, b, c)` or `(a,)`.
- `unit_expression`: `()`.
- `break_expression`: `break 'label value`.
- `continue_expression`: `continue 'label`.
- `index_expression`: `array[index]`.
- `range_expression`: `a..b`, `a..=b`, `..b`, `a..`, `..`.
- `closure_expression`: `|arg1, arg2| body`.
- `parenthesized_expression`: `(expr)`.
- `struct_expression`: `StructName { field1: val1, field2 }`.
- `if_expression`: `if condition { ... } else { ... }`.
- `match_expression`: `match value { pattern => result, ... }`.
- `while_expression`: `while condition { ... }`.
- `loop_expression`: `loop { ... }`.
- `for_expression`: `for pattern in iterable { ... }`.
- `unsafe_block`: `unsafe { ... }` expression.
- `async_block`: `async { ... }` or `async move { ... }` expression.
- `gen_block`: `gen { ... }` or `gen move { ... }` expression.
- `try_block`: `try { ... }` expression.
- `const_block`: `const { ... }` expression.
- `block`: `{ statement; statement; expression }` code block used as expression or statement body.
- `let_condition`: `let pattern = expr` used in `if`/`while`.
- `else_clause`: `else { ... }` or `else if ...`.
- `match_block`: `{ pattern => result, ... }` body of a match expression.
- `match_arm`: `pattern => result,` arm within a match block.
- `last_match_arm`: Final arm in a match block (optional comma).
- `match_pattern`: `pattern` or `pattern if condition` part of a match arm.
- `arguments`: `(arg1, arg2)` list in a call expression.
- `field_initializer_list`: `{ field1: val1, field2, ..base }` in a struct expression.
- `shorthand_field_initializer`: `field` (shorthand for `field: field`).
- `field_initializer`: `field: value`.
- `base_field_initializer`: `..base_struct`.

## 4. Patterns

- `negative_literal`: Pattern matching `-1`, `-3.14`.
- `tuple_pattern`: `(pat1, pat2)`.
- `tuple_struct_pattern`: `StructName(pat1, pat2)`.
- `struct_pattern`: `StructName { field1: pat1, field2 }`.
- `generic_pattern`: Pattern involving generics like `Enum::Variant::<T>`.
- `ref_pattern`: `ref mut pattern`.
- `slice_pattern`: `[pat1, pat2, ..]`.
- `captured_pattern`: `identifier @ pattern`.
- `reference_pattern`: `&pattern` or `&mut pattern`.
- `remaining_field_pattern`: `..` within struct or tuple patterns.
- `mut_pattern`: `mut identifier`.
- `or_pattern`: `pat1 | pat2`.
- `field_pattern`: Pattern for a field within `struct_pattern`.

## 5. Types

- `primitive_type`: Built-in types like `i32`, `f64`, `bool`, `str`.
- `abstract_type`: `impl Trait` type.
- `reference_type`: `&'a T`, `&'a mut T`.
- `pointer_type`: `*const T`, `*mut T`.
- `generic_type`: `TypeName<Arg1, Arg2>`.
- `generic_type_with_turbofish`: `TypeName::<Arg1>` (explicit generics).
- `scoped_type_identifier`: `path::to::TypeName`.
- `scoped_type_identifier_in_expression_position`: Special handling for `path::Type` used where an expression is expected.
- `tuple_type`: `(Type1, Type2)`.
- `unit_type`: `()`.
- `array_type`: `[Type; LEN]` or `[Type]` (slice type).
- `function_type`: `fn(ArgType) -> RetType` or `TraitName(ArgType) -> RetType`.
- `never_type`: `!` (the never type).
- `dynamic_type`: `dyn Trait`.
- `bounded_type`: `Type1 + Type2 + 'a` (combination of bounds).
- `removed_trait_bound`: `?Trait` (unimplemented).
- `bracketed_type`: `<Type>` (used in turbofish or qualified paths).
- `qualified_type`: `Type as Trait` (used in paths).
- `type_parameters`: `<'a, T: Bound, const N: usize>` generic parameters for items/types.
- `const_parameter`: `const NAME: type` generic parameter.
- `type_parameter`: `NAME: Bound = DefaultType` generic parameter.
- `lifetime_parameter`: `'a: 'b + 'c` generic parameter.
- `trait_bounds`: `: Bound1 + Bound2` bounds on generic parameters.
- `higher_ranked_trait_bound`: `for<'a> Trait<'a>`.
- `use_bounds`: `use<'a, T>` (hypothetical future syntax).
- `type_arguments`: `<Arg1, Arg2>` arguments provided to generic types/functions.
- `type_binding`: `AssocType = Type` within type arguments (e.g., `Iterator<Item = i32>`).
- `where_clause`: `where T: Bound, 'a: 'b` clause for complex bounds.
- `where_predicate`: `TypeOrLifetime: Bound1 + Bound2` single predicate in a where clause.

## 6. Attributes & Modifiers

- `attribute_item`: `# [attribute]` outer attribute.
- `inner_attribute_item`: `# ![attribute]` inner attribute.
- `attribute`: `path` or `path = expr` or `path(token_tree)` within `#[...]`.
- `visibility_modifier`: `pub` or `pub(crate)` or `pub(in path)` or `crate`.
- `extern_modifier`: `extern "ABI"`.
- `function_modifiers`: `async`, `const`, `unsafe`, `extern "ABI"`, `default`.
- `mutable_specifier`: `mut` keyword.

## 7. Macros

- `macro_definition`: `macro_rules! name { ... }`.
- `macro_rule`: `(matcher) => (transcriber)` rule within `macro_rules!`.
- `macro_invocation`: `macro_name!(...)` or `path::macro!(...)`.
- `token_tree_pattern`: `(...)`, `[...]`, `{...}` in macro matchers.
- `token_binding_pattern`: `$name:fragment_specifier` in macro matchers.
- `token_repetition_pattern`: `$ ( ... ) sep rep` in macro matchers.
- `fragment_specifier`: `ident`, `expr`, `ty`, `pat`, `stmt`, `block`, `item`, `meta`, `tt`, `path`, `vis`, `lifetime`, `literal`.
- `token_tree`: `(...)`, `[...]`, `{...}` in macro transcribers or arguments.
- `token_repetition`: `$ ( ... ) sep rep` in macro transcribers.
- `delim_token_tree`: `(...)`, `[...]`, `{...}` argument to a macro invocation.

## 8. Literals & Basic Elements

- `string_literal`: `"content"` or `b"content"`.
- `raw_string_literal`: `r#"content"#` or `br##"content"##`.
- `char_literal`: `'c'` or `b'c'`.
- `boolean_literal`: `true`, `false`.
- `integer_literal`: `123`, `0xff`, `0o77`, `0b11`, `123_u32`.
- `float_literal`: `1.23`, `1.23e-10`, `1.23_f64`.
- `escape_sequence`: `\n`, `\t`, `\xNN`, `\u{NNNN}` etc..
- `string_content`: Raw text inside a string literal (external token).
- `raw_string_literal_content`: Content inside a raw string (external token).
- `identifier`: Name for variables, functions, types, etc..
- `self`: The `self` keyword.
- `super`: The `super` keyword.
- `crate`: The `crate` keyword.
- `metavariable`: `$name` used in macros.
- `shebang`: `#!/path/to/interpreter` (optional, at start of file).
- `comment`: Line or block comment.
- `line_comment`: `// comment`.
- `block_comment`: `/* comment */`.

## 9. Lifetimes & Labels

- `lifetime`: `'name` lifetime annotation.
- `for_lifetimes`: `for<'a, 'b>` introducer for higher-ranked lifetimes.
- `label`: `'name:` label for loops.
