# Test Sample Organization

The test samples have been reorganized by syntactic domains to make it easier to:
1. Review specific language features
2. Debug compilation issues in isolation
3. Add new test cases for specific constructs

## Structure

### Python (`python/`)
- `imports/` - Import statements and patterns (standard, conditional, dynamic)
- `basics/` - Basic syntax, literals, and simple assignments
- `data_types/` - Data type operations (numbers, strings, lists, dicts, sets)
- `control_flow/` - Control flow constructs (if/else, loops, try/except, with)
- `functions/` - Functions, closures, decorators, generators
- `oop/` - Classes, inheritance, special methods, properties
- `advanced/` - Advanced features (async/await, comprehensions, unpacking)
- `stdlib/` - Standard library usage (math, collections, json, re)
- `dynamic/` - Dynamic features (eval, exec, introspection)
- `operators/` - Operators and subscript operations

### JavaScript (`javascript/`)
- `imports/` - ES6 imports/exports and CommonJS require
- `basics/` - Basic syntax, literals, and variable declarations
- `data_types/` - Data type operations and type coercion
- `control_flow/` - Control flow (if/else, loops, switch, try/catch)
- `functions/` - Functions, arrow functions, closures, generators
- `oop/` - Classes, prototypes, inheritance
- `advanced/` - Promises, async/await, destructuring, symbols
- `builtin/` - Built-in objects (JSON, Date, Math, RegExp)
- `dynamic/` - Dynamic features (eval, dynamic properties)
- `operators/` - Operators and subscript operations

## Original Files

The original comprehensive test files are preserved:
- `python.py` - Complete Python test suite
- `javascript.js` - Complete JavaScript test suite
- `expected_*_output*.txt` - Expected compilation outputs

## Running Tests

To run tests on the split files:
```bash
uv run pytest tests/test_split_samples.py -v
```

To run the original comprehensive tests:
```bash
uv run pytest tests/test_ast_to_malwicode.py -v
```