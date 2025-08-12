# Test File Split Summary

## Overview
The comprehensive test files `python.py` and `javascript.js` have been split into smaller, domain-specific files to improve:
- **Reviewability**: Easier to review specific language features
- **Debugging**: Isolate issues to specific constructs
- **Maintainability**: Add tests for specific features without searching through large files

## Benefits

### For Reviewers
1. **Focused Review**: Each file focuses on one syntactic domain
2. **Clear Structure**: Easy to find tests for specific language features
3. **Smaller Diffs**: Changes to specific features only affect relevant files

### For Debugging
1. **Isolated Testing**: Run tests for specific domains independently
2. **Clearer Error Messages**: Errors point to specific domain files
3. **Faster Iteration**: Test individual features without full suite

## File Organization

### Python Domains (10 files)
```
python/
├── imports/         # Import patterns and dynamic imports
├── basics/          # Literals, comments, basic assignments
├── data_types/      # Lists, dicts, sets, strings, numbers
├── control_flow/    # if/else, loops, try/except, with
├── functions/       # Functions, lambdas, decorators, generators
├── oop/             # Classes, inheritance, properties
├── advanced/        # Comprehensions, async/await, unpacking
├── stdlib/          # Standard library usage
├── dynamic/         # eval, exec, introspection
└── operators/       # Binary ops, subscripts, comparisons
```

### JavaScript Domains (10 files)
```
javascript/
├── imports/         # ES6 imports, CommonJS require
├── basics/          # Literals, variables, basic syntax
├── data_types/      # Arrays, objects, type coercion
├── control_flow/    # if/else, loops, switch, try/catch
├── functions/       # Functions, arrows, closures, async
├── oop/             # Classes, prototypes, inheritance
├── advanced/        # Promises, generators, destructuring
├── builtin/         # JSON, Date, Math, RegExp
├── dynamic/         # eval, dynamic properties
└── operators/       # Binary ops, subscripts, comparisons
```

## Test Structure

Each domain file:
- Is self-contained (can be compiled independently)
- Focuses on one aspect of the language
- Includes comments explaining what's being tested
- Ends with a completion message for easy verification

## Running Tests

### Test all domains:
```bash
uv run pytest tests/test_split_samples.py -v
```

### Test specific domain:
```bash
uv run pytest tests/test_split_samples.py::TestSplitSamples::test_python_control_flow_domain -v
```

### Original comprehensive tests still work:
```bash
uv run pytest tests/test_ast_to_malwicode.py -v
```

## Adding New Tests

To add tests for a new language feature:
1. Identify the appropriate domain (e.g., `control_flow` for new loop construct)
2. Add test code to the relevant file
3. Run domain-specific test to verify
4. No need to regenerate expected outputs for other domains

## Migration Notes

- Original files (`python.py`, `javascript.js`) are preserved
- Expected output files remain unchanged
- New test runner (`test_split_samples.py`) handles split files
- All existing tests continue to pass