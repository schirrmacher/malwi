# Bytecode Debugging Guide

## Quick Reference

### View Bytecode for a Domain

```bash
# View mapped bytecode (default)
uv run python util/view_domain_bytecode.py python control_flow

# View raw bytecode
uv run python util/view_domain_bytecode.py python control_flow --raw

# Compare raw vs mapped
uv run python util/view_domain_bytecode.py python control_flow --compare

# Limit output to first 20 lines
uv run python util/view_domain_bytecode.py python control_flow --lines 20
```

### List All Domains

```bash
uv run python util/view_domain_bytecode.py --list
```

## Directory Structure

```
tests/source_samples/
├── python/                    # Python source + bytecode
│   ├── control_flow/
│   │   ├── test_control_flow.py                   # Source file
│   │   ├── test_control_flow_bytecode.txt         # Raw bytecode  
│   │   └── test_control_flow_bytecode_mapped.txt  # Mapped bytecode
│   ├── strings/
│   │   ├── test_strings.py
│   │   ├── test_strings_bytecode.txt
│   │   └── test_strings_bytecode_mapped.txt
│   └── ... (11 domains total)
└── javascript/               # JavaScript source + bytecode
    └── ... (same structure)
```

## Debugging Specific Issues

### 1. Missing Opcode

```bash
# Check if opcode appears in any domain
grep -r "JUMP_BACKWARD" tests/source_samples/python/*/

# View specific domain where it should appear
uv run python util/view_domain_bytecode.py python control_flow --mapped | grep JUMP
```

### 2. Wrong Opcode Generated

```bash
# Compare raw vs mapped to see actual values
uv run python util/view_domain_bytecode.py python functions --compare

# Check specific construct (e.g., comprehensions)
uv run python util/view_domain_bytecode.py python advanced --mapped | grep -A5 -B5 "LOAD_FAST"
```

### 3. Scope Issues (LOAD_NAME vs LOAD_GLOBAL)

```bash
# Check global/nonlocal handling  
uv run python util/view_domain_bytecode.py python dynamic --mapped | grep -E "LOAD_NAME|LOAD_GLOBAL|STORE_GLOBAL"
```

### 4. Function Call Issues

```bash
# Check KW_NAMES generation
uv run python util/view_domain_bytecode.py python functions --mapped | grep -E "KW_NAMES|CALL"
```

## Common Debugging Patterns

### Check Import Handling
```bash
uv run python util/view_domain_bytecode.py python imports --mapped | head -50
```

### Check Control Flow
```bash
# Loops
uv run python util/view_domain_bytecode.py python control_flow --mapped | grep -E "FOR_ITER|JUMP_BACKWARD|WHILE"

# Conditionals  
uv run python util/view_domain_bytecode.py python control_flow --mapped | grep -E "POP_JUMP_IF|JUMP"
```

### Check Advanced Features
```bash
# Comprehensions
uv run python util/view_domain_bytecode.py python advanced --mapped | grep -E "LOAD_FAST|STORE_FAST|LIST_APPEND"

# Async/await
uv run python util/view_domain_bytecode.py python advanced --mapped | grep -E "AWAIT|ASYNC"
```

## Regenerating Bytecode

After making changes to the compiler:

```bash
# Regenerate all bytecode files
uv run python util/generate_domain_bytecode.py

# Regenerate test data for main test files
uv run python util/regenerate_test_data.py
```

## Example Debugging Session

1. **Identify the issue**: "List comprehensions not using LOAD_FAST"

2. **View the bytecode**:
   ```bash
   uv run python util/view_domain_bytecode.py python advanced --mapped | grep -A10 "list_comp"
   ```

3. **Compare with expected**:
   ```bash
   # See what's generated vs what Python generates
   uv run python util/bytecode_diff_analyzer.py --construct list_comprehension
   ```

4. **Fix in ast_to_malwicode.py**, then regenerate:
   ```bash
   uv run python util/generate_domain_bytecode.py
   ```

5. **Verify fix**:
   ```bash
   uv run python util/view_domain_bytecode.py python advanced --mapped | grep -A10 "list_comp"
   ```