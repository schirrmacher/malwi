# Bytecode Analysis Tools

This directory contains utilities for comparing malwi's bytecode generation with Python's official bytecode. These tools help identify missing opcodes and constructs that need to be implemented.

## Tools Overview

### 1. **compare_bytecode.py** - Basic Comparison
Quick overview of missing opcodes and construct identification.

```bash
# Compare with default test file
python util/compare_bytecode.py

# Compare specific file
python util/compare_bytecode.py examples/test.py
```

**Features:**
- Shows missing opcodes
- Shows extra opcodes in malwi
- Identifies likely missing constructs (e.g., generators, exception handling)
- Quick overview of differences

### 2. **bytecode_diff_analyzer.py** - Detailed Analysis
Comprehensive analysis with line-by-line diffs and construct testing.

```bash
# Analyze all Python constructs
python util/bytecode_diff_analyzer.py --all-constructs

# Analyze specific construct
python util/bytecode_diff_analyzer.py --construct list_comprehension

# List available constructs
python util/bytecode_diff_analyzer.py --list-constructs

# Analyze specific file
python util/bytecode_diff_analyzer.py myfile.py
```

**Features:**
- Tests 30+ Python constructs
- Shows unified diff output
- Identifies high-priority opcodes to implement
- Provides implementation recommendations
- Color-coded diff output

### 3. **bytecode_visual_diff.py** - Visual Side-by-Side
Visual comparison with side-by-side bytecode display.

```bash
# Simple example
python util/bytecode_visual_diff.py --simple

# Analyze patterns
python util/bytecode_visual_diff.py --patterns

# Compare specific file
python util/bytecode_visual_diff.py test.py
```

**Features:**
- Side-by-side comparison (Python | Malwi)
- Color coding: Red=Missing, Green=Extra, Yellow=Different args
- Pattern analysis for common constructs
- Visual alignment of instructions

### 4. **bytecode_side_by_side.py** - Enhanced Side-by-Side Renderer
Advanced side-by-side bytecode comparison with better alignment and HTML output.

```bash
# Analyze inline code
python util/bytecode_side_by_side.py --code "x = 5; y = x + 3"

# Show example comparisons
python util/bytecode_side_by_side.py --examples

# Generate HTML output
python util/bytecode_side_by_side.py myfile.py --html output.html

# Analyze specific file
python util/bytecode_side_by_side.py test.py
```

**Features:**
- Clean columnar layout with perfect alignment
- Statistics showing match percentages
- HTML output option with syntax highlighting
- Example mode for quick demonstrations
- Smart instruction alignment using sequence matching
- Color-coded differences in terminal and HTML

# Compare specific file
python util/bytecode_visual_diff.py test.py
```

**Features:**
- Side-by-side comparison (Python | Malwi)
- Color coding: Red=Missing, Green=Extra, Yellow=Different args
- Pattern analysis for common constructs
- Visual alignment of instructions

## Example Output

### Enhanced Side-by-Side (bytecode_side_by_side.py):
```
========================================================================================================================
SIDE-BY-SIDE BYTECODE COMPARISON
========================================================================================================================

Source Code:
------------------------------------------------------------------------------------------------------------------------
  1 | x = 5
  2 | y = x + 3
------------------------------------------------------------------------------------------------------------------------

Statistics:
  Python: 8 instructions
  Malwi:  8 instructions
  Matching: 5 (55.6%)
  Missing:  1 (11.1%)
  Extra:    1 (11.1%)

========================================================================================================================
                     PYTHON BYTECODE                       │                       MALWI BYTECODE                      
          Offset  Op              Arg     Value            │           Offset  Op              Arg     Value           
========================================================================================================================
      0    RESUME          0                              │                                                           
      2 L1 LOAD_CONST      0       (5)                    │       0    LOAD_CONST      5.0     
      4    STORE_NAME      0       (x)                    │       2    STORE_NAME      x       
                                                           │       4    POP_TOP          
      6 L2 LOAD_NAME       0       (x)                    │       6    LOAD_NAME       x       
      8    LOAD_CONST      1       (3)                    │       8    LOAD_CONST      3.0     
     10    BINARY_OP       0                              │      10    BINARY_ADD       
     14    STORE_NAME      1       (y)                    │      12    STORE_NAME      y       
     16    RETURN_CONST    2                              │      14    POP_TOP          
========================================================================================================================
```

## Example Output

### Basic Comparison (compare_bytecode.py):
```
=== BYTECODE COMPARISON RESULTS ===

Python opcodes found: 45
Malwi opcodes found: 32
Common opcodes: 28

🔴 MISSING in malwi (present in Python):
  - BUILD_STRING
  - FORMAT_VALUE
  - LIST_APPEND
  - SETUP_FINALLY
  - YIELD_VALUE

🔍 LIKELY MISSING CONSTRUCTS:

  Exception handling:
    - SETUP_FINALLY
    - POP_EXCEPT

  Generators:
    - YIELD_VALUE
```

### Detailed Analysis (bytecode_diff_analyzer.py):
```
================================================================================
CONSTRUCT: list_comprehension
================================================================================

Code:
----------------------------------------
  numbers = [1, 2, 3, 4, 5]
  squares = [x**2 for x in numbers]
----------------------------------------

Bytecode instruction count:
  Python: 23 instructions
  Malwi:  18 instructions

Detailed diff (- Python, + Malwi):
--------------------------------------------------------------------------------
-   4: BUILD_LIST           0
-   6: LOAD_FAST            0          (numbers)
-   8: GET_ITER
-  10: FOR_ITER             8
+   4: LOAD_NAME            numbers
+   6: BUILD_LIST           0
```

### Visual Diff (bytecode_visual_diff.py):
```
========================================================================================================================
                      PYTHON BYTECODE                       |                       MALWI BYTECODE
========================================================================================================================

   0 L  1 LOAD_CONST           0    (5)                     |    0     LOAD_CONST           5    (5)
   2     STORE_NAME           0    (x)                      |    2     STORE_NAME           x    (x)
   4 L  2 LOAD_NAME            0    (x)                     |    4     LOAD_NAME            x    (x)
   6     LOAD_CONST           1    (3)                      |    6     LOAD_CONST           3    (3)
   8     BINARY_ADD                                         |    8     BINARY_ADD           None (None)
  10     STORE_NAME           1    (y)                      |   10     STORE_NAME           y    (y)

Legend: Red = Missing in malwi, Green = Extra in malwi, Yellow = Different arguments
```

## Common Missing Constructs

Based on analysis, here are the most commonly missing constructs:

1. **Exception Handling** - try/except/finally blocks
2. **Context Managers** - with statements  
3. **Generators** - yield expressions
4. **Comprehensions** - Optimized list/set/dict comprehensions
5. **Extended Unpacking** - a, *rest = [1, 2, 3]
6. **Async/Await** - Asynchronous code
7. **Pattern Matching** - match/case statements (Python 3.10+)
8. **Format Strings** - f-string formatting

## Implementation Priority

Based on frequency of use, these opcodes should be prioritized:

1. **LIST_APPEND, SET_ADD, MAP_ADD** - Used in comprehensions
2. **FORMAT_VALUE, BUILD_STRING** - Used in f-strings
3. **YIELD_VALUE** - Used in generators
4. **SETUP_FINALLY, POP_EXCEPT** - Used in exception handling
5. **BUILD_SLICE** - Used in advanced slicing

## Tips for Implementation

1. Add missing opcodes to the `OpCode` enum in `src/research/ast_to_malwicode.py`
2. Handle the opcode in the appropriate node processing method
3. Test with the specific construct using these tools
4. Regenerate test data after implementation

## Quick Testing Workflow

```bash
# 1. Check what's missing for a construct
python util/bytecode_diff_analyzer.py --construct generators

# 2. Implement the missing opcodes in ast_to_malwicode.py

# 3. Test the implementation
python util/bytecode_visual_diff.py test_generators.py

# 4. Verify all constructs still work
python util/bytecode_diff_analyzer.py --all-constructs
```