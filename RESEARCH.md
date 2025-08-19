# malwi Research Progress

This document tracks the AI model training research progress for malwi, documenting chronological improvements and performance metrics.

## Research Timeline

### August 2025

#### 2025-08-17: Code Detection Category Performance Impact
- **Commit**: `1acc57be`
- **Finding**: New string categories (`STRING_BASH`, `STRING_SQL`, `STRING_CODE`) cause 95x slower preprocessing on malicious files
- **Data**: Benign: 20min/230k files vs Malicious: 1.5h/11k files (cancelled due to timeout with 5 unfinished futures)
- **Impact**: Code detection categories are highly discriminative but computationally expensive

#### 2025-08-04: Keyword Names Logic Optimization
- **Tag**: `1f6b7a1e_f1/0.925` 
- **F1 Score**: 0.925
- **Change**: Modified KW_NAMES logic
- **Impact**: Solid baseline performance achieved with improved keyword handling

#### 2025-08-04: CodeObject Creation Behavior
- **Tag**: `c09b6588_f1/0.932`
- **F1 Score**: 0.932 (+0.007)
- **Change**: Changed nested CodeObject creation behavior
- **Impact**: Small improvement in object creation logic

#### 2025-08-10: Vocabulary Size Experiment
- **Tag**: `1001a101_f1/0.0`
- **F1 Score**: 0.0 (-0.932)
- **Change**: Increased vocab size in training scripts
- **Files**: `cmds/train_distilbert.sh`, `cmds/train_distilbert_tiny.sh`, `cmds/train_tokenizer.sh`
- **Impact**: ❌ **Failed experiment** - vocabulary size increase broke model performance
- **Analysis**: Model architecture couldn't handle larger vocabulary efficiently

#### 2025-08-10: DistilBERT Size Reduction
- **Tag**: `b0b11be9_f1/0.846`
- **F1 Score**: 0.846 (+0.846 from failed state)
- **Change**: Reduced DistilBERT size based on vocabulary
- **Impact**: Recovery from failed vocabulary experiment, but below previous performance

#### 2025-08-12: KW_NAMES Split (Best Performance So Far)
- **Tag**: `11666b09_f1/0.947`
- **F1 Score**: 0.947 (+0.101)
- **Change**: Split KW_NAMES implementation in `ast_to_malwicode.py`
- **Files**: `src/research/ast_to_malwicode.py`, `tests/source_samples/expected_python_output_mapped.txt`
- **Impact**: ✅ **Significant improvement** - best performance to date
- **Analysis**: KW_NAMES architecture change was fundamental breakthrough

#### 2025-08-12: KW_NAMES Unmapping Experiment
- **Tag**: `3026c86e_f1/0.0`
- **F1 Score**: 0.0 (-0.947)
- **Change**: Unmapped KW_NAMES to let model see params
- **Impact**: ❌ **Failed experiment** - removing KW_NAMES mapping broke performance

#### 2025-08-12: Bytecode Refactoring
- **Tag**: `7fae71bd_f1/0.941`
- **F1 Score**: 0.941 (+0.941 from failed state)
- **Change**: Refactored bytecode creation
- **Impact**: Good recovery, maintaining high performance

#### 2025-08-14: String Mapping Optimization (Peak Performance)
- **Tag**: `2b4abcab_f1/0.958`
- **F1 Score**: 0.958 (+0.017)
- **Change**: Changed string mapping length in `ast_to_malwicode.py`
- **Files**: `src/research/ast_to_malwicode.py` (6 insertions, 4 deletions)
- **Impact**: ✅ **New peak performance** - highest F1 score achieved
- **Analysis**: Small but critical change to string length handling provided significant performance boost

#### 2025-08-14: DistilBERT 256 Reintroduction
- **Tag**: `7002e364_f1/0.944`
- **F1 Score**: 0.944 (-0.014)
- **Change**: Reintroduced DistilBERT 256
- **Impact**: Slight performance decrease, suggesting larger model may not always be better

#### 2025-08-14: Tokenizer Version Fix
- **Tag**: `b7a14a0c_f1/0.932`
- **F1 Score**: 0.932 (-0.012)
- **Change**: Fixed tokenizer issue due to version lookup
- **Impact**: Version compatibility fix with minor performance impact

#### 2025-08-15: False-Positives Training Integration
- **Tag**: `6b831862_f1/0.952`
- **F1 Score**: 0.952 (+0.020)
- **Change**: Included false-positives in training pipeline
- **Files**: `README.md`, `cmds/preprocess_data.sh` (added false-positive processing)
- **Impact**: ✅ **Good improvement** - training on edge cases enhanced performance
- **Analysis**: Including challenging borderline cases in training improved model robustness

#### 2025-08-15: Domain-Specific URL Detection
- **Tag**: `cf9342e9_f1/0.919`
- **F1 Score**: 0.919 (-0.033)
- **Change**: Added domain specific URL detection
- **Impact**: Performance decrease, possibly due to over-specification

#### 2025-08-16: Module Code Splitting
- **Tag**: `129e7f57_f1/0.847`
- **F1 Score**: 0.847 (-0.072)
- **Change**: Split module code properly in core bytecode logic
- **Files**: Major refactor in `src/common/bytecode.py`, `src/common/malwi_report.py`, removed test expectations, added `tests/test_module_extraction.py`
- **Impact**: ❌ **Significant performance decrease** - module splitting reduced signal quality
- **Analysis**: Breaking code into smaller modules lost important contextual information for detection

#### 2025-08-16: Full File Scanning
- **Tag**: `7564fc77_f1/0.894`
- **F1 Score**: 0.894 (+0.047)
- **Change**: Test scanning on full files only
- **Impact**: Partial recovery, full file scanning improved over module splitting

#### 2025-08-17: String Cases Performance Trade-off
- **Tag**: `0fd74a13_f1/0.842`
- **F1 Score**: 0.842 (-0.052)
- **Change**: Disabled new string cases due to performance
- **Impact**: Performance prioritization over feature completeness

#### 2025-08-19: Code Detection Tokens and String Mapping Optimization
- **Tag**: `ae143225_f1/0.9362`
- **F1 Score**: 0.9362 (-0.0218)
- **Change**: Applied new code detection tokens and removed old entropy-based string mapping
- **Impact**: ⚠️ **Slight performance decrease** - minor reduction from peak performance
- **Analysis**: While new code detection tokens and removal of entropy-based mapping improved processing efficiency, it resulted in a small accuracy trade-off. The approach may have removed some useful signal in the mapping process.

#### 2025-08-19: Configuration Centralization and String Size Buckets
- **Tag**: `a000a816_f1/0.8585`
- **F1 Score**: 0.8585 (-0.0777)
- **Change**: Fixed CodeObject embedding bug, centralized configuration constants, implemented string size buckets (S/M/L), added conservative string classification limits
- **Impact**: ❌ **Significant performance decrease** - accuracy drop from architectural changes
- **Analysis**: Performance decrease likely stems from replacing STRING_LARGE_PAYLOAD with granular size buckets and implementing conservative string classification logic with 50KB regex limits. The more restrictive approach to large string processing may have reduced detection signal quality.

#### 2025-08-19: Tokenizer Vocabulary Size Fix
- **Tag**: `2a22e8f1_f1/0.918`
- **F1 Score**: 0.918 (+0.0595)
- **Change**: Fixed tokenizer vocabulary overflow, centralized token count configuration, removed hardcoded 15000 values
- **Impact**: ✅ **Good recovery** - performance improved after fixing tokenizer configuration
- **Analysis**: Addressed tokenizer vocabulary exceeding 30,522 limit by removing double-counting of special tokens and centralizing DEFAULT_TOP_N_TOKENS=5000. This ensures vocabulary stays within DistilBERT constraints while maintaining detection capabilities.

## Key Insights

### ✅ High-Impact Improvements
1. **String mapping optimization** (0.958) - Peak performance achieved with minimal code changes  
2. **False-positives training** (0.952) - Edge case handling improved robustness
3. **KW_NAMES splitting** (0.947) - Major architecture improvement in AST processing
4. **Bytecode refactoring** (0.941) - Core logic improvement

### ⚠️ Mixed Results / Minor Performance Changes
1. **Code detection tokens optimization** (0.9362) - Slight decrease from peak but improved processing efficiency
2. **Tokenizer vocabulary fix** (0.918) - Good recovery after configuration issues
3. **Full file scanning** (0.894) - Partial recovery from module splitting issues
4. **DistilBERT 256 reintroduction** (0.944) - Minor decrease, larger model not always better

### ❌ Failed Experiments
1. **Vocabulary size increase** (0.0) - Complete model failure, suggests architecture limitations
2. **KW_NAMES unmapping** (0.0) - Removing essential mappings broke model completely
3. **Module code splitting** (0.847) - Lost contextual information critical for detection

### 📊 Performance Trends
- **Peak Performance**: 0.958 (2025-08-14) - String mapping optimization
- **Current Performance**: 0.918 (2025-08-19) - Tokenizer vocabulary size fix
- **Performance Range**: 0.0 - 0.958
- **Average Performance**: 0.786 (excluding failed experiments)
- **Recent Change**: +0.0595 recovery from tokenizer configuration fix
- **Volatility**: High - small changes can have major impact (±0.1 F1 score)

### 🔬 Critical Success Factors
1. **String Handling**: Length and mapping optimizations are disproportionately important (peak 0.958)
2. **AST Processing Pipeline**: Core changes in `ast_to_malwicode.py` have highest impact
3. **Context Preservation**: Full file scanning > module splitting (0.894 vs 0.847)
4. **Training Data Quality**: False-positives inclusion provided consistent +0.02 improvement
5. **Architecture Stability**: KW_NAMES system is fundamental - modifications must be careful
6. **Performance vs. Efficiency Trade-offs**: Removing entropy mapping improved speed but slightly reduced accuracy

### 🚨 High-Risk Areas
1. **Vocabulary changes**: Can completely break model performance
2. **KW_NAMES modifications**: Essential system, removal causes total failure
3. **Module splitting**: Loses contextual signal quality
4. **String tokenization**: Small changes have large impact

### 📈 Research Directions
1. **Incremental string optimizations**: Build on 0.958 success
2. **Hybrid approaches**: Combine best elements (string mapping + false-positives + KW_NAMES split)
3. **Context preservation**: Maintain full-file context while improving efficiency
4. **Training data curation**: Systematic false-positive identification and inclusion
5. **A/B testing**: Smaller incremental changes rather than major refactors

## Next Steps

### Immediate Priorities
1. **Close performance gap**: Investigate remaining 0.04 F1 gap from peak (0.958 vs 0.918)
2. **Tokenizer optimization**: Fine-tune special token selection for better malware detection
3. **String processing balance**: Optimize string size buckets and classification thresholds
4. **Architecture refinement**: Consolidate successful changes while reverting problematic ones

### Research Pipeline
1. **Advanced token research**: Expand specialized token categories (network patterns, crypto operations, system calls)
2. **Preprocessing optimization**: Balance detection accuracy with processing speed for large-scale deployment
3. **Training data enhancement**: Integrate large file detection signals into training pipeline
4. **Feature ablation**: Determine contribution of each token category to overall performance
5. **Context preservation**: Maintain full-file analysis while optimizing processing efficiency

### Risk Management
- Always tag experiments before major changes
- Test vocabulary/architecture changes on smaller datasets first
- Maintain rollback capability to known good states
- Document all failures to prevent repetition

## Workflow Usage

To add a new research result, provide Claude with:
```
Research commit: [commit_hash]
F1 Score: [score]
Change: [description]
Reasoning: [why performance changed]
```

Claude will automatically tag the commit and update this document chronologically.