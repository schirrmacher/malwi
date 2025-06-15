# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

malwi is an AI-powered Python malware scanner that detects zero-day vulnerabilities without requiring internet access. It uses a 5-step pipeline:

1. **Bytecode Compilation**: Python files → bytecode
2. **Token Mapping**: Bytecode → tokens via custom mappings
3. **DistilBERT Analysis**: Tokens → maliciousness scores
4. **Statistical Aggregation**: Scores → activity statistics (e.g., DYNAMIC_CODE_EXECUTION, FILESYSTEM_ACCESS)
5. **SVM Classification**: Statistics → final maliciousness decision

## Key Commands

**Development Setup:**
```bash
# Uses uv package manager
uv sync
```

**Testing:**
```bash
pytest
```

**Linting:**
```bash
ruff check .
ruff format .
```

**Training Models:**
```bash
# Full DistilBERT training pipeline
./cmds/preprocess_and_train_distilbert.sh

# Full SVM training pipeline
./cmds/preprocess_and_train_svm.sh
```

## Architecture Notes

- **Entry Point**: `src/cli/entry.py` - CLI interface and orchestration
- **Core Pipeline**: `src/research/disassemble_python.py` → `mapping.py` → `predict_distilbert.py` → `predict_svm_layer.py`
- **Mapping System**: JSON configs in `src/research/syntax_mapping/` define bytecode-to-token mappings
- **Models**: Pre-trained models stored in `malwi-models/`
- **Training Data**: Requires `malwi-samples` repository cloned in parent directory

## Important Considerations

- **Python Version Sensitivity**: Bytecode compilation is Python version-dependent, affecting model performance across versions
- **Output Formats**: Supports demo, markdown, json, yaml formats via `--format` flag
- **Triage Options**: Manual (`--triage`) or automated with Ollama (`--triage-ollama`)
- **Performance**: F1=0.96, Recall=0.95, Precision≥0.95 for both models