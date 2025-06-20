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

## Release

1. Run pytests
2. Create a version bump, adapt the minor version in:
   - `src/malwi/_version.py` (central version file)
   - Run `uv sync` to update uv.lock
3. Create a git commit with: version bump
4. Run: `git tag v<version>` (e.g., `git tag v0.0.15`)

**Note**: Version is now centralized in `src/malwi/_version.py`. All other files (pyproject.toml, setup.py, CLI) automatically read from this central location.

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