# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

malwi is an AI-powered Python malware scanner that detects zero-day vulnerabilities without requiring internet access. It uses a 3-step pipeline:

1. **AST Compilation**: Python/JavaScript files → language-independent bytecode via AST parsing
2. **Token Mapping**: Bytecode → tokens via custom mappings  
3. **DistilBERT Analysis**: Tokens → maliciousness scores and final classification

## Key Commands

**Development Setup:**
```bash
# Uses uv package manager
uv sync
```

**Testing:**
```bash
uv run pytest tests
```

**Linting:**
```bash
uv run ruff check .
uv run ruff format .
```

**Download Training Data:**
```bash
# Download all required data (malwi-samples + benign/malicious repos)
./cmds/download_data.sh
```

**Training Models:**
```bash
# Full DistilBERT training pipeline (with parallel preprocessing)
./cmds/preprocess_and_train_distilbert.sh

# Data preprocessing only (parallel by default)
./cmds/preprocess_data.sh
```

**Performance Tuning:**
```bash
# Configure parallel preprocessing (default: all CPU cores)
NUM_PROCESSES=8 ./cmds/preprocess_data.sh

# Disable parallel processing for debugging
uv run python -m src.research.preprocess '.repo_cache/benign_repos' benign.csv --no-parallel

# Custom chunk size for large datasets
uv run python -m src.research.preprocess '../malwi-samples' output.csv --chunk-size 50
```

**Regenerate Test Data:**
```bash
# When compiler changes affect output format
uv run python util/regenerate_test_data.py
```

**Repository Pinning:**
```bash
# Update pinned repository commits for reproducible training
uv run python util/pin_repositories.py

# Update model commit hash for releases
python util/update_model_commit.py

# Download data with latest commits (non-reproducible)
uv run python -m src.research.download_data --use-latest
```

**Data Triaging:**
```bash
# Triage newest PyPI packages for suspicious content
uv run python util/triage_pypi.py --count 50

# Dry run to see what packages would be scanned
uv run python util/triage_pypi.py --count 10 --dry-run

# Custom timeout and move directory
uv run python util/triage_pypi.py --timeout 180 --move-dir ./findings
```

**Usage:**
```bash
# Scan local files/directories
uv run python -m src.cli.entry scan examples/malicious

# Scan PyPI packages
uv run python -m src.cli.entry pypi requests
uv run python -m src.cli.entry pypi numpy 1.24.0 --format json --folder downloads

# Different output formats
uv run python -m src.cli.entry scan examples --format yaml
uv run python -m src.cli.entry pypi django --format markdown --save output.md
```

## Building Package

**For end-user distribution (excludes training files):**
```bash
# Backup training files and build clean package
python util/build_helpers.py backup
python -m build --wheel
python util/build_helpers.py restore

# The wheel will only contain files needed for scanning:
# - malwi_object.py, predict_distilbert.py, ast_to_malwicode.py
# - mapping.py, pypi.py, triage.py, syntax_mapping/
# Training files are excluded: train_*.py, preprocess.py, etc.
```

## Release

1. Run pytests
2. Create a version bump, adapt the minor version in:
   - `src/malwi/_version.py` (central version file)
   - Run `uv sync` to update uv.lock
3. **Update model commit hash**: `python util/update_model_commit.py` to get latest HuggingFace model commit and update `src/malwi/_version.py`
4. Build clean package: `python util/build_helpers.py backup && python -m build --wheel && python util/build_helpers.py restore`
5. Create a git commit with: version bump and model commit update
6. Run: `git tag v<version>` (e.g., `git tag v0.0.15`)

**Note**: Version and model commit hash are now centralized in `src/malwi/_version.py`. All other files automatically read from this central location.

## Model Version Pinning

Each malwi release is pinned to a specific HuggingFace model commit hash to ensure reproducibility:

**Get current model commit hash:**
```bash
python util/get_hf_model_info.py 0.0.21
```

**Update model configuration:**
```bash
# Edit src/research/predict_distilbert.py and add the commit hash to VERSION_TO_MODEL_CONFIG
# Example: "0.0.21": {"repo": "schirrmacher/malwi", "revision": "21f808cda19f6a465bbdd568960f6b0291321cdf"}
```

This ensures that:
- Older malwi versions always use compatible models
- Model updates don't break existing installations
- Reproducible results across different environments

## Architecture Notes

- **Entry Point**: `src/cli/entry.py` - CLI interface and orchestration
- **Core Pipeline**: `src/research/malwi_object.py` → `ast_to_malwicode.py` → `predict_distilbert.py`
- **Data Preprocessing**: `src/research/preprocess.py` - Parallel processing for fast AST compilation
- **AST Compilation**: `src/research/ast_to_malwicode.py` - Language-independent bytecode generation
- **Mapping System**: JSON configs in `src/common/syntax_mapping/` define bytecode-to-token mappings
- **Models**: Pre-trained DistilBERT model stored in `malwi-models/`
- **Training Data**: Requires `malwi-samples` repository cloned in parent directory

## Performance

- **Parallel Preprocessing**: ~6-8x faster with multi-core processing (40 min → 5-7 min on 8 cores)
- **Chunk-based Processing**: Each CPU core processes independent file chunks and writes to separate CSV files
- **Automatic Merging**: Chunk CSVs are merged into final output to avoid I/O bottlenecks

## Reproducible Training

malwi uses pinned repository commits to ensure reproducible training data:

- **Pinned Repositories**: All 533 training repositories are pinned to specific commit hashes in `util/pinned_repositories.json`
- **Automatic Verification**: Training data downloads use pinned commits by default  
- **Cache Optimization**: Repository caches include commit hashes in directory names (e.g., `pymatting_a60fdb63`)
- **Fallback Support**: Missing repositories fall back to latest commits with warnings

**Benefits:**
- Identical training data across different machines and time periods
- Reproducible model training results
- Version control for training data dependencies
- Easy rollback to previous training data states

## Important Considerations

- **Language Support**: Supports both Python and JavaScript files through language-independent AST compilation
- **Output Formats**: Supports demo, markdown, json, yaml formats via `--format` flag
- **Triage Options**: Manual (`--triage`) or automated with Ollama (`--triage-ollama`)
- **Performance**: F1=0.96, Recall=0.95, Precision≥0.95 for DistilBERT model