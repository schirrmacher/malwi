# Triage CLI Test Suite

This document describes the comprehensive test suite for the new `triage` CLI command in malwi.

## Test Coverage

The test suite covers the following components and functionality:

### 1. Base URL Derivation Logic (`TestFirstResponderBaseURL`)

Tests the smart base URL derivation based on model names:

- **Explicit Override**: Tests that manually provided base URLs take precedence
- **Mistral Models**: Verifies models containing "mistral" use `https://api.mistral.ai/v1`
- **OpenAI Models**: Verifies models containing "openai" or "gpt" use `https://api.openai.com/v1`
- **Claude Models**: Verifies models containing "claude" or "anthropic" use `https://api.anthropic.com/v1`
- **LLaMA Models**: Verifies models containing "llama" or "meta" use `https://api.together.xyz/v1`
- **Gemini Models**: Verifies models containing "gemini" or "google" use Google's API
- **Unknown Models**: Tests that unknown models default to Mistral API

**Example Model Coverage:**
```
Mistral: mistral-large-2411, mistral-medium-2508, custom-mistral-model
OpenAI: gpt-4o-mini, gpt-3.5-turbo, openai-gpt-4
Claude: claude-3-sonnet, anthropic-claude
LLaMA: llama-3.1-8b, meta-llama-3
Gemini: gemini-1.5-pro, google-gemini-flash
```

### 2. CLI Argument Parsing (`TestTriageCLIArguments`)

Tests the command-line interface argument handling:

- **Required Arguments**: Verifies that the input path is mandatory
- **Default Values**: Confirms `mistral-large-2411` is the default model
- **Flexible Models**: Tests that any custom model name is accepted (no hard-coding)
- **Optional Flags**: Verifies base-url and API key are optional
- **Custom Folders**: Tests customization of output folder names
- **Environment Variables**: Confirms API key can be provided via environment

### 3. Command Execution (`TestTriageCommand`)

Tests the main triage command execution logic:

- **Environment Variable Handling**: Tests reading API key from `LLM_API_KEY` env var
- **CLI Precedence**: Verifies command-line API key overrides environment variable
- **Error Handling**: Tests proper error responses for invalid input paths
- **Parameter Passing**: Confirms all custom parameters are passed through correctly

### 4. Core Triage Function (`TestRunTriageFunction`)

Tests the main `run_triage` function:

- **Custom Folder Creation**: Verifies folders are created with custom names
- **File Organization**: Tests that folders are moved to correct categories based on decisions
- **Input Validation**: Tests error handling for invalid paths and file inputs
- **Folder Structure**: Confirms proper directory hierarchy is maintained

### 5. Integration Scenarios (`TestIntegrationScenarios`)

Tests realistic end-to-end scenarios:

- **Multi-Category Triage**: Tests mixed benign/suspicious/malicious content
- **File Preservation**: Verifies original file contents are preserved during moves
- **Complex Folder Structure**: Tests handling of nested folder hierarchies
- **Edge Cases**: Tests empty directories and root-level file handling

## Test Structure

### Mock Strategy

The tests use comprehensive mocking to:
- Isolate units under test
- Avoid external API calls during testing
- Control LLM response behavior for predictable testing
- Test error conditions safely

### Test Data

Tests create realistic temporary directory structures with:
- Multiple folders representing different threat levels
- Various file types (Python, JavaScript)
- Realistic code samples (legitimate, suspicious, malicious)
- Complex nested folder hierarchies

### Assertions

Tests verify:
- Correct API endpoints are called
- Proper parameter passing
- File system operations work correctly
- Error conditions are handled gracefully
- Output folder structure matches expectations

## Running the Tests

```bash
# Run all triage tests
uv run pytest tests/test_triage_cli.py -v

# Run specific test class
uv run pytest tests/test_triage_cli.py::TestFirstResponderBaseURL -v

# Run specific test
uv run pytest tests/test_triage_cli.py::TestTriageCLIArguments::test_default_model_is_mistral_large -v

# Run with coverage
uv run pytest tests/test_triage_cli.py --cov=cli.triage --cov=common.triage --cov=cli.agents.first_responder
```

## Test Results

All 23 tests pass, providing comprehensive coverage of:
- 7 base URL derivation scenarios
- 6 CLI argument parsing cases  
- 4 command execution scenarios
- 4 core function tests
- 2 integration scenarios

This ensures the triage CLI is robust, flexible, and handles edge cases properly while maintaining compatibility with multiple LLM providers through the AutoGen framework.