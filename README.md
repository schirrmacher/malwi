# malwi - AI Python Malware Scanner

<img src="malwi-logo.png" alt="Logo">
<a href='https://huggingface.co/schirrmacher/malwi'><img src='https://img.shields.io/badge/%F0%9F%A4%97%20HF-Model-blue'></a>&ensp; 

## **malwi** detects Python malware using AI.

It specializes in finding **zero-day vulnerabilities** and can classify code as malicious or benign without requiring internet access.

### Key Features
- 🔍 Detects unknown malware patterns through AI analysis
- 🔒 Runs completely offline - no data leaves your machine
- ⚡ Fast scanning of entire codebases 
- 🚫 No external dependencies or cloud services required
- 📖 Open-source project built on research and open data 🇪🇺

### 1) Install
```
pip install --user malwi
```

### 2) Run
```bash
malwi scan examples/malicious
```

### 3) Evaluate: a [recent zero-day](https://socket.dev/blog/malicious-pypi-package-targets-discord-developers-with-RAT) detected with high confidence
```
                  __          __
  .--------.---.-|  .--.--.--|__|
  |        |  _  |  |  |  |  |  |
  |__|__|__|___._|__|________|__|
     AI Python Malware Scanner


- target: examples/malicious
- seconds: 0.42
- files: 13
  ├── scanned: 3
  ├── skipped: 10
  └── suspicious:
      ├── examples/malicious/discordpydebug-0.0.4/setup.py
      │   └── <module>
      │       ├── archive compression
      │       └── package installation execution
      └── examples/malicious/discordpydebug-0.0.4/src/discordpydebug/__init__.py
          ├── <module>
          │   ├── process management
          │   ├── system interaction
          │   ├── deserialization
          │   └── user io
          ├── run
          │   └── fs linking
          ├── debug
          │   ├── fs linking
          │   └── archive compression
          └── runcommand
              └── process management

=> 👹 malicious 0.98
```

## PyPI Package Scanning

malwi can directly scan PyPI packages without executing malicious logic, typically placed in `setup.py` or `__init__.py` files:

```bash
malwi pypi requests

                  __          __
  .--------.---.-|  .--.--.--|__|
  |        |  _  |  |  |  |  |  |
  |__|__|__|___._|__|________|__|
     AI Python Malware Scanner


- target: downloads/requests-2.32.4.tar
- seconds: 3.10
- files: 84
  ├── scanned: 34
  └── skipped: 50

=> 🟢 good
```

### PyPI Command Options
- `--folder, -d`: Download folder (default: downloads)  
- `--format, -f`: Output format (demo, json, yaml, markdown, tokens, code)
- `--threshold, -mt`: Maliciousness threshold (default: 0.7)
- `--save, -s`: Save output to file
- `--quiet, -q`: Suppress logging output

Downloaded packages are preserved in the specified folder for manual inspection and triaging.

## Why malwi?

[The number of _malicious open-source packages_ is growing](https://arxiv.org/pdf/2404.04991). This is not just a threat to your business but also to the open-source community.

Typical malware behaviors include:

- _Exfiltration_ of data: Stealing credentials, API keys, or sensitive user data.
- _Backdoors_: Allowing remote attackers to gain unauthorized access to your system.
- _Destructive_ actions: Deleting files, corrupting databases, or sabotaging applications.

## How does it work?

malwi applies [DistilBert](https://huggingface.co/docs/transformers/model_doc/distilbert) based on the design of [_Zero Day Malware Detection with Alpha: Fast DBI with Transformer Models for Real World Application_ (2025)](https://arxiv.org/pdf/2504.14886v1). The [malwi-samples](https://github.com/schirrmacher/malwi-samples) dataset is used for training.

### 1. Compile Python files to bytecode

```
def runcommand(value):
    output = subprocess.run(value, shell=True, capture_output=True)
    return [output.stdout, output.stderr]
```

```
  0           RESUME                   0

  1           LOAD_CONST               0 (<code object runcommand at 0x5b4f60ae7540, file "example.py", line 1>)
              MAKE_FUNCTION
              STORE_NAME               0 (runcommand)
              RETURN_CONST             1 (None)
  ...
```

### 2. Map bytecode to tokens

```
TARGETED_FILE resume load_global subprocess load_attr run load_fast value load_const INTEGER load_const INTEGER kw_names capture_output shell call store_fast output load_fast output load_attr stdout load_fast output load_attr stderr build_list return_value
```

### 3. Feed tokens into pre-trained DistilBert

```
=> Maliciousness: 0.92
```

This creates a list with malicious code objects. However malicious code might be split into chunks and spread across
a package. This is why the next layers are needed.

### 4. Take final decision

The DistilBERT model makes the final maliciousness decision based on the token patterns.

```
=> Maliciousness: 0.92
```

## Benchmarks?

### DistilBert

| Metric                     | Value                         |
|----------------------------|-------------------------------|
| F1 Score                   | 0.944                         |
| Recall                     | 0.906                         |
| Precision                  | 0.984                         |
| Training time              | ~1 hour                       |
| Hardware                   | NVIDIA RTX 4090               |
| Epochs                     | 3                             |


## Limitations

The malicious dataset includes some boilerplate functions, such as init functions, which can also appear in benign code. These cause false positives during scans. The goal is to triage and reduce such false positives to improve malwi's accuracy.

## What's next?

The first iteration focuses on **maliciousness of Python source code**.

Future iterations will cover malware scanning for more languages (JavaScript, Rust, Go) and more formats (binaries, logs).

## Contributing & Support

### 🐛 Report Issues
Found a bug or have a feature request? [Open an issue](https://github.com/schirrmacher/malwi/issues)

### 📊 Share Malware Samples
Have access to malicious packages in Rust, Go, or other languages? Your contributions can help expand malwi's detection capabilities:
- **Email**: [Contact via GitHub profile](https://github.com/schirrmacher)
- **Submit samples**: Follow responsible disclosure practices

### 💬 Community
- **Discussions**: Share ideas and ask questions in [GitHub Discussions](https://github.com/schirrmacher/malwi/discussions)
- **Security**: Report security vulnerabilities privately via GitHub Security tab

## Development

### 🛠️ Prerequisites

1. **Package Manager**: Install [uv](https://docs.astral.sh/uv/) for fast Python dependency management
2. **Training Data**: Clone [malwi-samples](https://github.com/schirrmacher/malwi-samples) in the parent directory:
   ```bash
   cd ..
   git clone https://github.com/schirrmacher/malwi-samples.git
   cd malwi
   ```

### 🚀 Quick Start

```bash
# Install dependencies
uv sync

# Run tests
uv run pytest tests

# Train a model from scratch (full pipeline)
./cmds/preprocess_and_train_distilbert.sh
```

### 📚 Training Pipeline

The training pipeline consists of three stages that can be run together or independently:

#### **Complete Pipeline** (Recommended)
```bash
# Data preprocessing → Tokenizer training → Model training
./cmds/preprocess_and_train_distilbert.sh
```

#### **Individual Stages**
```bash
# 1. Data Preprocessing (parallel by default, ~5-7 min on 8 cores)
./cmds/preprocess_data.sh

# 2. Tokenizer Training (~2 min)
./cmds/train_tokenizer.sh

# 3. Model Training (~5 hours on NVIDIA RTX 4090)
./cmds/train_distilbert.sh
```

### ⚙️ Configuration

```bash
# Customize parallel processing (preprocessing)
NUM_PROCESSES=16 ./cmds/preprocess_data.sh

# Train smaller/faster model
HIDDEN_SIZE=256 ./cmds/train_distilbert.sh

# Train larger/more accurate model  
HIDDEN_SIZE=512 EPOCHS=5 ./cmds/train_distilbert.sh
```

### 🧪 Testing & Quality

```bash
# Run tests
uv run pytest tests

# Code formatting
uv run ruff format .

# Linting
uv run ruff check .

# Regenerate test data (after compiler changes)
uv run python util/regenerate_test_data.py
```
