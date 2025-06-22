# malwi - AI Python Malware Scanner

<img src="malwi-logo.png" alt="Logo">
<a href='https://huggingface.co/schirrmacher/malwi'><img src='https://img.shields.io/badge/%F0%9F%A4%97%20HF-Model-blue'></a>&ensp; 


Detect Python malware _fast_ - no internet, no expensive hardware, no fees.

malwi is specialized in detecting **zero-day vulnerabilities**, for classifying code as safe or harmful. 

Open-source software made in Europe.
Based on open research, open code, open data.
 🇪🇺🤘🕊️

1) **Install**
```
pip install --user malwi
```

2) **Run**
```
malwi examples/malicious/discordpydebug-0.0.4
```

3) **Evaluate**: a [recent zero-day](https://socket.dev/blog/malicious-pypi-package-targets-discord-developers-with-RAT) detected with high confidence
```
- files: 12
  ├── scanned: 3
  └── skipped: 9
- objects: 8
  └── malicious: 4
      ├── filesystem access: 5
      ├── fs linking: 5
      ├── encoding decoding: 3
      ├── network http request: 3
      ├── process management: 2
      ├── deserialization: 1
      └── package installation execution: 1

=> 👹 malicious 0.97
```

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

### 4. Create statistics about malicious activities

```
- filesystem access: 5
- fs linking: 5
- encoding decoding: 3
- network http request: 3
- process management: 2
- deserialization: 1
- package installation execution: 1
```

### 5. Take final decision

An SVM layer takes statistics as input and decides if all findings combined are malicious.

```
=> Maliciousness: 0.96
```

## Benchmarks?

### DistilBert

| Metric                     | Value                         |
|----------------------------|-------------------------------|
| F1 Score                   | 0.96                          |
| Recall                     | 0.95                          |
| Precision                  | 0.98                          |
| Training time              | ~4 hours                      |
| Hardware                   | NVIDIA RTX 4090               |
| Epochs                     | 3                             |

### SVM Layer

| Metric                     | Value                         |
|----------------------------|-------------------------------|
| F1 Score                   | 0.96                          |
| Recall                     | 0.95                          |
| Precision                  | 0.95                          |

## Limitations

malwi compiles Python to bytecode, which is highly version dependent. The AI models are trained on that bytecode.
This means the performance might drop if a user installed a Python version which creates different bytecode instructions. There is no data yet about this.

The malicious dataset includes some boilerplate functions, such as init functions, which can also appear in benign code. These cause false positives during scans. The goal is to triage and reduce such false positives to improve malwi's accuracy.

## What's next?

The first iteration focuses on **maliciousness of Python source code**.

Future iterations will cover malware scanning for more languages (JavaScript, Rust, Go) and more formats (binaries, logs).

## Python API

You can use malwi programmatically as a Python library:

```python
from pathlib import Path
from malwi import process_files, MalwiReport

# Analyze a file or directory
report = process_files(
    input_path=Path("./my_project"),
    accepted_extensions=["py"],  # Only analyze Python files
    predict=True,               # Enable maliciousness prediction
    retrieve_source_code=True,  # Include source code in results
    malicious_threshold=0.7,    # Threshold for flagging as malicious
)

# Check results
print(f"Malicious: {report.malicious}")
print(f"Confidence: {report.confidence:.2f}")
print(f"Objects found: {len(report.all_objects)}")
print(f"Malicious objects: {len(report.malicious_objects)}")

# Export results
json_output = report.to_report_json()
yaml_output = report.to_report_yaml()
markdown_output = report.to_report_markdown()
```

### Available Classes

- **`process_files()`**: Main analysis function
- **`MalwiReport`**: Analysis results container with export methods
- **`MalwiObject`**: Individual code object with maliciousness scoring

For a complete example, see [`example_api_usage.py`](example_api_usage.py).

## Support

Do you have access to malicious Rust, Go, whatever packages? **Contact me.**

### Develop

**Prerequisites:** 
- [uv](https://docs.astral.sh/uv/)
- Download [malwi-samples](https://github.com/schirrmacher/malwi-samples) in the same parent folder

```bash
# Download and process data
cmds/download_and_preprocess_distilbert.sh

# Preprocess and train DistilBERT only
cmds/preprocess_and_train_distilbert.sh

# Preprocess and train SVM Layer only
cmds/preprocess_and_train_svm.sh

# Only preprocess data for DistilBERT
cmds/preprocess_distilbert.sh

# Only preprocess data for SVM Layer
cmds/preprocess_svm.sh

# Start DistilBERT training
cmds/train_distilbert.sh

# Start SVM Layer training
cmds/train_svm_layer.sh
```

### Triage

malwi uses a pipeline that can be enhanced by triaging its results (see `src/research/triage.py`). For automated triaging, you can leverage open-source models in combination with [Ollama](https://ollama.com/).

#### Start LLM

```
ollama run gemma3
```

#### Start Triaging

```
uv run python -m src.research.triage --triage-ollama --path <FOLDER_WITH_MALWI_YAML_RESULTS>
```