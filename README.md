# malwi - AI Python Malware Scanner

<img src="malwi-logo.png" alt="Logo">
<a href='https://huggingface.co/schirrmacher/malwi'><img src='https://img.shields.io/badge/%F0%9F%A4%97%20HF-Model-blue'></a>&ensp; 

**malwi** detects Python malware using machine learning. It specializes in finding **zero-day vulnerabilities** and can classify code as malicious or benign without requiring internet access.

## Key Features
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
```
malwi examples/malicious
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
| Training time              | ~5 hours                      |
| Hardware                   | NVIDIA RTX 4090               |
| Epochs                     | 3                             |


## Limitations

The malicious dataset includes some boilerplate functions, such as init functions, which can also appear in benign code. These cause false positives during scans. The goal is to triage and reduce such false positives to improve malwi's accuracy.

## What's next?

The first iteration focuses on **maliciousness of Python source code**.

Future iterations will cover malware scanning for more languages (JavaScript, Rust, Go) and more formats (binaries, logs).

## Support

Do you have access to malicious Rust, Go, whatever packages? **Contact me.**

### Develop

**Prerequisites:** 
- [uv](https://docs.astral.sh/uv/)
- Download [malwi-samples](https://github.com/schirrmacher/malwi-samples) in the same parent folder

```bash
# Download and process data
cmds/download_and_preprocess_distilbert.sh

# Complete pipelines
cmds/preprocess_and_train_distilbert.sh  # Data → Tokenizer → DistilBERT

# Individual data preprocessing
cmds/preprocess_data.sh                  # Process data for ML training

# Individual model training
cmds/train_tokenizer.sh                  # Train custom tokenizer
cmds/train_distilbert.sh                 # Train DistilBERT model
```
