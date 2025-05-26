# malwi - AI Python Malware Scanner

<img src="malwi-logo.png" alt="Logo">

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
malwi ./examples
```

3) **Evaluate**: a [recent zero-day](https://socket.dev/blog/malicious-pypi-package-targets-discord-developers-with-RAT) detected with high confidence
```
def runcommand(value):
    output = subprocess.run(value, shell=True, capture_output=True)
    return [output.stdout, output.stderr]

## examples/__init__.py
- Object: runcommand
- Maliciousness: 👹 0.9620079398155212
```

## Why malwi?

[The number of _malicious open-source packages_ is growing](https://arxiv.org/pdf/2404.04991). This is not just a threat to your business but also to the open-source community.

Typical malware behaviors include:

- _Exfiltration_ of data: Stealing credentials, API keys, or sensitive user data.
- _Backdoors_: Allowing remote attackers to gain unauthorized access to your system.
- _Destructive_ actions: Deleting files, corrupting databases, or sabotaging applications.

> **Attention**: Malicious packages might execute code during installation (e.g. through `setup.py`). 
Make sure to *NOT* download or install malicious packages from the dataset with commands like `uv add`, `pip install`, `poetry add`.

## What's next?

The first iteration focuses on **maliciousness of Python source code**.

Future iterations will cover malware scanning for more languages (JavaScript, Rust, Go) and more formats (binaries, logs).

## How does it work?

malwi applies [DistilBert](https://huggingface.co/docs/transformers/model_doc/distilbert) and Support Vector Machines (SVM) based on the design of [_Zero Day Malware Detection with Alpha: Fast DBI with Transformer Models for Real World Application_ (2025)](https://arxiv.org/pdf/2504.14886v1). [pypi_malregistry](https://github.com/lxyeternal/pypi_malregistry) is used as a source for malicious samples.

1. malwi compiles Python files to bytecode:

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

2. Bytecode operators are mapped to tokens:

```
TARGETED_FILE resume load_global subprocess load_attr run load_fast value load_const INTEGER load_const INTEGER kw_names capture_output shell call store_fast output load_fast output load_attr stdout load_fast output load_attr stderr build_list return_value
```

3. Tokens are used as input for a pre-trained DistilBert:

```
Maliciousness: 0.9620079398155212
```

## Support

Do you have access to malicious Rust, Go, whatever packages? **Contact me.**

### Develop

Prerequisites: [uv](https://docs.astral.sh/uv/)
```
# Download and process data
cmds/download_and_preprocess.sh

# Only process data
cmds/preprocess.sh

# Preprocess then start training
cmds/preprocess_and_train.sh

# Only start training
cmds/train.sh
```