# malwi - AI Python Malware Scanner

<img src="malwi-logo.png" alt="Logo">

Detect Python malware _fast_ - no internet, no expensive hardware, no fees.

malwi is specialized in detecting **zero-day vulnerabilities**, for classifying code as safe or harmful. 

Open-source software made in Europe.
Based on open research, open code, open data.
 🇪🇺🤘🕊️

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

malwi applies [DistilBert](https://huggingface.co/docs/transformers/model_doc/distilbert) and Support Vector Machines (SVM) based on the design of [_Zero Day Malware Detection with Alpha: Fast DBI with Transformer Models for Real World Application_ (2025)](https://arxiv.org/pdf/2504.14886v1). 
Additionally, malwi applies [Tree-sitter](https://tree-sitter.github.io/tree-sitter/) for creating Abstract Syntax Tree (ASTs) which are mapped to a unified and security sensitive syntax used as training input. The Python malware dataset can be found [here](https://github.com/lxyeternal/pypi_malregistry). After 3 epochs of training you will get: Loss: `0.0986`, Accuracy: `0.9669`, F1: `0.9666`.

High-level training pipeline:

- Create dataset from malicious/benign repositories and map code to malwi syntax
- Remove code duplications based on hashes
- Train DistilBert based on the malwi samples for categorizing malicious/benign

## Support

Do you have access to malicious Rust, Go, whatever packages? **Contact me.**


### Develop

Prerequisites: [uv](https://docs.astral.sh/uv/)


```
# Download and process data
cmds/download_and_preprocess.sh

# Only process data
cmds/preprocess.sh
```

```
# Preprocess then start training
cmds/preprocess_and_train.sh

# Only start training
cmds/train.sh
```