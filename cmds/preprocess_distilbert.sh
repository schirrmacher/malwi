#!/bin/bash

rm -f benign.csv malicious.csv malicious_processed.csv benign_processed.csv
uv run python -m src.research.ast_to_malwicode '.repo_cache/benign_repos' -f csv -s benign.csv --extensions '.py'
uv run python -m src.research.ast_to_malwicode '../malwi-samples/python/malicious' -f csv -s malicious.csv  --extensions '.py'
uv run python -m src.research.filter_data -b benign.csv -m malicious.csv --triaging triaging
uv run python -m src.research.train_tokenizer -b benign_processed.csv -m malicious_processed.csv -o malwi_models --force-retrain