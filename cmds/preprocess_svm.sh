rm benign_svm.csv
rm malicious_svm.csv
uv run python -m src.research.create_svm_data --label benign --dir .repo_cache/benign_repos  -s benign_svm.csv --benign-samples 1000 --max-files-per-sample 100
uv run python -m src.research.create_svm_data --label malicious --dir ../malwi-samples/python/malicious  -s malicious_svm.csv