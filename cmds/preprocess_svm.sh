rm benign_svm.csv
rm malicious_svm.csv

# Train based on the new model in malwi-models
# Add random benign sampling data to increase the benign dataset

uv run python -m src.research.create_svm_data \
    --label benign \
    --dir .repo_cache/benign_repos \
    -s benign_svm.csv \
    --use-random-sampling --samples 1000 --max-files-per-sample 100 \
    -m malwi-models -t malwi-models

uv run python -m src.research.create_svm_data \
    --label benign \
    --dir .repo_cache/benign_repos \
    -s benign_svm.csv \
    -m malwi-models -t malwi-models

uv run python -m src.research.create_svm_data \
    --label malicious \
    --dir ../malwi-samples/python/malicious \
    -s malicious_svm.csv \
    -m malwi-models -t malwi-models