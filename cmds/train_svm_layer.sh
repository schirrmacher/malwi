uv run python -m src.research.train_svm_layer \
    -b benign_svm.csv -m malicious_svm.csv \
    --feature-selection random_forest --k-features 81 --optimize