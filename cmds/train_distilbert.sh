rm -rf malwi_models
uv run python -m src.research.train_distilbert -b benign_processed.csv -m malicious_processed.csv --epochs 3 --num-proc 1