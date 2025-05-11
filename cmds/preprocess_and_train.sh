uv run python -m src.research.normalize_data -o benign
uv run python -m src.research.normalize_data -o malicious
uv run python -m src.research.filter_data -b benign.csv -m malicious.csv 
uv run python -m src.research.train train -b benign_processed.csv --m malicious_processed.csv --epochs 3