uv run python -m src.research.normalize_data -o benign
uv run python -m src.research.normalize_data -o malicious
uv run python -m src.research.filter_data malicious.csv benign.csv
uv run python -m src.research.train train --malicious_csv malicious_processed.csv --benign_csv benign_processed.csv --epochs 3