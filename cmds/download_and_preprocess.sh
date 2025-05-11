uv run python -m src.research.download_data
uv run python -m src.research.normalize_data -o benign
uv run python -m src.research.normalize_data -o malicious
uv run python -m src.research.filter_data -b benign.csv -m malicious.csv