uv run python -m src.research.download_data
uv run python -m src.research.normalize_data -o benign
uv run python -m src.research.normalize_data -o malicious
uv run python -m src.research.filter_data malicious.csv benign.csv