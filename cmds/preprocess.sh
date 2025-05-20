uv run python -m src.research.disassemble_python '.repo_cache/benign_repos' -f csv -s benign.csv
uv run python -m src.research.disassemble_python '.repo_cache/malicious_repos' -f csv -s malicious.csv
uv run python -m src.research.filter_data -b benign.csv -m malicious.csv