# This script is for evaluating the results on actual malicious data

for folder in .repo_cache/malicious_repos/pypi_malregistry/*; do
    target_file="analysis/$folder.yaml"
    if [ -d "$folder" ]; then
        if [ -f "$target_file" ]; then
            echo "Skipping $folder (output exists)"
            continue
        fi
        echo "Processing $folder..."
        uv run python -m src.cli.entry -f yaml "$folder" -s "$target_file"
    fi
done