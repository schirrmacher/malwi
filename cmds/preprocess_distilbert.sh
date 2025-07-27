#!/bin/bash

# DistilBERT Preprocessing Pipeline
# This script prepares data and trains a tokenizer for DistilBERT model training

set -e  # Exit on any error

echo "🚀 Starting DistilBERT preprocessing pipeline..."
echo

# Step 1: Clean up previous outputs
echo "🧹 Cleaning up previous outputs..."
rm -f benign.csv malicious.csv malicious_processed.csv benign_processed.csv
echo "✅ Cleanup completed"
echo

# Step 2: Generate AST data from source files
echo "📊 Generating benign AST data..."
uv run python -m src.research.ast_to_malwicode '.repo_cache/benign_repos' -f csv -s benign.csv --extensions '.py'
echo "✅ Benign data generated"
echo

echo "📊 Generating malicious AST data..."
uv run python -m src.research.ast_to_malwicode '../malwi-samples/python/malicious' -f csv -s malicious.csv --extensions '.py'
echo "✅ Malicious data generated"
echo

# Step 3: Filter and process the data
echo "🔍 Filtering and processing data..."
uv run python -m src.research.filter_data -b benign.csv -m malicious.csv --triaging triaging
echo "✅ Data filtering completed"
echo

# Step 4: Train tokenizer on the processed data
echo "🔤 Training tokenizer with top 5000 most frequent tokens..."
uv run python -m src.research.train_tokenizer \
    -b benign_processed.csv \
    -m malicious_processed.csv \
    -o malwi_models \
    --top-n-tokens 5000 \
    --save-computed-tokens \
    --force-retrain
echo "✅ Tokenizer training completed"
echo

# Step 5: Summary
echo "🎉 DistilBERT preprocessing completed successfully!"
echo
echo "📋 Generated files:"
echo "   • Raw data: benign.csv, malicious.csv"
echo "   • Processed data: benign_processed.csv, malicious_processed.csv"
echo "   • Tokenizer: malwi_models/"
echo "   • Computed tokens: malwi_models/computed_special_tokens.txt"
echo
echo "📖 Next steps:"
echo "   1. Review the computed special tokens file if needed"
echo "   2. Run train_distilbert.py to train the model using this tokenizer"
echo "   3. The tokenizer will automatically be loaded from malwi_models/"
echo