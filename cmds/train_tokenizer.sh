#!/bin/bash

# Tokenizer Training Script
# This script trains a custom tokenizer for machine learning models

set -e  # Exit on any error

echo "🔤 Starting tokenizer training..."
echo

# Check if processed data exists
if [ ! -f "benign_processed.csv" ] || [ ! -f "malicious_processed.csv" ]; then
    echo "❌ Error: Processed data files not found"
    echo "   Please run preprocess_data.sh first to generate processed data"
    exit 1
fi

echo "✅ Processed data files found"
echo

# Set configurable parameters
TOTAL_TOKENS=${TOTAL_TOKENS:-15000}

# Train custom tokenizer
echo "🚀 Training custom tokenizer..."
echo "   • Training on: benign_processed.csv, malicious_processed.csv"
echo "   • Total tokens: ${TOTAL_TOKENS}"
echo "   • Output directory: malwi_models/"
echo

uv run python -m src.research.train_tokenizer \
    -b benign_processed.csv \
    -m malicious_processed.csv \
    -o malwi_models \
    --top-n-tokens ${TOTAL_TOKENS} \
    --save-computed-tokens \
    --force-retrain

echo
echo "🎉 Tokenizer training completed successfully!"
echo
echo "📋 Generated files in malwi_models/:"
echo "   • tokenizer.json - Main tokenizer configuration"
echo "   • tokenizer_config.json - Tokenizer metadata"
echo "   • vocab.json - Vocabulary mapping"
echo "   • merges.txt - BPE merge rules"
echo "   • computed_special_tokens.txt - All special tokens (base + data)"
echo "   • base_tokens_from_function_mapping.txt - Base tokens only"
echo
echo "📖 Next steps:"
echo "   • Review computed_special_tokens.txt if needed"
echo "   • Run train_distilbert.sh to train the DistilBERT model"
echo "   • The tokenizer will be automatically loaded from malwi_models/"
echo