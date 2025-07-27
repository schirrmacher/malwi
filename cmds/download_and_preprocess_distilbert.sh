#!/bin/bash

# DistilBERT Data Download and Preprocessing Pipeline
# Downloads data, processes it, and trains a custom tokenizer

set -e  # Exit on any error

echo "📥 Starting DistilBERT data download and preprocessing..."
echo "   This includes: Data download → Processing → Tokenizer training"
echo

# Step 1: Download data
echo "📋 Step 1: Downloading training data..."
uv run python -m src.research.download_data
echo "✅ Data download completed"
echo

# Step 2: Preprocess data and train tokenizer
echo "📋 Step 2: Processing data and training tokenizer..."
./cmds/preprocess_distilbert.sh

echo
echo "🎉 DistilBERT data preparation completed successfully!"
echo
echo "📁 Ready for model training:"
echo "   • Processed training data available"
echo "   • Custom tokenizer trained on your data (top 5000 tokens)"
echo "   • Run train_distilbert.sh or preprocess_and_train_distilbert.sh next"
echo