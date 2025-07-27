#!/bin/bash

# DistilBERT Data Download and Preprocessing Pipeline
# Downloads data, processes it, and trains a custom tokenizer

set -e  # Exit on any error

echo "📥 Starting DistilBERT data download and preprocessing..."
echo "   This includes: Data download → Processing"
echo

# Step 1: Download data
echo "📋 Step 1: Downloading training data..."
uv run python -m src.research.download_data
echo "✅ Data download completed"
echo

# Step 2: Preprocess data
echo "📋 Step 2: Processing data..."
./cmds/preprocess_data.sh

echo
echo "🎉 DistilBERT data preparation completed successfully!"
echo
echo "📁 Ready for model training:"
echo "   • Processed training data available"
echo "   • Run train_tokenizer.sh first to create custom tokenizer"
echo "   • Run train_distilbert.sh for DistilBERT model training"
echo "   • Run preprocess_and_train_distilbert.sh for complete pipeline"
echo