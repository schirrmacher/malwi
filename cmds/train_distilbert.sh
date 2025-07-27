#!/bin/bash

# DistilBERT Training Script: Tokenizer + Model Training
# This script trains both the tokenizer and DistilBERT model

set -e  # Exit on any error

echo "🤖 Starting DistilBERT training pipeline..."
echo "   This includes: Tokenizer training → Model training"
echo

# Check if processed data exists
if [ ! -f "benign_processed.csv" ] || [ ! -f "malicious_processed.csv" ]; then
    echo "❌ Error: Processed data files not found"
    echo "   Please run data preprocessing first to generate processed data"
    exit 1
fi

echo "✅ Processed data files found"
echo

# Step 1: Train tokenizer
echo "🔤 Step 1: Training custom tokenizer..."
echo "   • Using top 5000 most frequent tokens from data"
echo "   • Training on: benign_processed.csv, malicious_processed.csv"
echo "   • Output: malwi_models/"
echo

uv run python -m src.research.train_tokenizer \
    -b benign_processed.csv \
    -m malicious_processed.csv \
    -o malwi_models \
    --top-n-tokens 5000 \
    --save-computed-tokens \
    --force-retrain

echo "✅ Tokenizer training completed"
echo

# Step 2: Train DistilBERT model
echo "🚀 Step 2: Training DistilBERT model..."
echo "   • Loading custom tokenizer from malwi_models/"
echo "   • Training data: benign_processed.csv, malicious_processed.csv"
echo "   • Epochs: 3"
echo "   • Using 1 processor for training"
echo

uv run python -m src.research.train_distilbert \
    -b benign_processed.csv \
    -m malicious_processed.csv \
    --epochs 3 \
    --num-proc 1

echo
echo "🎉 DistilBERT training pipeline completed!"
echo
echo "📋 Generated files in malwi_models/:"
echo "   • Custom tokenizer (trained on your data's top 5000 tokens)"
echo "   • Computed special tokens list"
echo "   • Trained DistilBERT model weights and config"
echo "   • Training metrics and logs"
echo