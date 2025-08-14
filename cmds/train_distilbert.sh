#!/bin/bash

# DistilBERT Model Training Script
# This script trains the DistilBERT model using a pre-existing tokenizer

set -e  # Exit on any error

echo "🤖 Starting DistilBERT model training..."
echo

# Check if processed data exists
if [ ! -f "benign_processed.csv" ] || [ ! -f "malicious_processed.csv" ]; then
    echo "❌ Error: Processed data files not found"
    echo "   Please run preprocess_data.sh first to generate processed data"
    exit 1
fi

echo "✅ Processed data files found"

# Check if tokenizer exists
if [ ! -f "malwi_models/tokenizer.json" ]; then
    echo "❌ Error: No tokenizer found at malwi_models/"
    echo "   Please run train_tokenizer.sh first to create the tokenizer"
    exit 1
fi

echo "✅ Tokenizer found at malwi_models/"
echo

# Train DistilBERT model
echo "🚀 Training DistilBERT model..."
echo "   • Loading pre-trained tokenizer from malwi_models/"
echo "   • Training data: benign_processed.csv, malicious_processed.csv"
echo "   • Model size: 256 hidden dimensions (smaller, faster model)"
echo "   • Epochs: 3"
echo "   • Using 1 processor for training"
echo
echo "   Note: Use --hidden-size 512 for larger model with better accuracy"
echo

uv run python -m src.research.train_distilbert \
    -b benign_processed.csv \
    -m malicious_processed.csv \
    --epochs 3 \
    --hidden-size 256 \
    --num-proc 1

echo
echo "🎉 DistilBERT model training completed!"
echo
echo "📋 Model files saved to malwi_models/:"
echo "   • Trained DistilBERT model weights and config"
echo "   • Training metrics and logs"
echo "   • Pre-existing tokenizer (preserved)"
echo