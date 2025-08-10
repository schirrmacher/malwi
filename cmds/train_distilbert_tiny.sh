#!/bin/bash

# Tiny DistilBERT Model Training Script
# This script trains a tiny version of DistilBERT for resource-constrained environments

set -e  # Exit on any error

echo "🤖 Starting Tiny DistilBERT model training..."
echo "   This creates a much smaller model suitable for edge devices"
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

# Define vocabulary size (should match tokenizer training)
VOCAB_SIZE=5000

# Train Tiny DistilBERT model
echo "🚀 Training Tiny DistilBERT model..."
echo "   • Loading pre-trained tokenizer from malwi_models/"
echo "   • Training data: benign_processed.csv, malicious_processed.csv"
echo "   • Vocabulary size: $VOCAB_SIZE"
echo "   • Model size: TINY (256 hidden dimensions)"
echo "   • Epochs: 5 (more epochs for smaller model)"
echo "   • Using 1 processor for training"
echo

uv run python -m src.research.train_distilbert \
    -b benign_processed.csv \
    -m malicious_processed.csv \
    --epochs 5 \
    --num-proc 1 \
    --vocab-size $VOCAB_SIZE \
    --model-size tiny \
    --model-output-path malwi_models_tiny

echo
echo "🎉 Tiny DistilBERT model training completed!"
echo
echo "📋 Model files saved to malwi_models_tiny/:"
echo "   • Trained Tiny DistilBERT model weights and config"
echo "   • Training metrics and logs"
echo "   • Pre-existing tokenizer (preserved)"
echo
echo "💡 Tiny Model Specifications:"
echo "   • Hidden dimensions: 256 (vs 768 standard)"
echo "   • Attention heads: 4 (vs 12 standard)"
echo "   • Layers: 4 (vs 6 standard)"
echo "   • Vocabulary: $VOCAB_SIZE tokens"
echo "   • Approximate size: ~35MB (vs ~210MB small, ~250MB standard)"
echo "   • Parameters: ~5.5M (vs ~66M standard)"
echo
echo "⚡ Performance Trade-offs:"
echo "   • Much faster inference (4-5x faster)"
echo "   • Lower memory usage (~85% reduction)"
echo "   • Slightly lower accuracy (expect ~2-3% drop)"
echo "   • Ideal for edge devices or high-throughput scenarios"
echo