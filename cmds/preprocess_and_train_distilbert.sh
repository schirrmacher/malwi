#!/bin/bash

# Complete DistilBERT Pipeline: Preprocessing + Tokenizer Training + Model Training
# This script runs the full pipeline from data processing to trained model

set -e  # Exit on any error

echo "🔄 Starting complete DistilBERT pipeline..."
echo "   This includes: Data processing → Tokenizer training → Model training"
echo

# Step 1: Data preprocessing and tokenizer training
echo "📋 Step 1: Running data preprocessing and tokenizer training..."
./cmds/preprocess_distilbert.sh

echo
echo "📋 Step 2: Running DistilBERT model training..."
./cmds/train_distilbert.sh

echo
echo "🎉 Complete DistilBERT pipeline finished successfully!"
echo
echo "📁 All outputs are in malwi_models/:"
echo "   • Tokenizer (trained on your data's top 5000 tokens)"
echo "   • Trained DistilBERT model"
echo "   • Training metrics and logs"
echo