#!/bin/bash

# Complete DistilBERT Pipeline: Preprocessing + Tokenizer Training + Model Training
# This script runs the full pipeline from data processing to trained model

set -e  # Exit on any error

echo "🔄 Starting complete DistilBERT pipeline..."
echo "   This includes: Data processing → Tokenizer training → Model training"
echo

# Step 1: Data preprocessing
echo "📋 Step 1: Running data preprocessing..."
./cmds/preprocess_data.sh

echo
echo "📋 Step 2: Training custom tokenizer..."
./cmds/train_tokenizer.sh

echo
echo "📋 Step 3: Running DistilBERT model training..."
./cmds/train_distilbert.sh

echo
echo "🎉 Complete DistilBERT pipeline finished successfully!"
echo
echo "📁 All outputs are in malwi_models/:"
echo "   • Tokenizer (trained on your data's top 5000 tokens)"
echo "   • Trained DistilBERT model"
echo "   • Training metrics and logs"
echo