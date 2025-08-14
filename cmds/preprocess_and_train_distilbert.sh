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
# Get dynamic values
HIDDEN_SIZE=${HIDDEN_SIZE:-256}
TOTAL_TOKENS=${TOTAL_TOKENS:-15000}

echo "📋 Step 3: Running DistilBERT model training (${HIDDEN_SIZE} hidden size)..."
./cmds/train_distilbert.sh

echo
echo "🎉 Complete DistilBERT pipeline finished successfully!"
echo
echo "📁 All outputs are in malwi_models/:"
echo "   • Tokenizer (trained on your data's top ${TOTAL_TOKENS} tokens)"
echo "   • Trained DistilBERT model (${HIDDEN_SIZE} hidden dimensions)"
echo "   • Training metrics and logs"
echo
echo "💡 Tip: For different configurations, set environment variables:"
echo "   HIDDEN_SIZE=512 TOTAL_TOKENS=20000 ./cmds/preprocess_and_train_distilbert.sh"
echo