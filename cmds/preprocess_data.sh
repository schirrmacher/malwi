#!/bin/bash

# Data Preprocessing Pipeline
# This script prepares and processes data for machine learning model training

set -e  # Exit on any error

echo "🚀 Starting data preprocessing pipeline..."
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

# Step 4: Summary
echo "🎉 Data preprocessing completed successfully!"
echo
echo "📋 Generated files:"
echo "   • Raw data: benign.csv, malicious.csv"
echo "   • Processed data: benign_processed.csv, malicious_processed.csv"
echo
echo "📖 Next steps:"
echo "   • Run train_tokenizer.sh to create custom tokenizer"
echo "   • Run train_distilbert.sh for DistilBERT model training"
echo "   • Run train_svm_layer.sh for SVM model training"
echo "   • Or run preprocess_and_train_distilbert.sh for complete pipeline"
echo