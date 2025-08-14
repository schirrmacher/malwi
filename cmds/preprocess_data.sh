#!/bin/bash

# Data Preprocessing Pipeline
# This script prepares and processes data for machine learning model training

set -e  # Exit on any error

echo "🔄 Data Preprocessing Pipeline"
echo

# Step 1: Clean up previous outputs
echo "📋 Step 1: Cleanup"
echo "   • Removing previous output files..."
rm -f benign.csv malicious.csv malicious_processed.csv benign_processed.csv
echo "   ✅ Cleanup completed"
echo

# Step 2: Generate AST data from source files (parallel by default)
echo "📋 Step 2: Generate AST Data (Parallel Processing)"
echo "   • Generating benign AST data..."
uv run python -m src.research.preprocess '.repo_cache/benign_repos' benign.csv --extensions '.py'
echo "   • Generating malicious AST data..."
uv run python -m src.research.preprocess '../malwi-samples/python/malicious' malicious.csv --extensions '.py'
echo "   ✅ AST data generation completed"
echo

# Step 3: Filter and process the data
echo "📋 Step 3: Data Processing"
echo "   • Filtering and processing data..."
uv run python -m src.research.filter_data -b benign.csv -m malicious.csv --triaging triaging
echo "   ✅ Data processing completed"
echo

# Step 4: Summary
echo "🎉 Data preprocessing completed successfully!"
echo
echo "📁 Generated files:"
echo "   • benign.csv (raw benign data)"
echo "   • malicious.csv (raw malicious data)"
echo "   • benign_processed.csv (processed benign data)"
echo "   • malicious_processed.csv (processed malicious data)"
echo
echo "📖 Next steps:"
echo "   • Run train_tokenizer.sh to create custom tokenizer"
echo "   • Run train_distilbert.sh for DistilBERT model training"
echo "   • Run preprocess_and_train_distilbert.sh for complete pipeline"