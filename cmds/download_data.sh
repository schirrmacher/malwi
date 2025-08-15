#!/bin/bash

# Data Download Pipeline
# Downloads all required training data including benign repos and malwi-samples

set -e  # Exit on any error

echo "📥 Starting complete data download pipeline..."
echo "   This includes: malwi-samples + benign/malicious repositories"
echo

# Step 1: Clone/update malwi-samples repository
echo "📋 Step 1: Downloading malwi-samples..."
if [ ! -d "../malwi-samples" ]; then
    echo "   • Cloning malwi-samples repository..."
    cd ..
    git clone https://github.com/schirrmacher/malwi-samples.git
    cd malwi
    echo "   ✅ malwi-samples cloned successfully"
else
    echo "   • Updating existing malwi-samples repository..."
    cd ../malwi-samples
    git pull origin main
    cd ../malwi
    echo "   ✅ malwi-samples updated successfully"
fi
echo

# Step 2: Download training repositories (benign + malicious)
echo "📋 Step 2: Downloading training repositories..."
echo "   • Using pinned commits for reproducible training"
echo "   • This may take 10-30 minutes depending on network speed"

# Run the download_data script with pinned commits
uv run python -m src.research.download_data --type all

echo "   ✅ Repository download completed"
echo

# Step 3: Show summary
echo "🎉 Data download completed successfully!"
echo
echo "📁 Downloaded data:"
echo "   • ../malwi-samples/ - Malware samples for training"
echo "   • .repo_cache/benign_repos/ - Benign Python repositories (pinned)"
echo "   • .repo_cache/malicious_repos/ - Malicious package datasets (pinned)"
echo
echo "📖 Next steps:"
echo "   • Run preprocess_data.sh to process the downloaded data"
echo "   • Run train_tokenizer.sh to create custom tokenizer"
echo "   • Run train_distilbert.sh for DistilBERT model training"
echo "   • Or run preprocess_and_train_distilbert.sh for complete pipeline"
echo

# Show disk usage summary
echo "💾 Disk usage summary:"
if [ -d "../malwi-samples" ]; then
    MALWI_SAMPLES_SIZE=$(du -sh ../malwi-samples 2>/dev/null | cut -f1 || echo "unknown")
    echo "   • malwi-samples: ${MALWI_SAMPLES_SIZE}"
fi
if [ -d ".repo_cache" ]; then
    REPO_CACHE_SIZE=$(du -sh .repo_cache 2>/dev/null | cut -f1 || echo "unknown")
    echo "   • Repository cache: ${REPO_CACHE_SIZE}"
fi
echo