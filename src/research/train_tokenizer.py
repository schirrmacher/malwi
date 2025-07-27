import os
import dis
import shutil
import pathlib
import argparse
import pandas as pd
from typing import Set
from pathlib import Path
from tokenizers import ByteLevelBPETokenizer, Tokenizer
from tokenizers.models import BPE
from tokenizers.normalizers import NFKC, Sequence, Lowercase
from tokenizers.pre_tokenizers import ByteLevel
from transformers import PreTrainedTokenizerFast

from common.messaging import (
    configure_messaging,
    info,
    success,
    warning,
    error,
)

DEFAULT_TOKENIZER_OUTPUT_PATH = Path("malwi_models")
DEFAULT_MAX_LENGTH = 512
DEFAULT_VOCAB_SIZE = 30522


def load_asts_from_csv(
    csv_file_path: str, token_column_name: str = "tokens"
) -> list[str]:
    """Load AST data from CSV file for tokenizer training."""
    asts = []
    try:
        df = pd.read_csv(csv_file_path)
        if token_column_name not in df.columns:
            warning(
                f"Column '{token_column_name}' not found in {csv_file_path}. Returning empty list."
            )
            return []

        for idx, row in df.iterrows():
            ast_data = row[token_column_name]
            if (
                pd.isna(ast_data)
                or not isinstance(ast_data, str)
                or not ast_data.strip()
            ):
                continue
            asts.append(ast_data.strip())
        success(f"Loaded {len(asts)} sample strings from {csv_file_path}")
    except FileNotFoundError:
        error(f"File not found at {csv_file_path}. Returning empty list.")
        return []
    except Exception as e:
        error(f"Reading CSV {csv_file_path}: {e}. Returning empty list.")
        return []
    return asts


def compute_tokens_from_texts(texts: list[str]) -> Set[str]:
    """
    Extract all unique tokens from input texts by splitting on whitespace.

    Args:
        texts: List of text strings to tokenize

    Returns:
        Set of unique tokens found in the texts
    """
    all_tokens = set()

    for text in texts:
        if not isinstance(text, str):
            continue
        # Split on whitespace and add non-empty tokens
        tokens = text.split()
        for token in tokens:
            token = token.strip()
            if token:  # Only add non-empty tokens
                all_tokens.add(token)

    return all_tokens


def create_special_tokens_from_data(
    all_texts: list[str], top_n_tokens: int = 5000
) -> Set[str]:
    """
    Create special tokens from the most frequent tokens in the input data.
    Takes the top N most common tokens regardless of frequency.

    Args:
        all_texts: List of all training texts
        top_n_tokens: Number of most frequent tokens to use as special tokens

    Returns:
        Set of special tokens derived from the data
    """
    info("Computing token frequencies from input data...")

    # Count token frequencies
    token_counts = {}
    total_texts = len(all_texts)

    for i, text in enumerate(all_texts):
        if i % 1000 == 0:
            info(f"Processing text {i + 1}/{total_texts}")

        if not isinstance(text, str):
            continue

        tokens = text.split()
        for token in tokens:
            token = token.strip()
            if token:
                token_counts[token] = token_counts.get(token, 0) + 1

    # Sort all tokens by frequency (descending) and take top N
    sorted_tokens = sorted(token_counts.items(), key=lambda x: x[1], reverse=True)

    # Take the top N most frequent tokens
    top_tokens = sorted_tokens[:top_n_tokens]
    special_tokens = set()
    for token, count in top_tokens:
        special_tokens.add(token)

    info(
        f"Created {len(special_tokens)} special tokens from {len(token_counts)} unique tokens"
    )
    if top_tokens:
        info(f"Frequency range: {top_tokens[0][1]} to {top_tokens[-1][1]}")

    return special_tokens


def create_or_load_tokenizer(
    tokenizer_output_path: Path,
    texts_for_training: list[str],
    vocab_size: int,
    computed_special_tokens: Set[str],
    max_length: int,
    force_retrain: bool,
):
    """Create a new tokenizer or load existing one."""
    huggingface_tokenizer_config_file = tokenizer_output_path / "tokenizer.json"

    if not force_retrain and huggingface_tokenizer_config_file.exists():
        info(
            f"Loading existing PreTrainedTokenizerFast from {tokenizer_output_path} (found tokenizer.json)."
        )
        tokenizer = PreTrainedTokenizerFast.from_pretrained(
            str(tokenizer_output_path), model_max_length=max_length
        )
    else:
        info("Training or re-training custom BPE tokenizer...")
        if force_retrain and tokenizer_output_path.exists():
            warning(
                f"Force retraining: Deleting existing tokenizer directory: {tokenizer_output_path}"
            )
            try:
                shutil.rmtree(tokenizer_output_path)
            except OSError as e:
                error(
                    f"Deleting directory {tokenizer_output_path}: {e}. Please delete manually and retry."
                )
                raise

        tokenizer_output_path.mkdir(parents=True, exist_ok=True)

        vocab_file_path = tokenizer_output_path / "vocab.json"
        merges_file_path = tokenizer_output_path / "merges.txt"

        if not texts_for_training:
            error("No texts provided for training BPE tokenizer.")
            raise ValueError("Cannot train tokenizer with no data.")

        bpe_trainer_obj = ByteLevelBPETokenizer()

        # Only use essential BPE tokens and computed tokens from data
        bpe_essential_tokens = [
            "[PAD]",
            "[UNK]",
            "[CLS]",
            "[SEP]",
            "[MASK]",
        ]

        # Combine essential tokens with computed tokens from input data
        combined_special_tokens = list(
            set(bpe_essential_tokens + list(computed_special_tokens))
        )

        info(f"Total special tokens: {len(combined_special_tokens)}")
        info(f"  - BPE essential tokens: {len(bpe_essential_tokens)}")
        info(f"  - Computed from input data: {len(computed_special_tokens)}")

        bpe_trainer_obj.train_from_iterator(
            texts_for_training,
            vocab_size=vocab_size,
            min_frequency=2,
            special_tokens=combined_special_tokens,
        )
        bpe_trainer_obj.save_model(str(tokenizer_output_path))
        success(
            f"BPE components (vocab.json, merges.txt) saved to {tokenizer_output_path}"
        )

        bpe_model = BPE.from_file(
            str(vocab_file_path), str(merges_file_path), unk_token="[UNK]"
        )
        tk = Tokenizer(bpe_model)
        tk.normalizer = Sequence([NFKC(), Lowercase()])
        tk.pre_tokenizer = ByteLevel()

        tokenizer = PreTrainedTokenizerFast(
            tokenizer_object=tk,
            unk_token="[UNK]",
            pad_token="[PAD]",
            cls_token="[CLS]",
            sep_token="[SEP]",
            mask_token="[MASK]",
            bos_token="[CLS]",
            eos_token="[SEP]",
            model_max_length=max_length,
        )
        tokenizer.save_pretrained(str(tokenizer_output_path))
        success(
            f"PreTrainedTokenizerFast fully saved to {tokenizer_output_path} (tokenizer.json created)."
        )

    return tokenizer


def train_tokenizer(args):
    """Main function to train tokenizer from CSV data."""
    info("Starting tokenizer training...")

    # Load training data from CSV files
    all_texts_for_training = []

    if args.benign:
        benign_asts = load_asts_from_csv(args.benign, args.token_column)
        all_texts_for_training.extend(benign_asts)
        info(f"Loaded {len(benign_asts)} benign samples")

    if args.malicious:
        malicious_asts = load_asts_from_csv(args.malicious, args.token_column)
        all_texts_for_training.extend(malicious_asts)
        info(f"Loaded {len(malicious_asts)} malicious samples")

    if not all_texts_for_training:
        error(
            "No training data loaded. Please provide valid CSV files with tokenizable content."
        )
        return

    info(f"Total training texts: {len(all_texts_for_training)}")

    # Compute special tokens from the input data
    info("Computing special tokens from input data...")
    computed_special_tokens = create_special_tokens_from_data(
        all_texts_for_training,
        top_n_tokens=args.top_n_tokens,
    )

    # Optional: Save computed tokens for inspection
    if args.save_computed_tokens:
        tokens_file = Path(args.output_path) / "computed_special_tokens.txt"
        tokens_file.parent.mkdir(parents=True, exist_ok=True)
        with open(tokens_file, "w") as f:
            sorted_tokens = sorted(computed_special_tokens)
            for token in sorted_tokens:
                f.write(f"{token}\n")
        info(
            f"Saved {len(computed_special_tokens)} computed special tokens to {tokens_file}"
        )

    try:
        tokenizer = create_or_load_tokenizer(
            tokenizer_output_path=Path(args.output_path),
            texts_for_training=all_texts_for_training,
            vocab_size=args.vocab_size,
            computed_special_tokens=computed_special_tokens,
            max_length=args.max_length,
            force_retrain=args.force_retrain,
        )
        success(f"Tokenizer training completed successfully!")
        success(f"Tokenizer saved to: {args.output_path}")

        # Print some basic stats
        info(f"Tokenizer vocab size: {len(tokenizer)}")
        info(f"Max length: {tokenizer.model_max_length}")

        # Print some example tokenizations
        if all_texts_for_training:
            info("Example tokenizations:")
            for i, text in enumerate(all_texts_for_training[:3]):
                if len(text) > 100:
                    sample_text = text[:100] + "..."
                else:
                    sample_text = text
                tokens = tokenizer.tokenize(sample_text)
                info(f"  Sample {i + 1}: '{sample_text}' -> {len(tokens)} tokens")

    except Exception as e:
        error(f"Failed to train tokenizer: {e}")
        return


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="Train a custom BPE tokenizer for malware detection from CSV data"
    )
    parser.add_argument("--benign", "-b", help="Path to benign CSV file (optional)")
    parser.add_argument(
        "--malicious", "-m", help="Path to malicious CSV file (optional)"
    )
    parser.add_argument(
        "--output-path",
        "-o",
        type=Path,
        default=DEFAULT_TOKENIZER_OUTPUT_PATH,
        help=f"Output path for trained tokenizer (default: {DEFAULT_TOKENIZER_OUTPUT_PATH})",
    )
    parser.add_argument(
        "--vocab-size",
        type=int,
        default=DEFAULT_VOCAB_SIZE,
        help=f"Vocabulary size for tokenizer (default: {DEFAULT_VOCAB_SIZE})",
    )
    parser.add_argument(
        "--max-length",
        type=int,
        default=DEFAULT_MAX_LENGTH,
        help=f"Maximum sequence length (default: {DEFAULT_MAX_LENGTH})",
    )
    parser.add_argument(
        "--token-column",
        type=str,
        default="tokens",
        help="Name of column to use from CSV files (default: tokens)",
    )
    parser.add_argument(
        "--force-retrain",
        action="store_true",
        help="Force retrain tokenizer even if it exists",
    )
    parser.add_argument(
        "--top-n-tokens",
        type=int,
        default=5000,
        help="Number of most frequent tokens to use as special tokens (default: 5000)",
    )
    parser.add_argument(
        "--save-computed-tokens",
        action="store_true",
        help="Save computed special tokens to a text file for inspection",
    )

    args = parser.parse_args()

    # Validate that at least one input file is provided
    if not args.benign and not args.malicious:
        error("At least one of --benign or --malicious must be provided")
        parser.print_help()
        exit(1)

    configure_messaging(quiet=False)
    train_tokenizer(args)
