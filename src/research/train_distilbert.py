import os
import dis
import shutil
import pathlib
import argparse
import numpy as np
import pandas as pd


from typing import Set
from pathlib import Path
from tokenizers import ByteLevelBPETokenizer, Tokenizer
from tokenizers.models import BPE
from tokenizers.normalizers import NFKC, Sequence, Lowercase
from tokenizers.pre_tokenizers import ByteLevel
from sklearn.model_selection import train_test_split
from sklearn.metrics import accuracy_score, precision_recall_fscore_support

from transformers import (
    DistilBertConfig,
    DistilBertForSequenceClassification,
    PreTrainedTokenizerFast,
    Trainer,
    TrainingArguments,
)

from datasets import Dataset, DatasetDict
from datasets.utils.logging import disable_progress_bar

from common.files import read_json_from_file
from common.messaging import (
    configure_messaging,
    info,
    success,
    warning,
    error,
    progress,
)

SCRIPT_DIR = pathlib.Path(__file__).resolve().parent

SPECIAL_TOKENS: Set[str] = read_json_from_file(
    SCRIPT_DIR / "syntax_mapping" / "special_tokens.json"
)

DEFAULT_MODEL_NAME = "distilbert-base-uncased"
DEFAULT_TOKENIZER_CLI_PATH = Path("malwi_models")
DEFAULT_MODEL_OUTPUT_CLI_PATH = Path("malwi_models")
DEFAULT_MAX_LENGTH = 512
DEFAULT_WINDOW_STRIDE = 128
DEFAULT_EPOCHS = 3
DEFAULT_BATCH_SIZE = 16
DEFAULT_VOCAB_SIZE = 30522
DEFAULT_SAVE_STEPS = 0
DEFAULT_BENIGN_TO_MALICIOUS_RATIO = 60.0
DEFAULT_NUM_PROC = (
    os.cpu_count() if os.cpu_count() is not None and os.cpu_count() > 1 else 2
)


def load_asts_from_csv(
    csv_file_path: str, token_column_name: str = "tokens"
) -> list[str]:
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


def compute_metrics(pred):
    labels = pred.label_ids
    preds = pred.predictions.argmax(-1)
    precision, recall, f1, _ = precision_recall_fscore_support(
        labels, preds, average="binary", zero_division=0
    )
    acc = accuracy_score(labels, preds)
    return {"accuracy": acc, "f1": f1, "precision": precision, "recall": recall}


def create_or_load_tokenizer(
    tokenizer_output_path: Path,
    texts_for_training: list[str],
    vocab_size: int,
    global_special_tokens: Set[str],
    max_length: int,
    force_retrain: bool,
):
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

        bytecode_op_names = [key.lower() for key in dis.opmap.keys()]

        bpe_default_special_tokens = [
            "[PAD]",
            "[UNK]",
            "[CLS]",
            "[SEP]",
            "[MASK]",
        ]

        bpe_default_special_tokens.extend(bytecode_op_names)

        combined_special_tokens = list(
            set(bpe_default_special_tokens + list(global_special_tokens))
        )

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


def save_training_metrics(metrics_dict: dict, output_path: Path):
    """Save training metrics to a text file."""
    metrics_file = output_path / "training_metrics.txt"

    try:
        with open(metrics_file, "w") as f:
            f.write("Training Metrics Summary\n")
            f.write("=" * 40 + "\n\n")

            for key, value in metrics_dict.items():
                if isinstance(value, (int, float)):
                    f.write(f"{key}: {value:.4f}\n")
                else:
                    f.write(f"{key}: {value}\n")

            f.write("\n" + "=" * 40 + "\n")
            f.write("Training completed successfully\n")

        success(f"Training metrics saved to: {metrics_file}")

    except Exception as e:
        warning(f"Could not save training metrics: {e}")


def save_model_with_prefix(trainer, tokenizer, output_path: Path):
    """Save model and tokenizer with prefixes in the same directory."""
    info(f"Saving model and tokenizer with prefixes to {output_path}...")

    # Create output directory if it doesn't exist
    output_path.mkdir(parents=True, exist_ok=True)

    # Save model files with distilbert prefix
    trainer.save_model(str(output_path))

    # Rename model files to add distilbert prefix
    model_file_mappings = {
        "config.json": "config.json",
        "pytorch_model.bin": "pytorch_model.bin",
        "model.safetensors": "model.safetensors",
        "training_args.bin": "training_args.bin",
    }

    for original_name, new_name in model_file_mappings.items():
        original_path = output_path / original_name
        new_path = output_path / new_name
        if original_path.exists():
            original_path.rename(new_path)
            success(f"Renamed {original_name} to {new_name}")

    # Save tokenizer files with tokenizer prefix
    tokenizer.save_pretrained(str(output_path))

    # Rename tokenizer files to add tokenizer prefix
    tokenizer_file_mappings = {
        "tokenizer.json": "tokenizer.json",
        "tokenizer_config.json": "tokenizer_config.json",
        "vocab.json": "vocab.json",
        "merges.txt": "merges.txt",
        "special_tokens_map.json": "special_tokens_map.json",
    }

    for original_name, new_name in tokenizer_file_mappings.items():
        original_path = output_path / original_name
        new_path = output_path / new_name
        if original_path.exists():
            original_path.rename(new_path)
            success(f"Renamed {original_name} to {new_name}")


def cleanup_model_directory(model_output_path: Path):
    """Clean up the model directory, keeping only essential prefixed model files and tokenizer."""
    info(f"Cleaning up model directory: {model_output_path}")

    # Essential files to keep (with prefixes)
    essential_files = {
        "config.json",
        "pytorch_model.bin",
        "model.safetensors",
        "training_args.bin",
        "tokenizer.json",
        "tokenizer_config.json",
        "vocab.json",
        "merges.txt",
        "special_tokens_map.json",
        "training_metrics.txt",
    }

    if not model_output_path.exists():
        warning(f"Directory {model_output_path} does not exist, skipping cleanup.")
        return

    try:
        for item in model_output_path.iterdir():
            if item.is_file():
                # Check if file should be kept
                if item.name not in essential_files:
                    info(f"Removing file: {item}")
                    item.unlink()
                else:
                    info(f"Keeping essential file: {item}")

            elif item.is_dir():
                # Remove all directories (results, logs, checkpoints, etc.)
                info(f"Removing directory: {item}")
                shutil.rmtree(item)

    except Exception as e:
        warning(f"Error during cleanup: {e}")


def run_training(args):
    if args.disable_hf_datasets_progress_bar:
        disable_progress_bar()

    progress("Starting DistilBERT model training...")

    benign_asts = load_asts_from_csv(args.benign, args.token_column)
    malicious_asts = load_asts_from_csv(args.malicious, args.token_column)

    info(f"Loaded {len(benign_asts)} benign samples")
    info(f"Loaded {len(malicious_asts)} malicious samples")

    if not malicious_asts:
        error("No malicious samples loaded. Cannot proceed with training.")
        return

    if (
        benign_asts
        and args.benign_to_malicious_ratio > 0
        and len(benign_asts) > len(malicious_asts) * args.benign_to_malicious_ratio
    ):
        target_benign_count = int(len(malicious_asts) * args.benign_to_malicious_ratio)
        if target_benign_count < len(
            benign_asts
        ):  # Ensure we are actually downsampling
            info(
                f"Downsampling benign samples from {len(benign_asts)} to {target_benign_count}"
            )
            rng = np.random.RandomState(42)
            benign_indices = rng.choice(
                len(benign_asts), size=target_benign_count, replace=False
            )
            benign_asts = [benign_asts[i] for i in benign_indices]
    elif not benign_asts:
        warning("No benign samples loaded.")

    info(f"Using {len(benign_asts)} benign samples for training")
    info(f"Using {len(malicious_asts)} malicious samples for training")

    all_texts_for_training = benign_asts + malicious_asts
    all_labels_for_training = [0] * len(benign_asts) + [1] * len(malicious_asts)

    if not all_texts_for_training:
        error("No data available for training after filtering or downsampling.")
        return

    info(f"Total original samples: {len(all_texts_for_training)}")

    (
        distilbert_train_texts,
        distilbert_val_texts,
        distilbert_train_labels,
        distilbert_val_labels,
    ) = train_test_split(
        all_texts_for_training,
        all_labels_for_training,
        test_size=0.2,
        random_state=42,
        stratify=all_labels_for_training if all_labels_for_training else None,
    )

    if not distilbert_train_texts:
        error("No training data available after train/test split. Cannot proceed.")
        return

    try:
        tokenizer = create_or_load_tokenizer(
            tokenizer_output_path=Path(args.tokenizer_path),
            texts_for_training=distilbert_train_texts,
            vocab_size=args.vocab_size,
            global_special_tokens=SPECIAL_TOKENS,
            max_length=args.max_length,
            force_retrain=args.force_retrain_tokenizer,
        )
    except Exception as e:
        error(f"Failed to create or load tokenizer: {e}")
        return

    info("Converting data to Hugging Face Dataset format...")
    train_data_dict = {"text": distilbert_train_texts, "label": distilbert_train_labels}
    val_data_dict = {"text": distilbert_val_texts, "label": distilbert_val_labels}

    train_hf_dataset = Dataset.from_dict(train_data_dict)
    val_hf_dataset = Dataset.from_dict(val_data_dict)

    raw_datasets = DatasetDict(
        {"train": train_hf_dataset, "validation": val_hf_dataset}
    )

    info("Tokenizing datasets with windowing using .map()...")

    # --- Updated Tokenization Function with Windowing ---
    def tokenize_and_split(examples):
        """Tokenize texts. For long texts, create multiple overlapping windows (features)."""
        # Tokenize the batch of texts. `return_overflowing_tokens` will create multiple
        # features from a single long text.
        tokenized_outputs = tokenizer(
            examples["text"],
            truncation=True,
            padding="max_length",
            max_length=args.max_length,
            stride=args.window_stride,  # The overlap between windows
            return_overflowing_tokens=True,
        )

        # `overflow_to_sample_mapping` tells us which original example each new feature came from.
        # We use this to assign the correct label to each new feature (window).
        sample_mapping = tokenized_outputs.pop("overflow_to_sample_mapping")

        original_labels = examples["label"]
        new_labels = [original_labels[sample_idx] for sample_idx in sample_mapping]
        tokenized_outputs["label"] = new_labels

        return tokenized_outputs

    num_proc = args.num_proc if args.num_proc > 0 else None

    # The new columns will be 'input_ids', 'attention_mask', and the new 'label' list.
    # We must remove the original columns ('text', 'label') that are now replaced.
    tokenized_datasets = raw_datasets.map(
        tokenize_and_split,
        batched=True,
        num_proc=num_proc,
        remove_columns=raw_datasets["train"].column_names,
    )

    info(f"Original training samples: {len(raw_datasets['train'])}")
    info(f"Windowed training features: {len(tokenized_datasets['train'])}")
    info(f"Original validation samples: {len(raw_datasets['validation'])}")
    info(f"Windowed validation features: {len(tokenized_datasets['validation'])}")
    success("Dataset tokenization and windowing completed")

    train_dataset_for_trainer = tokenized_datasets["train"]
    val_dataset_for_trainer = tokenized_datasets["validation"]

    model_output_path = Path(args.model_output_path)
    results_path = model_output_path / "results"
    logs_path = model_output_path / "logs"

    info(f"Setting up DistilBERT model for fine-tuning from {args.model_name}...")
    config = DistilBertConfig.from_pretrained(args.model_name, num_labels=2)
    config.pad_token_id = tokenizer.pad_token_id
    config.cls_token_id = tokenizer.cls_token_id
    config.sep_token_id = tokenizer.sep_token_id

    model = DistilBertForSequenceClassification.from_pretrained(
        args.model_name, config=config
    )

    if len(tokenizer) != model.config.vocab_size:
        info(
            f"Resizing model token embeddings from {model.config.vocab_size} to {len(tokenizer)}"
        )
        model.resize_token_embeddings(len(tokenizer))

    training_arguments = TrainingArguments(
        output_dir=str(results_path),
        num_train_epochs=args.epochs,
        per_device_train_batch_size=args.batch_size,
        per_device_eval_batch_size=args.batch_size,
        warmup_steps=500,
        weight_decay=0.01,
        logging_dir=str(logs_path),
        logging_steps=10,
        eval_strategy="epoch",
        save_strategy="epoch" if args.save_steps == 0 else "steps",
        save_steps=args.save_steps if args.save_steps > 0 else None,
        load_best_model_at_end=True,
        metric_for_best_model="f1",
        save_total_limit=5 if args.save_steps > 0 else None,
        report_to="none",
    )

    trainer = Trainer(
        model=model,
        args=training_arguments,
        train_dataset=train_dataset_for_trainer,
        eval_dataset=val_dataset_for_trainer,
        compute_metrics=compute_metrics,
        tokenizer=tokenizer,
    )

    info("Starting model training...")
    train_result = trainer.train()

    info("Evaluating final model...")
    eval_result = trainer.evaluate()

    save_model_with_prefix(trainer, tokenizer, model_output_path)

    training_metrics = {
        "training_loss": train_result.training_loss,
        "epochs_completed": args.epochs,
        "original_train_samples": len(distilbert_train_texts),
        "windowed_train_features": len(train_dataset_for_trainer),
        "original_validation_samples": len(distilbert_val_texts),
        "windowed_validation_features": len(val_dataset_for_trainer),
        "benign_samples_used": len(benign_asts),
        "malicious_samples_used": len(malicious_asts),
        "benign_to_malicious_ratio": args.benign_to_malicious_ratio,
        "vocab_size": args.vocab_size,
        "max_length": args.max_length,
        "window_stride": args.window_stride,
        "batch_size": args.batch_size,
        **eval_result,
    }

    save_training_metrics(training_metrics, model_output_path)
    cleanup_model_directory(model_output_path)

    success("DistilBERT model training completed successfully")
    success(f"Final model saved to: {model_output_path}")
    success(f"Training metrics saved to: {model_output_path}/training_metrics.txt")


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--benign", "-b", required=True, help="Path to benign CSV")
    parser.add_argument(
        "--malicious", "-m", required=True, help="Path to malicious CSV"
    )
    parser.add_argument("--model-name", default=DEFAULT_MODEL_NAME)
    parser.add_argument(
        "--tokenizer-path", type=Path, default=DEFAULT_TOKENIZER_CLI_PATH
    )
    parser.add_argument(
        "--model-output-path", type=Path, default=DEFAULT_MODEL_OUTPUT_CLI_PATH
    )
    parser.add_argument("--max-length", type=int, default=DEFAULT_MAX_LENGTH)
    # --- New CLI Argument for Windowing ---
    parser.add_argument(
        "--window-stride",
        type=int,
        default=DEFAULT_WINDOW_STRIDE,
        help="Overlap stride for windowing long inputs during training.",
    )
    parser.add_argument("--epochs", type=int, default=DEFAULT_EPOCHS)
    parser.add_argument("--batch-size", type=int, default=DEFAULT_BATCH_SIZE)
    parser.add_argument("--vocab-size", type=int, default=DEFAULT_VOCAB_SIZE)
    parser.add_argument("--save-steps", type=int, default=DEFAULT_SAVE_STEPS)
    parser.add_argument("--num-proc", type=int, default=DEFAULT_NUM_PROC)
    parser.add_argument("--force-retrain-tokenizer", action="store_true")
    parser.add_argument("--disable-hf-datasets-progress-bar", action="store_true")
    parser.add_argument(
        "--token-column",
        type=str,
        default="tokens",
        help="Name of column to use from CSV",
    )
    parser.add_argument(
        "--benign-to-malicious-ratio",
        type=float,
        default=DEFAULT_BENIGN_TO_MALICIOUS_RATIO,
        help="Ratio of benign to malicious samples to use for training (e.g., 1.0 for 1:1). Set to 0 or negative to disable downsampling.",
    )

    args = parser.parse_args()
    configure_messaging(quiet=False)
    run_training(args)
