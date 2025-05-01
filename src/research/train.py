import torch
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


from src.common.files import read_json_from_file

SCRIPT_DIR = pathlib.Path(__file__).resolve().parent

SPECIAL_TOKENS: Set[str] = read_json_from_file(
    SCRIPT_DIR / "syntax_mapping" / "special_tokens.json"
)

DEFAULT_MODEL_NAME = "distilbert-base-uncased"
DEFAULT_TOKENIZER_CLI_PATH = Path("malwi_tokenizer")
DEFAULT_MODEL_OUTPUT_CLI_PATH = Path("malwi_model")
DEFAULT_MAX_LENGTH = 512
DEFAULT_EPOCHS = 3  # Default total epochs if not resuming
DEFAULT_BATCH_SIZE = 16
DEFAULT_VOCAB_SIZE = 30522
DEFAULT_SAVE_STEPS = 0  # Default to epoch-based saving


def load_asts_from_csv(csv_file_path: str, ast_column_name: str = "ast") -> list[str]:
    """Loads AST strings from a specified column in a CSV file."""
    asts = []
    try:
        df = pd.read_csv(csv_file_path)
        if ast_column_name not in df.columns:
            print(
                f"Warning: Column '{ast_column_name}' not found in {csv_file_path}. Returning empty list."
            )
            return []

        for idx, row in df.iterrows():
            ast_data = row[ast_column_name]
            if (
                pd.isna(ast_data)
                or not isinstance(ast_data, str)
                or not ast_data.strip()
            ):
                continue
            asts.append(ast_data.strip())
        print(f"Loaded {len(asts)} AST strings from {csv_file_path}")
    except FileNotFoundError:
        print(f"Error: File not found at {csv_file_path}. Returning empty list.")
        return []
    except Exception as e:
        print(f"Error reading CSV {csv_file_path}: {e}. Returning empty list.")
        return []
    return asts


class ASTDataset(torch.utils.data.Dataset):
    def __init__(self, encodings, labels):
        self.encodings = encodings
        self.labels = labels

    def __getitem__(self, idx):
        item = {key: torch.tensor(val[idx]) for key, val in self.encodings.items()}
        item["labels"] = torch.tensor(self.labels[idx])
        return item

    def __len__(self):
        return len(self.labels)


def compute_metrics(pred):
    labels = pred.label_ids
    preds = pred.predictions.argmax(-1)
    precision, recall, f1, _ = precision_recall_fscore_support(
        labels, preds, average="binary", zero_division=0
    )
    acc = accuracy_score(labels, preds)
    return {"accuracy": acc, "f1": f1, "precision": precision, "recall": recall}


def run_training(args):
    """Handles the model training process."""
    if args.resume_from_checkpoint:
        print(
            f"--- Resuming Model Training from checkpoint: {args.resume_from_checkpoint} ---"
        )
    else:
        print("--- Starting New Model Training ---")

    benign_ast_strings_raw = load_asts_from_csv(args.benign_csv)
    malicious_ast_strings_raw = load_asts_from_csv(args.malicious_csv)

    if not benign_ast_strings_raw and not malicious_ast_strings_raw:
        print("Error: No AST strings loaded. Training cannot proceed.")
        return

    print("\nPreparing AST strings for training...")
    processed_benign_asts = {
        ast_string for ast_string in benign_ast_strings_raw if ast_string
    }
    processed_malicious_candidate_asts = [
        ast_string for ast_string in malicious_ast_strings_raw if ast_string
    ]

    final_malicious_asts_for_training = []
    for m_ast in processed_malicious_candidate_asts:
        if m_ast not in processed_benign_asts:
            final_malicious_asts_for_training.append(m_ast)

    print(f"Processed benign ASTs for training lookup: {len(processed_benign_asts)}")
    print(
        f"Malicious ASTs for training (after filtering): {len(final_malicious_asts_for_training)}"
    )

    all_texts_for_training = (
        list(processed_benign_asts) + final_malicious_asts_for_training
    )
    all_labels_for_training = [0] * len(processed_benign_asts) + [1] * len(
        final_malicious_asts_for_training
    )

    if not all_texts_for_training:
        print("Error: No data available for training after filtering.")
        return

    print(f"Total AST strings for model training: {len(all_texts_for_training)}")

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
        stratify=all_labels_for_training,
    )

    tokenizer_path = Path(args.tokenizer_path)
    huggingface_tokenizer_config_file = tokenizer_path / "tokenizer.json"

    if not args.resume_from_checkpoint and (
        args.force_retrain_tokenizer or not huggingface_tokenizer_config_file.exists()
    ):
        print("\nTraining or re-training custom BPE tokenizer...")
        if args.force_retrain_tokenizer and tokenizer_path.exists():
            print(
                f"Force retraining: Deleting existing tokenizer directory: {tokenizer_path}"
            )
            try:
                shutil.rmtree(tokenizer_path)
            except OSError as e:
                print(
                    f"Error deleting directory {tokenizer_path}: {e}. Please delete manually and retry."
                )
                return

        tokenizer_path.mkdir(parents=True, exist_ok=True)

        vocab_file_path = tokenizer_path / "vocab.json"
        merges_file_path = tokenizer_path / "merges.txt"

        if not distilbert_train_texts:
            print("Error: distilbert_train_texts is empty. Cannot train BPE tokenizer.")
            return

        bpe_trainer_obj = ByteLevelBPETokenizer()

        bpe_special_tokens = [
            "[PAD]",
            "[UNK]",
            "[CLS]",
            "[SEP]",
            "[MASK]",
        ] + SPECIAL_TOKENS

        bpe_trainer_obj.train_from_iterator(
            distilbert_train_texts,
            vocab_size=args.vocab_size,
            min_frequency=2,
            special_tokens=bpe_special_tokens,
        )
        bpe_trainer_obj.save_model(str(tokenizer_path))
        print(f"BPE components (vocab.json, merges.txt) saved to {tokenizer_path}")

        bpe_model = BPE(str(vocab_file_path), str(merges_file_path), unk_token="[UNK]")
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
            model_max_length=args.max_length,
        )
        tokenizer.save_pretrained(str(tokenizer_path))
        print(
            f"PreTrainedTokenizerFast fully saved to {tokenizer_path} (tokenizer.json created)."
        )
    else:
        print(
            f"\nLoading existing PreTrainedTokenizerFast from {tokenizer_path} (found tokenizer.json)."
        )
        tokenizer = PreTrainedTokenizerFast.from_pretrained(
            str(tokenizer_path), max_len=args.max_length
        )

    print("\nPreparing Hugging Face datasets...")
    train_encodings = tokenizer(
        distilbert_train_texts,
        truncation=True,
        padding=True,
        max_length=args.max_length,
    )
    val_encodings = tokenizer(
        distilbert_val_texts, truncation=True, padding=True, max_length=args.max_length
    )

    train_dataset = ASTDataset(train_encodings, distilbert_train_labels)
    val_dataset = ASTDataset(val_encodings, distilbert_val_labels)

    model_output_path = Path(args.model_output_path)

    if not args.resume_from_checkpoint:
        print("\nSetting up NEW DistilBERT model for fine-tuning...")
        config = DistilBertConfig.from_pretrained(args.model_name, num_labels=2)
        config.pad_token_id = tokenizer.pad_token_id
        config.cls_token_id = tokenizer.cls_token_id
        config.sep_token_id = tokenizer.sep_token_id
        model = DistilBertForSequenceClassification.from_pretrained(
            args.model_name, config=config
        )

        if len(tokenizer) != model.config.vocab_size:
            print(
                f"Resizing model token embeddings from {model.config.vocab_size} to {len(tokenizer)}"
            )
            model.resize_token_embeddings(len(tokenizer))
    else:
        print(
            f"\nPreparing to resume training. Model will be loaded from checkpoint: {args.resume_from_checkpoint}"
        )
        try:
            # When resuming, it's often better to load config from where the final model was/will be saved,
            # or from the checkpoint itself if it contains a config.json.
            # Here, we prioritize model_output_path for config consistency.
            config_load_path = (
                model_output_path
                if model_output_path.exists()
                and (model_output_path / "config.json").exists()
                else args.resume_from_checkpoint
            )
            print(f"Loading config for resumed training from: {config_load_path}")
            config = DistilBertConfig.from_pretrained(
                str(config_load_path), num_labels=2
            )
        except OSError:
            print(
                f"Warning: Could not load config from {config_load_path} or {model_output_path}. Using base model config: {args.model_name}."
            )
            config = DistilBertConfig.from_pretrained(args.model_name, num_labels=2)

        config.pad_token_id = tokenizer.pad_token_id
        config.cls_token_id = tokenizer.cls_token_id
        config.sep_token_id = tokenizer.sep_token_id
        # Model instance for Trainer; actual weights loaded from the checkpoint specified in resume_from_checkpoint by the Trainer.
        # If not resuming from a specific checkpoint dir, or if it's invalid, Trainer might load from model_name.
        # We initialize with model_output_path to have a consistent structure if resuming generally.
        model_load_path_for_resume_init = (
            model_output_path
            if model_output_path.exists()
            and (model_output_path / "config.json").exists()
            else args.model_name
        )
        print(
            f"Initializing model structure for resumed training from: {model_load_path_for_resume_init}"
        )
        model = DistilBertForSequenceClassification.from_pretrained(
            str(model_load_path_for_resume_init), config=config
        )

    current_save_strategy = "epoch"
    current_save_steps = None  # Correctly initialize
    save_total_limit_val = None  # Correctly initialize

    if args.save_steps > 0:
        current_save_strategy = "steps"
        current_save_steps = args.save_steps
        save_total_limit_val = 5  # Default limit when saving by steps
        print(
            f"Configuring to save checkpoints every {current_save_steps} steps. Total checkpoints limit: {save_total_limit_val}"
        )
    else:
        print("Configuring to save checkpoints at the end of each epoch.")

    training_arguments = TrainingArguments(
        output_dir=str(model_output_path / "results"),  # Checkpoints will be saved here
        num_train_epochs=args.epochs,
        per_device_train_batch_size=args.batch_size,
        per_device_eval_batch_size=args.batch_size,
        warmup_steps=500,
        weight_decay=0.01,
        logging_dir=str(model_output_path / "logs"),
        logging_steps=10,
        eval_strategy="epoch",
        save_strategy=current_save_strategy,
        save_steps=current_save_steps,  # Pass the actual value
        load_best_model_at_end=True,
        metric_for_best_model="f1",
        save_total_limit=save_total_limit_val,  # Pass the actual value
        report_to="none",
    )

    trainer = Trainer(
        model=model,
        args=training_arguments,
        train_dataset=train_dataset,
        eval_dataset=val_dataset,
        compute_metrics=compute_metrics,
        tokenizer=tokenizer,
    )

    print("\nStarting/Resuming model training...")
    train_kwargs = {}
    if args.resume_from_checkpoint:
        checkpoint_path = Path(args.resume_from_checkpoint)
        if checkpoint_path.is_dir() and (
            (
                checkpoint_path / DistilBertForSequenceClassification.WEIGHTS_NAME
            ).exists()
            or (
                checkpoint_path / DistilBertForSequenceClassification.SAFE_WEIGHTS_NAME
            ).exists()
        ):
            train_kwargs["resume_from_checkpoint"] = str(checkpoint_path)
            print(
                f"Attempting to resume training from valid checkpoint: {checkpoint_path}"
            )
        else:
            print(
                f"Warning: Checkpoint path {args.resume_from_checkpoint} does not seem to be a valid checkpoint directory (missing model weights). "
                f"Training will proceed based on the model initialized (either new or from --model_output_path if its contents were used)."
            )
            # Ensure resume_from_checkpoint is not passed if invalid to avoid Trainer errors
            args.resume_from_checkpoint = (
                None  # Clear it so Trainer doesn't try to load from an invalid path
            )

    if train_dataset and len(train_dataset) > 0:
        # If args.resume_from_checkpoint was valid, it's in train_kwargs. Otherwise, it's a normal train call.
        trainer.train(**train_kwargs)
        print("\nTraining complete.")

        print(
            "\nEvaluating the best model (that will be saved) on the validation set..."
        )
        final_eval_results = trainer.evaluate()
        print(
            "Final evaluation results of the best model (before saving):",
            final_eval_results,
        )

        # Save the best model (and tokenizer) to the root of model_output_path
        trainer.save_model(str(model_output_path))
        print(f"Best fine-tuned model and tokenizer saved to {model_output_path}")

    else:
        print("Training skipped as the training dataset is empty.")
    print("--- Training Finished ---")


def run_prediction(args):
    """Handles prediction using a trained model."""
    print("--- Starting Prediction ---")
    model_path = Path(args.model_path)

    if args.tokenizer_predict_path:
        tokenizer_load_path = Path(args.tokenizer_predict_path)
        print(f"Using specified tokenizer path: {tokenizer_load_path}")
    else:
        tokenizer_load_path = model_path
        print(f"Using model path for tokenizer: {tokenizer_load_path}")

    # Validate model path for essential model files
    if not model_path.exists() or not (model_path / "config.json").exists():
        print(
            f"Error: Model directory or model configuration (config.json) "
            f"not found at model_path: {model_path}."
        )
        return
    # training_args.bin is not strictly needed by from_pretrained for the model, but good for context
    if not (model_path / "training_args.bin").exists():
        print(
            f"Warning: training_args.bin not found at model_path: {model_path}. Predictions will proceed without it."
        )

    # Validate tokenizer path for tokenizer.json
    if (
        not tokenizer_load_path.exists()
        or not (tokenizer_load_path / "tokenizer.json").exists()
    ):
        print(
            f"Error: Tokenizer file (tokenizer.json) not found at tokenizer path: {tokenizer_load_path}."
        )
        return

    print(f"Loading model from: {model_path}")
    print(f"Loading tokenizer from: {tokenizer_load_path}")

    try:
        model = DistilBertForSequenceClassification.from_pretrained(str(model_path))
        tokenizer = PreTrainedTokenizerFast.from_pretrained(
            str(tokenizer_load_path), max_len=args.max_length
        )
    except Exception as e:
        print(f"Error loading model or tokenizer: {e}")
        return

    device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
    model.to(device)
    model.eval()

    if args.ast_string:
        print(f'\nPredicting for AST string: "{args.ast_string}"')
        inputs = tokenizer(
            args.ast_string,
            return_tensors="pt",
            truncation=True,
            padding=True,
            max_length=args.max_length,
        )

        # Prepare inputs for the model, excluding token_type_ids
        model_inputs = {
            "input_ids": inputs.get("input_ids").to(device),
            "attention_mask": inputs.get("attention_mask").to(device),
        }
        # Remove None items in case a key was missing, though tokenizer should always provide these for 'pt'
        model_inputs = {k: v for k, v in model_inputs.items() if v is not None}

        with torch.no_grad():
            outputs = model(**model_inputs)  # Pass only expected inputs
            logits = outputs.logits
            probabilities = torch.softmax(logits, dim=-1).cpu().numpy()[0]
            prediction = np.argmax(probabilities)

        label_map = {0: "Benign", 1: "Malicious"}
        print(f"Prediction: {label_map[prediction]}")
        print(
            f"Probabilities: Benign={probabilities[0]:.4f}, Malicious={probabilities[1]:.4f}"
        )

    elif args.input_csv:
        print(f"\nPredicting for AST strings in CSV: {args.input_csv}")
        asts_to_predict = load_asts_from_csv(args.input_csv)
        if not asts_to_predict:
            print("No AST strings loaded from the input CSV.")
            return

        results = []
        for ast_text in asts_to_predict:
            inputs = tokenizer(
                ast_text,
                return_tensors="pt",
                truncation=True,
                padding=True,
                max_length=args.max_length,
            )

            # Prepare inputs for the model, excluding token_type_ids
            model_inputs = {
                "input_ids": inputs.get("input_ids").to(device),
                "attention_mask": inputs.get("attention_mask").to(device),
            }
            model_inputs = {k: v for k, v in model_inputs.items() if v is not None}

            with torch.no_grad():
                outputs = model(**model_inputs)  # Pass only expected inputs
                logits = outputs.logits
                probabilities = torch.softmax(logits, dim=-1).cpu().numpy()[0]
                prediction = np.argmax(probabilities)

            results.append(
                {
                    "ast_string": ast_text,
                    "predicted_label": prediction,
                    "probability_benign": probabilities[0],
                    "probability_malicious": probabilities[1],
                }
            )

        results_df = pd.DataFrame(results)

        if args.output_csv:
            output_csv_path = Path(args.output_csv)
            output_csv_path.parent.mkdir(parents=True, exist_ok=True)
            results_df.to_csv(output_csv_path, index=False)
            print(f"Predictions saved to {output_csv_path}")
        else:
            print("\nPrediction Results:")
            print(results_df.to_string())
    else:
        print("No input provided for prediction. Use --ast_string or --input_csv.")
    print("--- Prediction Finished ---")


def main():
    parser = argparse.ArgumentParser(
        description="CLI for DistilBERT AST Classifier Training and Prediction."
    )
    parser.add_argument(
        "--model_name",
        type=str,
        default=DEFAULT_MODEL_NAME,
        help=f"Base DistilBERT model name (default: {DEFAULT_MODEL_NAME}). Used for initializing a new model in training.",
    )
    parser.add_argument(
        "--max_length",
        type=int,
        default=DEFAULT_MAX_LENGTH,
        help=f"Max sequence length for tokenizer (default: {DEFAULT_MAX_LENGTH}).",
    )
    parser.add_argument(
        "--vocab_size",
        type=int,
        default=DEFAULT_VOCAB_SIZE,
        help=f"BPE tokenizer vocabulary size (default: {DEFAULT_VOCAB_SIZE}). Used during tokenizer training.",
    )

    subparsers = parser.add_subparsers(
        dest="command",
        required=True,
        help="Sub-command to execute: 'train' or 'predict'",
    )

    train_parser = subparsers.add_parser(
        "train", help="Train a new DistilBERT AST classifier."
    )
    train_parser.add_argument(
        "--benign_csv",
        type=str,
        required=True,
        help="Path to CSV file containing benign AST strings.",
    )
    train_parser.add_argument(
        "--malicious_csv",
        type=str,
        required=True,
        help="Path to CSV file containing malicious AST strings.",
    )
    train_parser.add_argument(
        "--tokenizer_path",
        type=str,
        default=str(DEFAULT_TOKENIZER_CLI_PATH),
        help=f"Path to save/load tokenizer during training (default: {DEFAULT_TOKENIZER_CLI_PATH}).",
    )
    train_parser.add_argument(
        "--model_output_path",
        type=str,
        default=str(DEFAULT_MODEL_OUTPUT_CLI_PATH),
        help=f"Path to save fine-tuned model and checkpoints (default: {DEFAULT_MODEL_OUTPUT_CLI_PATH}).",
    )
    train_parser.add_argument(
        "--epochs",
        type=int,
        default=DEFAULT_EPOCHS,
        help=f"Total training epochs (default: {DEFAULT_EPOCHS}).",
    )
    train_parser.add_argument(
        "--batch_size",
        type=int,
        default=DEFAULT_BATCH_SIZE,
        help=f"Batch size for training and evaluation (default: {DEFAULT_BATCH_SIZE}).",
    )
    train_parser.add_argument(
        "--force_retrain_tokenizer",
        action="store_true",
        help="Force retraining the tokenizer even if an existing one is found at --tokenizer_path.",
    )
    train_parser.add_argument(
        "--resume_from_checkpoint",
        type=str,
        default=None,
        help="Path to a specific checkpoint directory (e.g., output_path/results/checkpoint-xxxx) to resume training from.",
    )
    train_parser.add_argument(
        "--save_steps",
        type=int,
        default=DEFAULT_SAVE_STEPS,
        help="Save a checkpoint every X steps. If 0, saves at the end of each epoch. (default: 0)",
    )
    train_parser.set_defaults(func=run_training)

    predict_parser = subparsers.add_parser(
        "predict", help="Predict with a trained classifier."
    )
    predict_parser.add_argument(
        "--model_path",
        type=str,
        required=True,
        help="Path to the trained model directory (containing config.json, model weights).",
    )
    predict_parser.add_argument(
        "--tokenizer_predict_path",
        type=str,
        default=None,
        help="Optional: Path to the tokenizer directory (containing tokenizer.json). "
        "If not provided, tokenizer is expected to be in --model_path.",
    )
    predict_parser.add_argument(
        "--ast_string", type=str, help="A single AST string to classify."
    )
    predict_parser.add_argument(
        "--input_csv",
        type=str,
        help="Path to a CSV file with an 'asts' column for batch prediction.",
    )
    predict_parser.add_argument(
        "--output_csv",
        type=str,
        help="Path to save CSV prediction results when using --input_csv.",
    )
    predict_parser.set_defaults(func=run_prediction)

    args = parser.parse_args()

    if hasattr(args, "func"):
        args.func(args)
    else:
        parser.print_help()


if __name__ == "__main__":
    main()
