import torch
import shutil
import pathlib
import argparse
import numpy as np
import pandas as pd
import os

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

SCRIPT_DIR = pathlib.Path(__file__).resolve().parent

SPECIAL_TOKENS: Set[str] = read_json_from_file(
    SCRIPT_DIR / "syntax_mapping" / "special_tokens.json"
)

DEFAULT_MODEL_NAME = "distilbert-base-uncased"
DEFAULT_TOKENIZER_CLI_PATH = Path("malwi_tokenizer")
DEFAULT_MODEL_OUTPUT_CLI_PATH = Path("malwi_model")
DEFAULT_MAX_LENGTH = 512
DEFAULT_EPOCHS = 3
DEFAULT_BATCH_SIZE = 16
DEFAULT_VOCAB_SIZE = 30522
DEFAULT_SAVE_STEPS = 0
DEFAULT_NUM_PROC = (
    os.cpu_count() if os.cpu_count() is not None and os.cpu_count() > 1 else 2
)


def load_asts_from_csv(csv_file_path: str, ast_column_name: str = "ast") -> list[str]:
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


def compute_metrics(pred):
    labels = pred.label_ids
    preds = pred.predictions.argmax(-1)
    precision, recall, f1, _ = precision_recall_fscore_support(
        labels, preds, average="binary", zero_division=0
    )
    acc = accuracy_score(labels, preds)
    return {"accuracy": acc, "f1": f1, "precision": precision, "recall": recall}


def run_training(args):
    if args.disable_hf_datasets_progress_bar:
        disable_progress_bar()

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
        ] + list(SPECIAL_TOKENS)  # Ensure SPECIAL_TOKENS is a list for concatenation

        bpe_trainer_obj.train_from_iterator(
            distilbert_train_texts,
            vocab_size=args.vocab_size,
            min_frequency=2,
            special_tokens=bpe_special_tokens,
        )
        bpe_trainer_obj.save_model(str(tokenizer_path))
        print(f"BPE components (vocab.json, merges.txt) saved to {tokenizer_path}")

        bpe_model = BPE.from_files(
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
            str(tokenizer_path), model_max_length=args.max_length
        )

    print("\nConverting data to Hugging Face Dataset format...")
    train_data_dict = {"text": distilbert_train_texts, "label": distilbert_train_labels}
    val_data_dict = {"text": distilbert_val_texts, "label": distilbert_val_labels}

    train_hf_dataset = Dataset.from_dict(train_data_dict)
    val_hf_dataset = Dataset.from_dict(val_data_dict)

    raw_datasets = DatasetDict(
        {"train": train_hf_dataset, "validation": val_hf_dataset}
    )

    print("Tokenizing datasets using .map()...")

    def tokenize_function(examples):
        return tokenizer(
            examples["text"],
            truncation=True,
            padding="max_length",
            max_length=args.max_length,
        )

    num_proc = (
        args.num_proc if args.num_proc > 0 else None
    )  # Use None for datasets to auto-detect or use single process

    tokenized_datasets = raw_datasets.map(
        tokenize_function, batched=True, num_proc=num_proc, remove_columns=["text"]
    )
    print("Tokenization complete.")

    train_dataset_for_trainer = tokenized_datasets["train"]
    val_dataset_for_trainer = tokenized_datasets["validation"]

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
    current_save_steps = None
    save_total_limit_val = None

    if args.save_steps > 0:
        current_save_strategy = "steps"
        current_save_steps = args.save_steps
        save_total_limit_val = 5
        print(
            f"Configuring to save checkpoints every {current_save_steps} steps. Total checkpoints limit: {save_total_limit_val}"
        )
    else:
        print("Configuring to save checkpoints at the end of each epoch.")

    training_arguments = TrainingArguments(
        output_dir=str(model_output_path / "results"),
        num_train_epochs=args.epochs,
        per_device_train_batch_size=args.batch_size,
        per_device_eval_batch_size=args.batch_size,
        warmup_steps=500,
        weight_decay=0.01,
        logging_dir=str(model_output_path / "logs"),
        logging_steps=10,
        eval_strategy="epoch",
        save_strategy=current_save_strategy,
        save_steps=current_save_steps,
        load_best_model_at_end=True,
        metric_for_best_model="f1",
        save_total_limit=save_total_limit_val,
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
                f"Training will proceed based on the model initialized."
            )
            args.resume_from_checkpoint = None

    if train_dataset_for_trainer and len(train_dataset_for_trainer) > 0:
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

        trainer.save_model(str(model_output_path))
        print(f"Best fine-tuned model and tokenizer saved to {model_output_path}")

    else:
        print("Training skipped as the training dataset is empty.")
    print("--- Training Finished ---")


def run_prediction(args):
    print("--- Starting Prediction ---")
    model_path = Path(args.model_path)

    if args.tokenizer_predict_path:
        tokenizer_load_path = Path(args.tokenizer_predict_path)
        print(f"Using specified tokenizer path: {tokenizer_load_path}")
    else:
        tokenizer_load_path = model_path
        print(f"Using model path for tokenizer: {tokenizer_load_path}")

    if not model_path.exists() or not (model_path / "config.json").exists():
        print(
            f"Error: Model directory or model configuration (config.json) "
            f"not found at model_path: {model_path}."
        )
        return
    if not (
        model_path / "training_args.bin"
    ).exists():  # In new HF versions this might be different
        has_pytorch_model = (model_path / "pytorch_model.bin").exists() or (
            model_path / "model.safetensors"
        ).exists()
        if not has_pytorch_model:
            print(
                f"Warning: Neither pytorch_model.bin, model.safetensors nor training_args.bin found at model_path: {model_path}. "
                "Predictions will proceed if other model files are present but this is unusual."
            )
        else:
            print(
                f"Note: training_args.bin not found at model_path: {model_path}, but model weights exist. Predictions will proceed."
            )

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
            str(tokenizer_load_path), model_max_length=args.max_length
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

        model_inputs = {
            "input_ids": inputs.get("input_ids").to(device),
            "attention_mask": inputs.get("attention_mask").to(device),
        }
        model_inputs = {k: v for k, v in model_inputs.items() if v is not None}

        with torch.no_grad():
            outputs = model(**model_inputs)
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

            model_inputs = {
                "input_ids": inputs.get("input_ids").to(device),
                "attention_mask": inputs.get("attention_mask").to(device),
            }
            model_inputs = {k: v for k, v in model_inputs.items() if v is not None}

            with torch.no_grad():
                outputs = model(**model_inputs)
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
        help=f"Base DistilBERT model name (default: {DEFAULT_MODEL_NAME}).",
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
        help=f"BPE tokenizer vocabulary size (default: {DEFAULT_VOCAB_SIZE}).",
    )
    parser.add_argument(
        "--num_proc",
        type=int,
        default=DEFAULT_NUM_PROC,
        help=f"Number of processes for .map() in datasets (default: {DEFAULT_NUM_PROC}, 0 to disable multiprocessing).",
    )
    parser.add_argument(
        "--disable_hf_datasets_progress_bar",
        action="store_true",
        help="Disable progress bars from the Hugging Face datasets library.",
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
        help=f"Path to save/load tokenizer (default: {DEFAULT_TOKENIZER_CLI_PATH}).",
    )
    train_parser.add_argument(
        "--model_output_path",
        type=str,
        default=str(DEFAULT_MODEL_OUTPUT_CLI_PATH),
        help=f"Path to save fine-tuned model (default: {DEFAULT_MODEL_OUTPUT_CLI_PATH}).",
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
        help="Force retraining tokenizer even if existing one is found.",
    )
    train_parser.add_argument(
        "--resume_from_checkpoint",
        type=str,
        default=None,
        help="Path to checkpoint directory to resume training from.",
    )
    train_parser.add_argument(
        "--save_steps",
        type=int,
        default=DEFAULT_SAVE_STEPS,
        help="Save checkpoint every X steps. If 0, saves per epoch. (default: 0)",
    )
    train_parser.set_defaults(func=run_training)

    predict_parser = subparsers.add_parser(
        "predict", help="Predict with a trained classifier."
    )
    predict_parser.add_argument(
        "--model_path",
        type=str,
        required=True,
        help="Path to trained model directory.",
    )
    predict_parser.add_argument(
        "--tokenizer_predict_path",
        type=str,
        default=None,
        help="Optional path to tokenizer. If None, uses --model_path.",
    )
    predict_parser.add_argument(
        "--ast_string", type=str, help="A single AST string to classify."
    )
    predict_parser.add_argument(
        "--input_csv",
        type=str,
        help="Path to CSV file with 'asts' column for batch prediction.",
    )
    predict_parser.add_argument(
        "--output_csv",
        type=str,
        help="Path to save CSV prediction results.",
    )
    predict_parser.set_defaults(func=run_prediction)

    args = parser.parse_args()

    if hasattr(args, "func"):
        args.func(args)
    else:
        parser.print_help()


if __name__ == "__main__":
    main()
