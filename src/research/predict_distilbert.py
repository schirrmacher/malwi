import logging
from typing import Dict, Any, Optional, List
import threading

import torch
import torch.nn.functional as F
from transformers import AutoTokenizer, DistilBertForSequenceClassification

# Changed to use the same repository for both tokenizer and model
HF_REPO_NAME = "schirrmacher/malwi"
HF_TOKENIZER_NAME = HF_REPO_NAME
HF_MODEL_NAME = HF_REPO_NAME

HF_TOKENIZER_INSTANCE = None
HF_MODEL_INSTANCE = None
HF_DEVICE_INSTANCE = None
HF_DEVICE_IDS = None  # List of GPU device IDs
USE_MULTI_GPU = False

# Thread-local storage for tokenizers to avoid "Already borrowed" errors
_thread_local = threading.local()

# Higher == Faster
WINDOW_STRIDE = 384


def get_thread_tokenizer():
    """Get a thread-local tokenizer instance to avoid 'Already borrowed' errors."""
    if not hasattr(_thread_local, "tokenizer"):
        if HF_TOKENIZER_INSTANCE is None:
            raise RuntimeError(
                "Models not initialized. Call initialize_models() first."
            )

        # Create a new tokenizer instance for this thread
        actual_tokenizer_path = getattr(
            _thread_local, "tokenizer_path", HF_TOKENIZER_NAME
        )
        _thread_local.tokenizer = AutoTokenizer.from_pretrained(
            actual_tokenizer_path, trust_remote_code=True
        )
    return _thread_local.tokenizer


def initialize_models(
    model_path: Optional[str] = None, tokenizer_path: Optional[str] = None
):
    logging.getLogger("transformers").setLevel(logging.ERROR)
    global \
        HF_TOKENIZER_INSTANCE, \
        HF_MODEL_INSTANCE, \
        HF_DEVICE_INSTANCE, \
        HF_MODEL_NAME, \
        HF_TOKENIZER_NAME, \
        HF_DEVICE_IDS, \
        USE_MULTI_GPU

    if HF_MODEL_INSTANCE is not None:
        return

    actual_tokenizer_path = tokenizer_path if tokenizer_path else HF_TOKENIZER_NAME
    actual_model_path = model_path if model_path else HF_MODEL_NAME

    # Store tokenizer path for thread-local instances
    _thread_local.tokenizer_path = actual_tokenizer_path

    try:
        HF_TOKENIZER_INSTANCE = AutoTokenizer.from_pretrained(
            actual_tokenizer_path, trust_remote_code=True
        )
        HF_MODEL_INSTANCE = DistilBertForSequenceClassification.from_pretrained(
            actual_model_path, trust_remote_code=True
        )

        # Setup device configuration for single or multi-GPU
        if torch.cuda.is_available():
            gpu_count = torch.cuda.device_count()
            if gpu_count > 1:
                # Multi-GPU setup
                print(f"Found {gpu_count} GPUs, using DataParallel")
                HF_DEVICE_IDS = list(range(gpu_count))
                HF_DEVICE_INSTANCE = torch.device(f"cuda:{HF_DEVICE_IDS[0]}")
                HF_MODEL_INSTANCE = torch.nn.DataParallel(
                    HF_MODEL_INSTANCE, device_ids=HF_DEVICE_IDS
                )
                USE_MULTI_GPU = True
            else:
                # Single GPU setup
                print("Found 1 GPU, using single GPU")
                HF_DEVICE_INSTANCE = torch.device("cuda:0")
                HF_DEVICE_IDS = [0]
                USE_MULTI_GPU = False
        elif torch.backends.mps.is_available():
            # Apple Silicon GPU setup
            print("Found Apple Silicon GPU, using MPS")
            HF_DEVICE_INSTANCE = torch.device("mps")
            HF_DEVICE_IDS = None
            USE_MULTI_GPU = False
        else:
            # CPU fallback
            print("No GPUs found, using CPU")
            HF_DEVICE_INSTANCE = torch.device("cpu")
            HF_DEVICE_IDS = None
            USE_MULTI_GPU = False

        HF_MODEL_INSTANCE.to(HF_DEVICE_INSTANCE)
        HF_MODEL_INSTANCE.eval()
    except Exception as e:
        logging.error(f"Failed to load HF model/tokenizer: {e}")
        HF_TOKENIZER_INSTANCE = HF_MODEL_INSTANCE = HF_DEVICE_INSTANCE = None


def _get_windowed_predictions(
    input_ids: torch.Tensor, attention_mask: torch.Tensor
) -> List[Dict[str, Any]]:
    """
    Run inference on a batch of sliding windows of a single long input.
    This function expects input tensors to be on the CPU.
    """
    max_length = get_thread_tokenizer().model_max_length
    num_tokens = attention_mask.sum().item()

    batch_input_ids = []
    batch_attention_mask = []

    # The loop correctly iterates through all valid starting positions.
    for i in range(0, num_tokens, WINDOW_STRIDE):
        start_idx = i
        end_idx = i + max_length

        window_input_ids = input_ids[0, start_idx:end_idx]
        window_attention_mask = attention_mask[0, start_idx:end_idx]

        padding_needed = max_length - len(window_input_ids)
        if padding_needed > 0:
            # Pad on CPU
            pad_tensor = torch.tensor(
                [get_thread_tokenizer().pad_token_id] * padding_needed
            )
            window_input_ids = torch.cat([window_input_ids, pad_tensor])

            mask_pad_tensor = torch.tensor([0] * padding_needed)
            window_attention_mask = torch.cat([window_attention_mask, mask_pad_tensor])

        batch_input_ids.append(window_input_ids)
        batch_attention_mask.append(window_attention_mask)

    if not batch_input_ids:
        return []

    # Stack tensors and move the entire batch to the GPU
    model_inputs = {
        "input_ids": torch.stack(batch_input_ids).to(HF_DEVICE_INSTANCE),
        "attention_mask": torch.stack(batch_attention_mask).to(HF_DEVICE_INSTANCE),
    }

    try:
        with torch.no_grad():
            outputs = HF_MODEL_INSTANCE(**model_inputs)

        window_results = []
        if hasattr(outputs, "logits"):
            logits = outputs.logits
            probabilities_batch = F.softmax(logits, dim=-1).cpu()
            predictions_idx_batch = torch.argmax(probabilities_batch, dim=-1)
            label_map = {0: "Benign", 1: "Malicious"}

            for i in range(len(predictions_idx_batch)):
                prediction_idx = predictions_idx_batch[i].item()
                predicted_label = label_map.get(
                    prediction_idx, f"Unknown_Index_{prediction_idx}"
                )
                window_results.append(
                    {
                        "window_index": i,
                        "index": prediction_idx,
                        "label": predicted_label,
                        "probabilities": probabilities_batch[i].tolist(),
                    }
                )

        return window_results

    finally:
        # Clean up GPU memory after windowing operations
        if torch.cuda.is_available():
            torch.cuda.empty_cache()
        # Clear tensors
        if "model_inputs" in locals():
            del model_inputs
        if "outputs" in locals():
            del outputs


def get_batch_text_predictions(text_inputs: List[str]) -> List[Dict[str, Any]]:
    """
    Process multiple text inputs in a single batch for optimal GPU utilization.
    Returns predictions in the same order as input.
    """
    if not text_inputs:
        return []

    if (
        HF_MODEL_INSTANCE is None
        or HF_TOKENIZER_INSTANCE is None
        or HF_DEVICE_INSTANCE is None
    ):
        error_result = {
            "status": "error",
            "message": "Model_Not_Loaded",
            "prediction_debug": {"batch_size": len(text_inputs)},
        }
        return [error_result] * len(text_inputs)

    try:
        tokenizer = get_thread_tokenizer()
        max_length = tokenizer.model_max_length
        batch_results = []

        # Separate short and long texts for different processing strategies
        short_texts = []
        short_indices = []
        long_texts = []
        long_indices = []

        for i, text in enumerate(text_inputs):
            if not isinstance(text, str):
                batch_results.append(
                    {
                        "status": "error",
                        "message": "Input_Error_Invalid_Text_Input_Type",
                        "prediction_debug": {"input_index": i},
                    }
                )
                continue

            # Quick tokenization to check length
            test_tokens = tokenizer(
                text, return_tensors="pt", padding=False, truncation=False
            )
            num_tokens = test_tokens["input_ids"].shape[1]

            if num_tokens <= max_length:
                short_texts.append((i, text, test_tokens))
                short_indices.append(i)
            else:
                long_texts.append((i, text))
                long_indices.append(i)

        # Initialize results array
        results = [None] * len(text_inputs)

        # Process short texts in batches
        if short_texts:
            _process_short_texts_batch(short_texts, results, tokenizer, max_length)

        # Process long texts individually (windowing required)
        if long_texts:
            _process_long_texts_batch(long_texts, results)

        # Fill any remaining None values with errors
        for i, result in enumerate(results):
            if result is None:
                results[i] = {
                    "status": "error",
                    "message": "Processing_Error",
                    "prediction_debug": {"input_index": i},
                }

        return results

    except Exception as e:
        logging.error(f"Exception during batch inference: {e}", exc_info=True)
        error_result = {
            "status": "error",
            "message": f"Batch_Inference_Error: {str(e)}",
            "prediction_debug": {"batch_size": len(text_inputs)},
        }
        return [error_result] * len(text_inputs)


def _process_short_texts_batch(short_texts, results, tokenizer, max_length):
    """Process texts that fit within model max_length in efficient batches."""
    # Dynamic batch sizing based on available GPU memory
    if torch.cuda.is_available():
        try:
            # Check available GPU memory
            gpu_memory_gb = torch.cuda.get_device_properties(
                HF_DEVICE_INSTANCE
            ).total_memory / (1024**3)
            if gpu_memory_gb >= 8:
                BATCH_SIZE = 16  # Larger batch for high-memory GPUs
            elif gpu_memory_gb >= 4:
                BATCH_SIZE = 8  # Standard batch size
            else:
                BATCH_SIZE = 4  # Conservative for low-memory GPUs
        except Exception:
            BATCH_SIZE = 8  # Fallback
    else:
        BATCH_SIZE = 4  # Conservative for CPU/MPS

    for batch_start in range(0, len(short_texts), BATCH_SIZE):
        batch_end = min(batch_start + BATCH_SIZE, len(short_texts))
        batch = short_texts[batch_start:batch_end]

        # Prepare batch tensors
        batch_input_ids = []
        batch_attention_masks = []

        for _, text, tokens in batch:
            input_ids = tokens["input_ids"][0]
            attention_mask = tokens["attention_mask"][0]

            # Pad to max_length
            padding_needed = max_length - len(input_ids)
            if padding_needed > 0:
                pad_tensor = torch.tensor([tokenizer.pad_token_id] * padding_needed)
                input_ids = torch.cat([input_ids, pad_tensor])

                mask_pad_tensor = torch.tensor([0] * padding_needed)
                attention_mask = torch.cat([attention_mask, mask_pad_tensor])

            batch_input_ids.append(input_ids)
            batch_attention_masks.append(attention_mask)

        # Stack and move to GPU
        model_inputs = {
            "input_ids": torch.stack(batch_input_ids).to(HF_DEVICE_INSTANCE),
            "attention_mask": torch.stack(batch_attention_masks).to(HF_DEVICE_INSTANCE),
        }

        try:
            with torch.no_grad():
                outputs = HF_MODEL_INSTANCE(**model_inputs)

            # Process batch results
            if hasattr(outputs, "logits"):
                logits = outputs.logits
                probabilities_batch = F.softmax(logits, dim=-1).cpu()
                predictions_idx_batch = torch.argmax(probabilities_batch, dim=-1)
                label_map = {0: "Benign", 1: "Malicious"}

                for batch_idx, (original_idx, text, _) in enumerate(batch):
                    prediction_idx = predictions_idx_batch[batch_idx].item()
                    predicted_label = label_map.get(
                        prediction_idx, f"Unknown_Index_{prediction_idx}"
                    )

                    results[original_idx] = {
                        "status": "success",
                        "index": prediction_idx,
                        "label": predicted_label,
                        "probabilities": probabilities_batch[batch_idx].tolist(),
                        "prediction_debug": {
                            "tokenization_performed": True,
                            "windowing_performed": False,
                            "batch_processed": True,
                            "original_text_snippet": text[:200] + "..."
                            if len(text) > 200
                            else text,
                        },
                    }

        finally:
            # Explicit GPU memory cleanup
            if torch.cuda.is_available():
                torch.cuda.empty_cache()
            # Clear intermediate tensors
            del model_inputs
            if "outputs" in locals():
                del outputs


def _process_long_texts_batch(long_texts, results):
    """Process long texts that require windowing - can still batch windows."""
    for original_idx, text in long_texts:
        # Use existing windowing logic but could be optimized further
        result = get_node_text_prediction_single(text)
        results[original_idx] = result


def get_node_text_prediction(text_input: str) -> Dict[str, Any]:
    """
    Single text prediction - now optimized to use batch processing internally.
    Maintained for backward compatibility.
    """
    if isinstance(text_input, str):
        batch_results = get_batch_text_predictions([text_input])
        return (
            batch_results[0]
            if batch_results
            else {"status": "error", "message": "Batch_Processing_Failed"}
        )
    else:
        return {
            "status": "error",
            "message": "Input_Error_Invalid_Text_Input_Type",
            "prediction_debug": {"tokenization_performed": False},
        }


def get_node_text_prediction_single(text_input: str) -> Dict[str, Any]:
    prediction_debug_info: Dict[str, Any] = {
        "tokenization_performed": False,
        "windowing_performed": False,
        "window_count": 0,
        "aggregation_strategy": "N/A",
        "original_text_snippet": (
            text_input[:200] + "..." if isinstance(text_input, str) else ""
        ),
    }

    if not isinstance(text_input, str):
        return {
            "status": "error",
            "message": "Input_Error_Invalid_Text_Input_Type",
            "prediction_debug": prediction_debug_info,
        }

    if (
        HF_MODEL_INSTANCE is None
        or HF_TOKENIZER_INSTANCE is None
        or HF_DEVICE_INSTANCE is None
    ):
        return {
            "status": "error",
            "message": "Model_Not_Loaded",
            "prediction_debug": prediction_debug_info,
        }
    try:
        # Tokenize on CPU
        inputs = get_thread_tokenizer()(
            text_input,
            return_tensors="pt",
            padding=False,  # No padding yet
            truncation=False,  # No truncation yet
        )
        prediction_debug_info["tokenization_performed"] = True

        input_ids = inputs.get("input_ids")
        attention_mask = inputs.get("attention_mask")

        if input_ids is None or input_ids.numel() == 0:
            return {
                "status": "error",
                "message": "Input_Error_Empty_After_Tokenization",
                "prediction_debug": prediction_debug_info,
            }

        num_tokens = input_ids.shape[1]
        max_length = get_thread_tokenizer().model_max_length

        # --- Windowing Logic ---
        if num_tokens > max_length:
            prediction_debug_info["windowing_performed"] = True

            # This function now expects CPU tensors and handles batching + GPU transfer
            window_predictions = _get_windowed_predictions(input_ids, attention_mask)

            prediction_debug_info["window_count"] = len(window_predictions)
            prediction_debug_info["aggregation_strategy"] = "max_malicious_probability"
            prediction_debug_info["all_window_predictions"] = window_predictions

            if not window_predictions:
                return {
                    "status": "error",
                    "message": "Windowing_Error_No_Results",
                    "prediction_debug": prediction_debug_info,
                }

            # Aggregate results: find the window with the highest probability for "Malicious" (index 1)
            # This is a common strategy: if any part is malicious, the whole is.
            best_window = max(window_predictions, key=lambda x: x["probabilities"][1])

            return {
                "status": "success",
                "index": best_window["index"],
                "label": best_window["label"],
                "probabilities": best_window["probabilities"],
                "prediction_debug": prediction_debug_info,
            }

        # --- Single-Window Logic (input is not long) ---
        else:
            # The input is short enough, pad it and predict
            padding_needed = max_length - num_tokens
            if padding_needed > 0:
                # Pad on CPU
                pad_tensor = torch.tensor(
                    [get_thread_tokenizer().pad_token_id] * padding_needed
                )
                input_ids = torch.cat([input_ids[0], pad_tensor]).unsqueeze(0)

                mask_pad_tensor = torch.tensor([0] * padding_needed)
                attention_mask = torch.cat(
                    [attention_mask[0], mask_pad_tensor]
                ).unsqueeze(0)

            # Move to GPU for inference
            model_inputs = {
                "input_ids": input_ids.to(HF_DEVICE_INSTANCE),
                "attention_mask": attention_mask.to(HF_DEVICE_INSTANCE),
            }

            with torch.no_grad():
                outputs = HF_MODEL_INSTANCE(**model_inputs)

            if hasattr(outputs, "logits"):
                logits = outputs.logits
                probabilities = F.softmax(logits, dim=-1).cpu()[0]
                prediction_idx = torch.argmax(probabilities).item()
                label_map = {0: "Benign", 1: "Malicious"}
                predicted_label = label_map.get(
                    prediction_idx, f"Unknown_Index_{prediction_idx}"
                )

                return {
                    "status": "success",
                    "index": prediction_idx,
                    "label": predicted_label,
                    "probabilities": probabilities.tolist(),
                    "prediction_debug": prediction_debug_info,
                }

            return {
                "status": "error",
                "message": "No_Logits",
                "prediction_debug": prediction_debug_info,
            }

    except Exception as e:
        logging.error(
            f"Exception during model inference for input '{text_input[:100]}...': {e}",
            exc_info=True,
        )
        return {
            "status": "error",
            "message": f"Inference_Err: {str(e)}",
            "prediction_debug": prediction_debug_info,
        }


def get_model_version_string(base_version: str) -> str:
    """Get complete version string including model information."""
    try:
        initialize_models()

        version_str = f"v{base_version}"

        if HF_MODEL_INSTANCE is not None:
            try:
                # Add GPU information
                if USE_MULTI_GPU and HF_DEVICE_IDS:
                    version_str += f" (GPUs: {len(HF_DEVICE_IDS)})"
                elif torch.cuda.is_available():
                    version_str += " (GPU: 1)"
                else:
                    version_str += " (CPU)"

                # Get HuggingFace commit hash if available
                model_to_check = (
                    HF_MODEL_INSTANCE.module if USE_MULTI_GPU else HF_MODEL_INSTANCE
                )
                if hasattr(model_to_check, "config"):
                    config = model_to_check.config
                    if hasattr(config, "_commit_hash") and config._commit_hash:
                        version_str += f" (models commit: {config._commit_hash[:8]})"
            except Exception:
                pass

    except Exception:
        # Fallback to basic version if model loading fails
        version_str = f"v{base_version}"

    return version_str
