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
        HF_TOKENIZER_NAME

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
        HF_DEVICE_INSTANCE = torch.device(
            "cuda" if torch.cuda.is_available() else "cpu"
        )
        HF_MODEL_INSTANCE.to(HF_DEVICE_INSTANCE)
        HF_MODEL_INSTANCE.eval()
    except Exception as e:
        logging.error(f"Failed to load HF model/tokenizer: {e}")
        HF_TOKENIZER_INSTANCE = HF_MODEL_INSTANCE = HF_DEVICE_INSTANCE = None


def _get_windowed_predictions(
    input_ids: torch.Tensor, attention_mask: torch.Tensor
) -> List[Dict[str, Any]]:
    """
    Run inference on multiple sliding windows of a single long input.
    """
    window_results = []
    max_length = get_thread_tokenizer().model_max_length
    num_tokens = attention_mask.sum().item()

    # The loop correctly iterates through all valid starting positions.
    for i in range(0, num_tokens, WINDOW_STRIDE):
        start_idx = i
        end_idx = i + max_length

        window_input_ids = input_ids[0, start_idx:end_idx]
        window_attention_mask = attention_mask[0, start_idx:end_idx]

        padding_needed = max_length - len(window_input_ids)
        if padding_needed > 0:
            pad_tensor = torch.tensor(
                [get_thread_tokenizer().pad_token_id] * padding_needed,
                device=HF_DEVICE_INSTANCE,
            )
            window_input_ids = torch.cat([window_input_ids, pad_tensor])

            mask_pad_tensor = torch.tensor(
                [0] * padding_needed, device=HF_DEVICE_INSTANCE
            )
            window_attention_mask = torch.cat([window_attention_mask, mask_pad_tensor])

        model_inputs = {
            "input_ids": window_input_ids.unsqueeze(0),
            "attention_mask": window_attention_mask.unsqueeze(0),
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

            window_results.append(
                {
                    "window_index": len(window_results),
                    "index": prediction_idx,
                    "label": predicted_label,
                    "probabilities": probabilities.tolist(),
                }
            )

        # --- THIS BLOCK IS REMOVED ---
        # if end_idx >= num_tokens:
        #     break

    return window_results


def get_node_text_prediction(text_input: str) -> Dict[str, Any]:
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
        # Tokenize the entire input without truncation to check its length
        inputs = get_thread_tokenizer()(
            text_input,
            return_tensors="pt",
            padding=False,  # No padding yet
            truncation=False,  # No truncation yet
        )
        prediction_debug_info["tokenization_performed"] = True

        input_ids = inputs.get("input_ids").to(HF_DEVICE_INSTANCE)
        attention_mask = inputs.get("attention_mask").to(HF_DEVICE_INSTANCE)

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
            # The input is short enough, so we pad it to max_length and predict
            padded_inputs = get_thread_tokenizer()(
                text_input,
                return_tensors="pt",
                padding="max_length",
                truncation=True,
                max_length=max_length,
            )
            model_inputs = {
                "input_ids": padded_inputs["input_ids"].to(HF_DEVICE_INSTANCE),
                "attention_mask": padded_inputs["attention_mask"].to(
                    HF_DEVICE_INSTANCE
                ),
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

        version_str = f"👹 v{base_version}"

        if HF_MODEL_INSTANCE is not None:
            try:
                # Get HuggingFace commit hash if available
                if hasattr(HF_MODEL_INSTANCE, "config"):
                    config = HF_MODEL_INSTANCE.config
                    if hasattr(config, "_commit_hash") and config._commit_hash:
                        version_str += f" (models commit: {config._commit_hash[:8]})"
            except Exception:
                pass

    except Exception:
        # Fallback to basic version if model loading fails
        version_str = f"👹 v{base_version}"

    return version_str
