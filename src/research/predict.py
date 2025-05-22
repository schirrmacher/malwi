import logging
from typing import Dict, Any, Optional

import torch
import torch.nn.functional as F
from transformers import AutoTokenizer, DistilBertForSequenceClassification

HF_TOKENIZER_NAME = "schirrmacher/malwi-tokenizer"
HF_MODEL_NAME = "schirrmacher/malwi"
HF_TOKENIZER_INSTANCE = None
HF_MODEL_INSTANCE = None
HF_DEVICE_INSTANCE = None


def initialize_models(
    model_path: Optional[str] = None, tokenizer_path: Optional[str] = None
):
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


def get_node_text_prediction(text_input: str) -> Dict[str, Any]:
    tokenization_debug_info: Dict[str, Any] = {
        "tokenization_performed": False,
        "original_text_snippet": (
            text_input[:200] + "..." if isinstance(text_input, str) else ""
        ),
        "input_ids": None,
        "decoded_tokens": None,
        "unk_token_id": None,
        "unk_token_count": 0,
        "total_non_padding_tokens": 0,
        "oov_rate_percentage": 0.0,
    }

    if not isinstance(text_input, str):
        return {
            "status": "error",
            "message": "Input_Error_Invalid_Text_Input_Type",
            "tokenization_debug": tokenization_debug_info,
        }

    if (
        HF_MODEL_INSTANCE is None
        or HF_TOKENIZER_INSTANCE is None
        or HF_DEVICE_INSTANCE is None
    ):
        return {
            "status": "error",
            "message": "Model_Not_Loaded",
            "tokenization_debug": tokenization_debug_info,
        }
    try:
        inputs = HF_TOKENIZER_INSTANCE(
            text_input,
            return_tensors="pt",
            padding=True,
            truncation=True,
            max_length=512,
        )
        tokenization_debug_info["tokenization_performed"] = True

        input_ids_tensor = inputs.get("input_ids")
        if input_ids_tensor is not None and input_ids_tensor.numel() > 0:
            tokenization_debug_info["input_ids"] = input_ids_tensor[0].tolist()
            decoded_tokens = [
                HF_TOKENIZER_INSTANCE.decode([token_id])
                for token_id in input_ids_tensor[0].tolist()
            ]
            tokenization_debug_info["decoded_tokens"] = decoded_tokens

            unk_token_id = HF_TOKENIZER_INSTANCE.unk_token_id
            tokenization_debug_info["unk_token_id"] = unk_token_id
            if unk_token_id is not None:
                unk_token_count = (input_ids_tensor[0] == unk_token_id).sum().item()
                if HF_TOKENIZER_INSTANCE.pad_token_id is not None:
                    total_valid_tokens = (
                        input_ids_tensor[0]
                        .ne(HF_TOKENIZER_INSTANCE.pad_token_id)
                        .sum()
                        .item()
                    )
                else:
                    total_valid_tokens = len(input_ids_tensor[0])

                tokenization_debug_info["unk_token_count"] = unk_token_count
                tokenization_debug_info["total_non_padding_tokens"] = total_valid_tokens
                if total_valid_tokens > 0:
                    oov_rate = (unk_token_count / total_valid_tokens) * 100
                    tokenization_debug_info["oov_rate_percentage"] = round(oov_rate, 2)
            else:
                pass
        else:
            tokenization_debug_info["input_ids"] = []
            tokenization_debug_info["decoded_tokens"] = []

        model_inputs = {}
        if "input_ids" in inputs and inputs["input_ids"].numel() > 0:
            model_inputs["input_ids"] = inputs["input_ids"].to(HF_DEVICE_INSTANCE)
        if "attention_mask" in inputs and inputs["input_ids"].numel() > 0:
            model_inputs["attention_mask"] = inputs["attention_mask"].to(
                HF_DEVICE_INSTANCE
            )

        if model_inputs.get("input_ids") is None:
            return {
                "status": "error",
                "message": "Input_Error_Missing_Input_IDs",
                "tokenization_debug": tokenization_debug_info,
            }

        with torch.no_grad():
            outputs = HF_MODEL_INSTANCE(**model_inputs)

        if hasattr(outputs, "logits"):
            logits = outputs.logits
            probabilities = F.softmax(logits, dim=-1).cpu()
            first_item_probabilities = probabilities[0]
            prediction_idx = torch.argmax(first_item_probabilities).item()
            label_map = {
                0: "Benign",
                1: "Malicious",
            }
            predicted_label = label_map.get(
                prediction_idx, f"Unknown_Index_{prediction_idx}"
            )
            return {
                "status": "success",
                "index": prediction_idx,
                "label": predicted_label,
                "probabilities": first_item_probabilities.tolist(),
                "tokenization_debug": tokenization_debug_info,
            }
        return {
            "status": "error",
            "message": "No_Logits",
            "tokenization_debug": tokenization_debug_info,
        }
    except Exception as e:
        logging.error(
            f"Exception during model inference for input '{text_input[:100]}...': {e}",
            exc_info=True,
        )
        return {
            "status": "error",
            "message": f"Inference_Err: {str(e)}",
            "tokenization_debug": tokenization_debug_info,
        }
