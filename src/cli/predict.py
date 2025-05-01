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


def initialize_hf_model_components(
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
        logging.info(f"HF model '{actual_model_path}' loaded on {HF_DEVICE_INSTANCE}.")
    except Exception as e:
        logging.error(f"Failed to load HF model/tokenizer: {e}")
        HF_TOKENIZER_INSTANCE = HF_MODEL_INSTANCE = HF_DEVICE_INSTANCE = None


def get_node_text_prediction(text_input: str) -> Dict[str, Any]:
    if (
        HF_MODEL_INSTANCE is None
        or HF_TOKENIZER_INSTANCE is None
        or HF_DEVICE_INSTANCE is None
    ):
        return {"status": "error", "message": "Model_Not_Loaded"}
    try:
        inputs = HF_TOKENIZER_INSTANCE(
            text_input,
            return_tensors="pt",
            padding=True,
            truncation=True,
            max_length=512,
        )
        model_inputs = {}
        if "input_ids" in inputs:
            model_inputs["input_ids"] = inputs["input_ids"].to(HF_DEVICE_INSTANCE)
        if "attention_mask" in inputs:
            model_inputs["attention_mask"] = inputs["attention_mask"].to(
                HF_DEVICE_INSTANCE
            )

        if not model_inputs.get("input_ids") is not None:
            return {"status": "error", "message": "Input_Error"}

        with torch.no_grad():
            outputs = HF_MODEL_INSTANCE(**model_inputs)

        if hasattr(outputs, "logits"):
            logits = outputs.logits
            probabilities = F.softmax(logits, dim=-1).cpu()
            first_item_probabilities = probabilities[0]
            prediction_idx = torch.argmax(first_item_probabilities).item()
            label_map = {0: "Benign", 1: "Malicious"}
            predicted_label = label_map.get(
                prediction_idx, f"Unknown_Index_{prediction_idx}"
            )
            return {
                "status": "success",
                "index": prediction_idx,
                "label": predicted_label,
                "probabilities": first_item_probabilities.tolist(),
            }
        return {"status": "error", "message": "No_Logits"}
    except Exception as e:
        logging.error(
            f"Exception during model inference for input '{text_input[:100]}...': {e}",
            exc_info=True,
        )
        return {"status": "error", "message": "Inference_Err"}
