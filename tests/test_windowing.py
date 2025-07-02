import unittest
from unittest.mock import patch, MagicMock

import torch
import torch.nn.functional as F

# The path to the module needs to match your project structure.
# I've kept it as it was in the file you provided.
from research.predict_distilbert import get_node_text_prediction, initialize_models


class TestWindowingPrediction(unittest.TestCase):

    def setUp(self):
        """
        This method runs before each test.
        We can do initial setup here if needed, but patching is handled per-test.
        """
        import logging

        logging.getLogger("transformers").setLevel(logging.ERROR)

    # --- THIS IS THE KEY CHANGE ---
    # The mock for HF_DEVICE_INSTANCE is replaced with a direct value using 'new'.
    @patch("research.predict_distilbert.HF_MODEL_INSTANCE")
    @patch("research.predict_distilbert.HF_TOKENIZER_INSTANCE")
    @patch("research.predict_distilbert.get_thread_tokenizer")
    @patch("research.predict_distilbert.HF_DEVICE_INSTANCE", new="cpu")
    def test_long_input_triggers_windowing_and_aggregates_correctly(
        self, mock_get_thread_tokenizer, mock_tokenizer, mock_model
    ):
        """
        Tests the full windowing pipeline for a long input text.
        Verifies that windowing is triggered and that the results from multiple
        windows are aggregated correctly (selecting the most malicious one).
        """
        # Note: 'mock_device' is no longer an argument to this method.

        # --- 1. Configure Mocks ---

        # Configure the mock tokenizer
        mock_tokenizer.model_max_length = 512
        mock_tokenizer.pad_token_id = 0

        # When the tokenizer is called, return a tensor of 1000 tokens.
        long_input_ids = torch.ones((1, 1000), dtype=torch.long)
        long_attention_mask = torch.ones((1, 1000), dtype=torch.long)
        mock_tokenizer.return_value = {
            "input_ids": long_input_ids,
            "attention_mask": long_attention_mask,
        }

        # Configure get_thread_tokenizer to return our mock tokenizer
        mock_get_thread_tokenizer.return_value = mock_tokenizer

        # Configure the mock model to return different logits for each window.
        # The aggregation logic should pick the result from the 2nd window.
        logits_window_1 = torch.tensor([[2.197, -2.197]])
        logits_window_2 = torch.tensor([[-0.847, 0.847]])
        logits_window_3 = torch.tensor([[1.386, -1.386]])

        # The model is now called once with a batch of all windows.
        all_logits = torch.cat(
            [
                logits_window_1,
                logits_window_2,  # This one is the most malicious
                logits_window_3,
                logits_window_1,
                logits_window_1,
                logits_window_1,
                logits_window_1,
                logits_window_1,
            ],
            dim=0,
        )

        mock_model.return_value = MagicMock(logits=all_logits)

        # --- 2. Call the Function under Test ---

        long_text_input = "A" * 2000
        initialize_models()
        result = get_node_text_prediction(long_text_input)

        # --- 3. Assert the Results ---

        self.assertIsNotNone(result, "The result should not be None")
        self.assertEqual(
            result["status"], "success", "Prediction status should be 'success'"
        )

        self.assertEqual(
            result["label"], "Malicious", "The final label should be 'Malicious'"
        )
        self.assertEqual(result["index"], 1, "The final index should be 1")

        expected_probs_window_2 = F.softmax(logits_window_2, dim=-1)[0].tolist()
        self.assertAlmostEqual(
            result["probabilities"][0], expected_probs_window_2[0], places=5
        )
        self.assertAlmostEqual(
            result["probabilities"][1], expected_probs_window_2[1], places=5
        )

        debug_info = result["prediction_debug"]
        self.assertTrue(
            debug_info["windowing_performed"],
            "Debug info should confirm windowing was performed",
        )
        self.assertEqual(
            debug_info["window_count"],
            8,  # We expect 8 windows now
        )
        self.assertEqual(
            debug_info["aggregation_strategy"], "max_malicious_probability"
        )
        # The model should only be called once with the entire batch
        mock_model.assert_called_once()
