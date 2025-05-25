# Research Notes

- Commit: `5b1eb22`
- `DEFAULT_BENIGN_TO_MALICIOUS_RATIO = 5.0`

```
{'eval_loss': 0.11457934230566025, 'eval_accuracy': 0.9714260101745815, 'eval_f1': 0.9104697703812934, 'eval_precision': 0.9527751922794298, 'eval_recall': 0.8717615419094576, 'eval_runtime': 226.4452, 'eval_samples_per_second': 591.15, 'eval_steps_per_second': 36.949, 'epoch': 3.0}
{'train_runtime': 8969.4482, 'train_samples_per_second': 179.091, 'train_steps_per_second': 11.193, 'train_loss': 0.12444903290217556, 'epoch': 3.0}
```

- Commit: `1188024`

```
{'eval_loss': 0.29895564913749695, 'eval_accuracy': 0.8867476329084278, 'eval_f1': 0.8473368511252424, 'eval_precision': 0.9194479788587648, 'eval_recall': 0.7857142857142857, 'eval_runtime': 51.7835, 'eval_samples_per_second': 577.191, 'eval_steps_per_second': 36.093, 'epoch': 3.0}
```

## Showing Content of Strings

When showing the content of strings smaller than 10 chars without mapping the performance increases massively.

Is that over-fitting?

```
{'eval_loss': 0.20528019964694977, 'eval_accuracy': 0.9382244410679401, 'eval_f1': 0.9208212775428444, 'eval_precision': 0.9447933318109157, 'eval_recall': 0.8980355980030389, 'eval_runtime': 79.1926, 'eval_samples_per_second': 581.746, 'eval_steps_per_second': 36.367, 'epoch': 3.0}
```

After updating the special tokens as well:

```
{'eval_loss': 0.2024698257446289, 'eval_accuracy': 0.9367050141089647, 'eval_f1': 0.9189549749861033, 'eval_precision': 0.9418869644484958, 'eval_recall': 0.8971130887779466, 'eval_runtime': 78.3273, 'eval_samples_per_second': 588.173, 'eval_steps_per_second': 36.769, 'epoch': 3.0}
```