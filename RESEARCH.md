# Research Notes

## Best Training Results

Commit `d33f83c3f07df13b43a61d8d8c23e550bf9cd4d7`

- eval_loss: 0.12330903112888336
- eval_accuracy: 0.9648917299775762
- eval_f1: 0.9177491440370089
- eval_precision: 0.9576197229191665
- eval_recall: 0.8810658905003262
- epoch: 3.0

Limitations:
- There are still very similar functions in the benign and malicious dataset.
- Those leads to false-positives

## Importance of Function Names

### Sanitization and Mapping

Commit: `d33f83c3f07df13b43a61d8d8c23e550bf9cd4d7`

The removal of mapping function names to categories has negative implication on training results. Thus, mapping and sanitization of function names increases results.

- eval_loss: 0.17983506619930267
- eval_accuracy: 0.949343601184092
- eval_f1: 0.8746583158621055
- eval_precision: 0.979144385026738
- eval_recall: 0.7903218071075728
- epoch: 3.0

### Removal

Commit: `bd9b81f6c1784f3aedf11069a4e15427b26fe0ca`

Removing the function names had severe impact on the model performance. The F1 score dropped from ~96% to ~50%.

- eval_loss: 0.26130083203315735
- eval_accuracy: 0.9277157136557401
- eval_f1: 0.47700079766019676
- eval_precision: 0.998330550918197
- eval_recall: 0.31336244541484715
- epoch: 3.0

We removed the function names because we saw many functions in the test data with similar structures, only differing in a function name. The goal was to remove those, since they seem to be not meaningful.