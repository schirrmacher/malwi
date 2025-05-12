# Research Notes

## Importance of Function Names

Removing the function names had severe impact on the model performance. The F1 score dropped from ~96% to ~50%.

- eval_loss: 0.26130083203315735
- eval_accuracy: 0.9277157136557401
- eval_f1'0.47700079766019676
- eval_precision: 0.998330550918197
- eval_recall: 0.31336244541484715
- epoch: 3.0

We removed the function names because we saw many functions in the test data with similar structures, only differing in a function name. The goal was to remove those, since they seem to be not meaningful.