# Research Notes

## Best Training Results

Including imports with every functions definition.

Commit `ffdde6a0c2bdebe8d531f273d42ed6a6d01a4306`

- eval_loss: 0.10081843286752701
- eval_accuracy: 0.9729129300505462
- eval_f1: 0.9388684452621895
- eval_precision: 0.9689532399715167
- eval_recall: 0.9105955833147445
- epoch: 3.0

Limitations:
- There are still very similar functions in the benign and malicious dataset.
- There are many false-positives when scanning random folders
- The dataset needs more polishing

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

### Removal for Hash Only

Commit: `23366c5b66a9bd294b20146900404eb8ccaaaeda`

We changed the hashing to discover more similar function structures for removal. This was achieved by removing the function name before hashing a token sequence. However the F1 score dropped by 10%.

- eval_loss: 0.12401288002729416
- eval_accuracy: 0.9644007561436673
- eval_f1: 0.8386344941047437
- eval_precision: 0.9123042505592841
- eval_recall: 0.7759736141063047
- epoch: 3.0

## Meta-Data Features

Commit: `aed8d3722ad20a1007171462a40c03aa77c31a64`

Introduction of the file size in bytes with size categories.

- eval_loss: 0.1232079267501831
- eval_accuracy: 0.965107625372109
- eval_f1: 0.8406952430737062
- eval_precision: 0.9221616972477065
- eval_recall: 0.7724543707973103
- epoch: 3.0

## Combinations

- Including imports and including function names from hashing
    - eval_loss: 0.10081843286752701
    - eval_accuracy: 0.9729129300505462
    - eval_f1: 0.9388684452621895
    - eval_precision: 0.9689532399715167
    - eval_recall: 0.9105955833147445

- Including imports and excluding function names from hashing
    - eval_loss: 0.11095818877220154
    - eval_accuracy: 0.9707047034103766
    - eval_f1: 0.8708968955897193
    - eval_precision: 0.9338085539714868
    - eval_recall: 0.8159270381492604

- Excluding imports and function names from hashing
    - eval_loss: 0.10438332706689835
    - eval_accuracy: 0.9722226197461253
    - eval_f1: 0.8744745521567613
    - eval_precision: 0.9477151668068405
    - eval_recall: 0.8117421058950655