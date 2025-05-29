# Research Notes

## Tokenization

Status: `Open`

Problem: Different language versions create different artifacts. Example: Compilation of Python version A creates different bytecode than Python version B.

There are different ways to address this:

- Train models with randomly picked bytecode versions
    - More development effort
    - Better for the user because she can use any Python version
- Train different models for different versions
    - Complex model management
    - User potentially works with many models
- Define abstract format for training
    - Requires deep knowledge of all Python versions
- Pin compilation version, e.g. by extracting compilation logic of one language version
    - Requires platform independent binaries for the compilation on the user's machine

## Triaging

Status: `Open`

Problem: Triaging is the categorization of findings into true-positives or false-positives. Persisting triaging data has the advantage of using it for future training. However, when the tokenization logic changes, the triaging data might get obsolete. This creates the question how to persist triaging data independently of the language version beeing used and the tokenization logic?

- code snippet extraction
    - snippets might not be syntactically sound, e.g. only extracting a function from a class cannot be compiled solely
- store whole file
    - requires more memory
    - open how to target a specific object in that file, most object do not possess a name
- store raw tokenization information
    - still bytecode might change due to versions
    - mapping tokenization to new format very elaborate
- ❌ marshalling the code object
    - Highly language version specific
- ❌ store tokenized bytecode
    - mapping logic changes, making the triaged data obsolete

## Model Training

- Commit: `5b1eb22`
- `DEFAULT_BENIGN_TO_MALICIOUS_RATIO = 7.0`
- `STRING_MAX_LENGTH = 15`

```
{'eval_loss': 0.0848444327712059, 'eval_accuracy': 0.9788069376238938, 'eval_f1': 0.9118840786100826, 'eval_precision': 0.9493328391401038, 'eval_recall': 0.8772777092752432, 'eval_runtime': 397.5391, 'eval_samples_per_second': 587.532, 'eval_steps_per_second': 36.721, 'epoch': 3.0}
```

- Commit: `1188024`

```
{'eval_loss': 0.29895564913749695, 'eval_accuracy': 0.8867476329084278, 'eval_f1': 0.8473368511252424, 'eval_precision': 0.9194479788587648, 'eval_recall': 0.7857142857142857, 'eval_runtime': 51.7835, 'eval_samples_per_second': 577.191, 'eval_steps_per_second': 36.093, 'epoch': 3.0}
```

### Importance of Strings

When showing the content of strings smaller than 10 chars without mapping the performance increases massively.

Is that over-fitting?

```
{'eval_loss': 0.20528019964694977, 'eval_accuracy': 0.9382244410679401, 'eval_f1': 0.9208212775428444, 'eval_precision': 0.9447933318109157, 'eval_recall': 0.8980355980030389, 'eval_runtime': 79.1926, 'eval_samples_per_second': 581.746, 'eval_steps_per_second': 36.367, 'epoch': 3.0}
```

After updating the special tokens as well:

```
{'eval_loss': 0.2024698257446289, 'eval_accuracy': 0.9367050141089647, 'eval_f1': 0.9189549749861033, 'eval_precision': 0.9418869644484958, 'eval_recall': 0.8971130887779466, 'eval_runtime': 78.3273, 'eval_samples_per_second': 588.173, 'eval_steps_per_second': 36.769, 'epoch': 3.0}
```