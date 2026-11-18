# CT Phish Detection

## Training

Set `model.type` in `config.yaml` to choose the training models:

- `custom` - Tuned model
- `classical` - Train and evaluate every classical model
- `logistic_regression`
- `random_forest`
- `svm`
- `decision_tree`
- `knn`
- `naive_bayes`
- `gradient_boosting`

Run `make reproduce` or `python -m src.train --config config.yaml`.

A model choice can also be overridden for one run:
```bash
python -m src.train --config config.yaml --model svm
```