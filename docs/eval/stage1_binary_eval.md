# Stage 1 Binary Classifier Evaluation Report

- **Target Gate Requirement**: Macro F1 >= 0.9900
- **Status**: **PASSED** (Macro F1 = 0.9995)
- **Overall Accuracy**: 99.963%

## Classification Metrics

| Class | Precision | Recall | F1-Score | Support |
| :--- | :---: | :---: | :---: | :---: |
| **Attack** | 0.9998 | 0.9997 | 0.9998 | 64,840.0 |
| **Benign** | 0.9989 | 0.9995 | 0.9992 | 18,937.0 |
| **Macro Avg** | 0.9994 | 0.9996 | 0.9995 | 83,777.0 |
| **Weighted Avg** | 0.9996 | 0.9996 | 0.9996 | 83,777.0 |

## Confusion Matrix

```
Predicted ->       Attack      Benign
Actual Attack        64819          21
Actual Benign           10       18927
```
