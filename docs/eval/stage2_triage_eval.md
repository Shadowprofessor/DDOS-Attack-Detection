# Stage 2 Multi-Class Attack Triage Model Evaluation Report

- **Target Gate Requirement**: Macro F1 >= 0.9500
- **Status**: **PASSED** (5-Fold CV Mean Macro F1 = **0.9717 +/- 0.0009**)
- **95% Confidence Interval**: [0.9698, 0.9735]

## 5-Fold Stratified Cross-Validation Breakdown

| Fold | Macro F1 Score |
| :--- | :---: |
| Fold 1 | 0.9712 |
| Fold 2 | 0.9729 |
| Fold 3 | 0.9704 |
| Fold 4 | 0.9712 |
| Fold 5 | 0.9726 |
| **Mean +/- Std** | **0.9717 +/- 0.0009** |

## Per-Class Performance Breakdown (Held-Out Test Set)

| Canonical Class | Precision | Recall | F1-Score | Support |
| :--- | :---: | :---: | :---: | :---: |
| **MSSQL** | 0.9219 | 0.9567 | 0.9390 | 2,357.0 |
| **NTP** | 0.9984 | 0.9994 | 0.9989 | 24,266.0 |
| **Reflection-Amplification** | 0.9338 | 0.8927 | 0.9128 | 1,771.0 |
| **Syn** | 0.9962 | 0.9952 | 0.9957 | 9,552.0 |
| **TFTP** | 0.9995 | 0.9975 | 0.9985 | 19,767.0 |
| **UDP-Based** | 0.9891 | 0.9910 | 0.9900 | 7,117.0 |
| **Macro Avg** | 0.9732 | 0.9721 | 0.9725 | 64,830.0 |
| **Weighted Avg** | 0.9928 | 0.9928 | 0.9928 | 64,830.0 |

## Confusion Matrix

```
Actual \ Pred                     MSSQL           NTPReflection-Amplification           Syn          TFTP     UDP-Based
MSSQL                              2255             5            85             1             3             8
NTP                                   1         24252             6             2             2             3
Reflection-Amplification            160            13          1581            10             0             7
Syn                                   1             1             8          9506             1            35
TFTP                                  3            14             2             6         19717            25
UDP-Based                            26             7            11            17             3          7053
```
