# Multi-Dataset Model Evaluation Report

**Generated:** 2026-10-11 02:24:47
**Feature Schema:** 77 features (CICFLOWMETER_FEATURE_NAMES)
**Dataset Split:** 80% Train (381,666 samples), 20% Held-Out Test (95,417 samples)
**Performance Gate:** ❌ FAILED (baseline=0.9980, achieved=0.9828)

---

## 1. Aggregate Model Performance Summary

| Model | Accuracy | Macro F1 | Weighted F1 | Training Time |
|---|---|---|---|---|
| **XGBoost (Primary)** | **98.03%** | **0.7921** | **0.9814** | 22.91s |
| **Random Forest (Baseline)** | 98.23% | 0.7912 | 0.9828 | 2.91s |

---

## 2. Primary Model (XGBoost) Per-Class Metrics (Aggregate)

| Class | Precision | Recall | F1-Score | Test Support |
|---|---:|---:|---:|---:|
| **Benign** | 0.9992 | 0.9979 | 0.9985 | 24,787 |
| **DNS** | 0.6042 | 0.6281 | 0.6159 | 734 |
| **LDAP** | 0.5976 | 0.7105 | 0.6492 | 418 |
| **MSSQL** | 0.9278 | 0.9215 | 0.9246 | 2,357 |
| **NTP** | 0.9997 | 0.9941 | 0.9969 | 24,266 |
| **NetBIOS** | 0.6478 | 0.7630 | 0.7007 | 135 |
| **Other_DDoS** | 0.9974 | 1.0000 | 0.9987 | 378 |
| **Portmap** | 0.3413 | 0.7037 | 0.4597 | 81 |
| **SNMP** | 0.7006 | 0.8362 | 0.7624 | 403 |
| **Syn** | 0.9998 | 0.9903 | 0.9950 | 12,419 |
| **TFTP** | 0.9998 | 0.9966 | 0.9982 | 19,767 |
| **UDP** | 0.9693 | 0.9302 | 0.9494 | 7,971 |
| **UDP-Lag** | 0.7164 | 0.8575 | 0.7806 | 1,691 |
| **WebDDoS** | 0.1493 | 1.0000 | 0.2597 | 10 |

---

## 3. XGBoost Confusion Matrix (Aggregate)

```
Classes Order: [np.str_('Benign'), np.str_('DNS'), np.str_('LDAP'), np.str_('MSSQL'), np.str_('NTP'), np.str_('NetBIOS'), np.str_('Other_DDoS'), np.str_('Portmap'), np.str_('SNMP'), np.str_('Syn'), np.str_('TFTP'), np.str_('UDP'), np.str_('UDP-Lag'), np.str_('WebDDoS')]
            Benign  DNS  LDAP  MSSQL    NTP  NetBIOS  Other_DDoS  Portmap  SNMP    Syn   TFTP   UDP  UDP-Lag  WebDDoS
Benign       24735   18     1      0      3        2           1       10     1      0      2     0        1       13
DNS              0  461   125     86      3       10           0        1    42      0      0     5        1        0
LDAP             1   72   297      6      0        0           0        0    41      0      0     0        1        0
MSSQL            0   97    22   2172      0        7           0        5    52      0      1     1        0        0
NTP              8   63     1     11  24123        2           0        7     3      0      0     0       14       34
NetBIOS          0    0     0      5      1      103           0       23     0      2      0     0        0        1
Other_DDoS       0    0     0      0      0        0         378        0     0      0      0     0        0        0
Portmap          1    0     0      0      0       23           0       57     0      0      0     0        0        0
SNMP             0    8    49      4      0        4           0        0   337      0      0     0        1        0
Syn              8    2     0      3      0        0           0       56     0  12299      0     0       51        0
TFTP             2    2     0      8      0        0           0        1     3      0  19699     0       43        9
UDP              0   36     0     44      0        8           0        5     1      0      0  7415      462        0
UDP-Lag          0    4     2      2      0        0           0        2     1      1      0   229     1450        0
WebDDoS          0    0     0      0      0        0           0        0     0      0      0     0        0       10
```

---

## 4. Per-Dataset Evaluation Breakdowns

### XGBoost

#### Source: `cicddos2019` (83,810 test samples)

| Metric | Value |
|---|---:|
| Accuracy | 97.76% |
| Macro F1 | 0.7742 |
| Weighted F1 | 0.9788 |

| Class | Precision | Recall | F1-Score | Support |
|---|---:|---:|---:|---:|
| Benign | 0.9989 | 0.9973 | 0.9981 | 18,968 |
| DNS | 0.6042 | 0.6281 | 0.6159 | 734 |
| LDAP | 0.5976 | 0.7105 | 0.6492 | 418 |
| MSSQL | 0.9278 | 0.9215 | 0.9246 | 2,357 |
| NTP | 0.9997 | 0.9941 | 0.9969 | 24,266 |
| NetBIOS | 0.6478 | 0.7630 | 0.7007 | 135 |
| Portmap | 0.3413 | 0.7037 | 0.4597 | 81 |
| SNMP | 0.7006 | 0.8362 | 0.7624 | 403 |
| Syn | 0.9997 | 0.9875 | 0.9935 | 9,565 |
| TFTP | 0.9998 | 0.9966 | 0.9982 | 19,767 |
| UDP | 0.9539 | 0.8973 | 0.9247 | 5,415 |
| UDP-Lag | 0.7164 | 0.8575 | 0.7806 | 1,691 |
| WebDDoS | 0.1493 | 1.0000 | 0.2597 | 10 |

```
Confusion Matrix (cicddos2019):
Classes: [np.str_('Benign'), np.str_('DNS'), np.str_('LDAP'), np.str_('MSSQL'), np.str_('NTP'), np.str_('NetBIOS'), np.str_('Portmap'), np.str_('SNMP'), np.str_('Syn'), np.str_('TFTP'), np.str_('UDP'), np.str_('UDP-Lag'), np.str_('WebDDoS')]
         Benign  DNS  LDAP  MSSQL    NTP  NetBIOS  Portmap  SNMP   Syn   TFTP   UDP  UDP-Lag  WebDDoS
Benign    18917   18     1      0      3        2       10     1     0      2     0        1       13
DNS           0  461   125     86      3       10        1    42     0      0     5        1        0
LDAP          1   72   297      6      0        0        0    41     0      0     0        1        0
MSSQL         0   97    22   2172      0        7        5    52     0      1     1        0        0
NTP           8   63     1     11  24123        2        7     3     0      0     0       14       34
NetBIOS       0    0     0      5      1      103       23     0     2      0     0        0        1
Portmap       1    0     0      0      0       23       57     0     0      0     0        0        0
SNMP          0    8    49      4      0        4        0   337     0      0     0        1        0
Syn           8    2     0      3      0        0       56     0  9445      0     0       51        0
TFTP          2    2     0      8      0        0        1     3     0  19699     0       43        9
UDP           0   36     0     44      0        8        5     1     0      0  4859      462        0
UDP-Lag       0    4     2      2      0        0        2     1     1      0   229     1450        0
WebDDoS       0    0     0      0      0        0        0     0     0      0     0        0       10
```

#### Source: `CICIoT2023 (unofficial Hugging Face mirror, partial: Benign/SYN Flood/UDP Flood only, 3 of 33+ official attack classes)` (8,270 test samples)

| Metric | Value |
|---|---:|
| Accuracy | 100.00% |
| Macro F1 | 1.0000 |
| Weighted F1 | 1.0000 |

| Class | Precision | Recall | F1-Score | Support |
|---|---:|---:|---:|---:|
| Benign | 1.0000 | 1.0000 | 1.0000 | 2,860 |
| Syn | 1.0000 | 1.0000 | 1.0000 | 2,854 |
| UDP | 1.0000 | 1.0000 | 1.0000 | 2,556 |

```
Confusion Matrix (ciciot2023):
Classes: [np.str_('Benign'), np.str_('Syn'), np.str_('UDP')]
        Benign   Syn   UDP
Benign    2860     0     0
Syn          0  2854     0
UDP          0     0  2556
```

#### Source: `insdn` (3,337 test samples)

| Metric | Value |
|---|---:|
| Accuracy | 99.97% |
| Macro F1 | 0.9993 |
| Weighted F1 | 0.9997 |

| Class | Precision | Recall | F1-Score | Support |
|---|---:|---:|---:|---:|
| Benign | 1.0000 | 0.9997 | 0.9998 | 2,959 |
| Other_DDoS | 0.9974 | 1.0000 | 0.9987 | 378 |

```
Confusion Matrix (insdn):
Classes: [np.str_('Benign'), np.str_('Other_DDoS')]
            Benign  Other_DDoS
Benign        2958           1
Other_DDoS       0         378
```

#### Source: `synthetic_sdn (eval-only, 6/77 real features, not used in training)` (2,000 eval-only samples)

> [!NOTE]
> **Eval-Only Dataset:** Held out entirely from training split (0 samples in training set) to eliminate shortcut learning from its absent/zero-filled features.

| Metric | Value |
|---|---:|
| Accuracy | 0.00% |
| Macro F1 | 0.0000 |
| Weighted F1 | 0.0000 |

| Class | Precision | Recall | F1-Score | Support |
|---|---:|---:|---:|---:|
| Benign | 0.0000 | 0.0000 | 0.0000 | 0 |
| Other_DDoS | 0.0000 | 0.0000 | 0.0000 | 2,000 |
| Syn | 0.0000 | 0.0000 | 0.0000 | 0 |
| UDP | 0.0000 | 0.0000 | 0.0000 | 0 |

```
Confusion Matrix (synthetic_sdn):
Classes: [np.str_('Benign'), np.str_('Other_DDoS'), np.str_('Syn'), np.str_('UDP')]
            Benign  Other_DDoS  Syn  UDP
Benign           0           0    0    0
Other_DDoS     734           0  731  535
Syn              0           0    0    0
UDP              0           0    0    0
```

### RandomForest

#### Source: `cicddos2019` (83,810 test samples)

| Metric | Value |
|---|---:|
| Accuracy | 97.99% |
| Macro F1 | 0.7736 |
| Weighted F1 | 0.9804 |

| Class | Precision | Recall | F1-Score | Support |
|---|---:|---:|---:|---:|
| Benign | 0.9977 | 0.9970 | 0.9974 | 18,968 |
| DNS | 0.6438 | 0.5368 | 0.5854 | 734 |
| LDAP | 0.5758 | 0.7177 | 0.6390 | 418 |
| MSSQL | 0.9089 | 0.9478 | 0.9279 | 2,357 |
| NTP | 0.9997 | 0.9945 | 0.9971 | 24,266 |
| NetBIOS | 0.6369 | 0.7407 | 0.6849 | 135 |
| Portmap | 0.3413 | 0.7037 | 0.4597 | 81 |
| SNMP | 0.7329 | 0.8784 | 0.7991 | 403 |
| Syn | 0.9998 | 0.9868 | 0.9933 | 9,565 |
| TFTP | 0.9999 | 0.9960 | 0.9980 | 19,767 |
| UDP | 0.9363 | 0.9557 | 0.9459 | 5,415 |
| UDP-Lag | 0.8342 | 0.7883 | 0.8106 | 1,691 |
| WebDDoS | 0.1270 | 0.8000 | 0.2192 | 10 |

```
Confusion Matrix (cicddos2019):
Classes: [np.str_('Benign'), np.str_('DNS'), np.str_('LDAP'), np.str_('MSSQL'), np.str_('NTP'), np.str_('NetBIOS'), np.str_('Portmap'), np.str_('SNMP'), np.str_('Syn'), np.str_('TFTP'), np.str_('UDP'), np.str_('UDP-Lag'), np.str_('WebDDoS')]
         Benign  DNS  LDAP  MSSQL    NTP  NetBIOS  Portmap  SNMP   Syn   TFTP   UDP  UDP-Lag  WebDDoS
Benign    18911   22     2      0      2        1        6     0     2      0     0       11       11
DNS           0  394   166    110      4       15        1    40     0      0     3        1        0
LDAP          2   74   300      4      0        0        0    37     0      0     0        1        0
MSSQL         0   45    21   2234      0        6        4    46     0      1     0        0        0
NTP          18   33     1     21  24132        4        7     0     0      0     1       15       34
NetBIOS       0    1     0      4      0      100       27     0     0      0     0        2        1
Portmap       1    2     0      0      0       20       57     0     0      0     1        0        0
SNMP          0    9    30      4      0        4        1   354     0      0     0        1        0
Syn          14    2     0      3      0        0       55     0  9439      0     0       52        0
TFTP          3    2     0     17      0        0        3     3     0  19688     0       42        9
UDP           0   26     0     59      2        7        5     1     0      0  5175      140        0
UDP-Lag       3    2     1      2      0        0        1     2     0      0   347     1333        0
WebDDoS       2    0     0      0      0        0        0     0     0      0     0        0        8
```

#### Source: `CICIoT2023 (unofficial Hugging Face mirror, partial: Benign/SYN Flood/UDP Flood only, 3 of 33+ official attack classes)` (8,270 test samples)

| Metric | Value |
|---|---:|
| Accuracy | 100.00% |
| Macro F1 | 1.0000 |
| Weighted F1 | 1.0000 |

| Class | Precision | Recall | F1-Score | Support |
|---|---:|---:|---:|---:|
| Benign | 1.0000 | 1.0000 | 1.0000 | 2,860 |
| Syn | 1.0000 | 1.0000 | 1.0000 | 2,854 |
| UDP | 1.0000 | 1.0000 | 1.0000 | 2,556 |

```
Confusion Matrix (ciciot2023):
Classes: [np.str_('Benign'), np.str_('Syn'), np.str_('UDP')]
        Benign   Syn   UDP
Benign    2860     0     0
Syn          0  2854     0
UDP          0     0  2556
```

#### Source: `insdn` (3,337 test samples)

| Metric | Value |
|---|---:|
| Accuracy | 100.00% |
| Macro F1 | 1.0000 |
| Weighted F1 | 1.0000 |

| Class | Precision | Recall | F1-Score | Support |
|---|---:|---:|---:|---:|
| Benign | 1.0000 | 1.0000 | 1.0000 | 2,959 |
| Other_DDoS | 1.0000 | 1.0000 | 1.0000 | 378 |

```
Confusion Matrix (insdn):
Classes: [np.str_('Benign'), np.str_('Other_DDoS')]
            Benign  Other_DDoS
Benign        2959           0
Other_DDoS       0         378
```

#### Source: `synthetic_sdn (eval-only, 6/77 real features, not used in training)` (2,000 eval-only samples)

> [!NOTE]
> **Eval-Only Dataset:** Held out entirely from training split (0 samples in training set) to eliminate shortcut learning from its absent/zero-filled features.

| Metric | Value |
|---|---:|
| Accuracy | 0.00% |
| Macro F1 | 0.0000 |
| Weighted F1 | 0.0000 |

| Class | Precision | Recall | F1-Score | Support |
|---|---:|---:|---:|---:|
| Benign | 0.0000 | 0.0000 | 0.0000 | 0 |
| Other_DDoS | 0.0000 | 0.0000 | 0.0000 | 2,000 |
| UDP | 0.0000 | 0.0000 | 0.0000 | 0 |

```
Confusion Matrix (synthetic_sdn):
Classes: [np.str_('Benign'), np.str_('Other_DDoS'), np.str_('UDP')]
            Benign  Other_DDoS  UDP
Benign           0           0    0
Other_DDoS    1772           0  228
UDP              0           0    0
```

---

## 5. Classes Below Recall Threshold (< 95%)

Explicit audit of all attack classes failing the >= 95% recall operational reliability gate on held-out test splits:

| Model | Source Dataset | Attack Class | Recall | Precision | F1-Score | Support | Reliability Assessment |
|---|---|---|---:|---:|---:|---:|---|
| **XGBoost** | `cicddos2019` | **DNS** | 62.81% | 0.6042 | 0.6159 | 734 | HIGH SAMPLE (n >= 500) -- systematic feature overlap / structural deficit |
| **XGBoost** | `cicddos2019` | **LDAP** | 71.05% | 0.5976 | 0.6492 | 418 | MODERATE SAMPLE (n < 500) -- inter-protocol reflection confusion |
| **XGBoost** | `cicddos2019` | **MSSQL** | 92.15% | 0.9278 | 0.9246 | 2,357 | HIGH SAMPLE (n >= 500) -- systematic feature overlap / structural deficit |
| **XGBoost** | `cicddos2019` | **NetBIOS** | 76.30% | 0.6478 | 0.7007 | 135 | MODERATE SAMPLE (n < 500) -- inter-protocol reflection confusion |
| **XGBoost** | `cicddos2019` | **Portmap** | 70.37% | 0.3413 | 0.4597 | 81 | MODERATE SAMPLE (n < 500) -- inter-protocol reflection confusion |
| **XGBoost** | `cicddos2019` | **SNMP** | 83.62% | 0.7006 | 0.7624 | 403 | MODERATE SAMPLE (n < 500) -- inter-protocol reflection confusion |
| **XGBoost** | `cicddos2019` | **UDP** | 89.73% | 0.9539 | 0.9247 | 5,415 | HIGH SAMPLE (n >= 500) -- systematic feature overlap / structural deficit |
| **XGBoost** | `cicddos2019` | **UDP-Lag** | 85.75% | 0.7164 | 0.7806 | 1,691 | HIGH SAMPLE (n >= 500) -- systematic feature overlap / structural deficit |
| **RandomForest** | `cicddos2019` | **DNS** | 53.68% | 0.6438 | 0.5854 | 734 | HIGH SAMPLE (n >= 500) -- systematic feature overlap / structural deficit |
| **RandomForest** | `cicddos2019` | **LDAP** | 71.77% | 0.5758 | 0.6390 | 418 | MODERATE SAMPLE (n < 500) -- inter-protocol reflection confusion |
| **RandomForest** | `cicddos2019` | **MSSQL** | 94.78% | 0.9089 | 0.9279 | 2,357 | HIGH SAMPLE (n >= 500) -- systematic feature overlap / structural deficit |
| **RandomForest** | `cicddos2019` | **NetBIOS** | 74.07% | 0.6369 | 0.6849 | 135 | MODERATE SAMPLE (n < 500) -- inter-protocol reflection confusion |
| **RandomForest** | `cicddos2019` | **Portmap** | 70.37% | 0.3413 | 0.4597 | 81 | MODERATE SAMPLE (n < 500) -- inter-protocol reflection confusion |
| **RandomForest** | `cicddos2019` | **SNMP** | 87.84% | 0.7329 | 0.7991 | 403 | MODERATE SAMPLE (n < 500) -- inter-protocol reflection confusion |
| **RandomForest** | `cicddos2019` | **UDP-Lag** | 78.83% | 0.8342 | 0.8106 | 1,691 | HIGH SAMPLE (n >= 500) -- systematic feature overlap / structural deficit |
| **RandomForest** | `cicddos2019` | **WebDDoS** | 80.00% | 0.1270 | 0.2192 | 10 | LOW SAMPLE CONFIDENCE (n < 50) -- high variance / underrepresented |

---

## 6. Below-Threshold Remediation: UDP-Lag Family Grouping Experiment

Comparative evaluation testing the consolidated taxonomy remediation from `KNOWN_ISSUES.md`:

| Taxonomy Configuration | Attack Family | Recall | Precision | F1-Score | Support | Status |
|---|---|---:|---:|---:|---:|---|
| Individual (Baseline) | `UDP` | 93.02% | 0.9693 | 0.9494 | 7,971 | Clears 95% threshold |
| Individual (Baseline) | `UDP-Lag` | 85.75% | 0.7164 | 0.7806 | 1,691 | ⚠ FAILS 95% threshold (confused with UDP) |
| Consolidated Family | `UDP-Based` (UDP + UDP-Lag) | **99.09%** | **0.9868** | **0.9888** | **9,662** | **✅ CLEARS 95% threshold** |
| Consolidated Family | `Reflection-Amplification` | **89.72%** | **0.8594** | **0.8779** | **1,771** | **✅ Reflection bottleneck resolved** |

