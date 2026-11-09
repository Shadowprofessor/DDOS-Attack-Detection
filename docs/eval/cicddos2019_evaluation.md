# CICDDoS2019 Model Evaluation Report — Step 2

**Generated:** 2026-10-03 15:25:08  
**Taxonomy:** 13 Canonical Classes (SSDP dropped per known limitation, TFTP & Portmap included)  
**Dataset Split:** 80% Train (335,107 samples), 20% Held-Out Test (83,777 samples)  
**Deduplication:** Applied across all 77 features prior to splitting to eliminate cross-day synthetic leakage.

---

## 1. Summary Performance Comparison

| Model | Accuracy | Macro F1 | Weighted F1 | Training Time |
|---|---|---|---|---|
| **XGBoost (Primary)** | **98.34%** | **0.7952** | **0.9834** | 9.71s |
| **Random Forest (Baseline)** | 98.22% | 0.7776 | 0.9819 | 1.98s |

---

## 2. XGBoost Per-Class Performance Breakdown

| Class | Precision | Recall | F1-Score | Test Support |
|---|---:|---:|---:|---:|
| **Benign** | 0.9980 | 0.9987 | 0.9984 | 18,937 |
| **DNS** | 0.7491 | 0.5450 | 0.6309 | 734 |
| **LDAP** | 0.6448 | 0.6818 | 0.6628 | 418 |
| **MSSQL** | 0.9212 | 0.9622 | 0.9413 | 2,357 |
| **NTP** | 0.9992 | 0.9953 | 0.9972 | 24,266 |
| **NetBIOS** | 0.7285 | 0.8148 | 0.7692 | 135 |
| **Portmap** | 0.4276 | 0.7654 | 0.5487 | 81 |
| **SNMP** | 0.6673 | 0.8412 | 0.7442 | 403 |
| **Syn** | 0.9987 | 0.9892 | 0.9940 | 9,552 |
| **TFTP** | 0.9999 | 0.9977 | 0.9988 | 19,767 |
| **UDP** | 0.9316 | 0.9913 | 0.9605 | 5,427 |
| **UDP-Lag** | 0.9310 | 0.7669 | 0.8410 | 1,690 |
| **WebDDoS** | 0.1452 | 0.9000 | 0.2500 | 10 |

---

## 3. XGBoost Confusion Matrix

```
Classes Order: [np.str_('Benign'), np.str_('DNS'), np.str_('LDAP'), np.str_('MSSQL'), np.str_('NTP'), np.str_('NetBIOS'), np.str_('Portmap'), np.str_('SNMP'), np.str_('Syn'), np.str_('TFTP'), np.str_('UDP'), np.str_('UDP-Lag'), np.str_('WebDDoS')]
         Benign  DNS  LDAP  MSSQL    NTP  NetBIOS  Portmap  SNMP   Syn   TFTP   UDP  UDP-Lag  WebDDoS
Benign    18913   16     1      0      2        1        3     0     0      0     0        0        1
DNS           2  400   111    122     11       20        6    55     0      0     6        0        1
LDAP          2   65   285     15      0        0        0    51     0      0     0        0        0
MSSQL         2   13     5   2268      1        0        5    60     0      1     2        0        0
NTP          17   14     0      7  24152        5       13     0     3      0     5        6       44
NetBIOS       0    1     0      7      0      110       14     0     1      0     2        0        0
Portmap       0    0     0      2      0       14       62     0     2      0     1        0        0
SNMP          0   15    38      9      0        1        0   339     0      0     0        0        1
Syn          12    0     0      2      0        0       36     0  9449      0     4       48        1
TFTP          2    0     0      5      2        0        2     0     2  19721     0       28        5
UDP           0    9     0     23      0        0        1     0     0      0  5380       14        0
UDP-Lag       1    1     2      2      3        0        3     3     4      0   375     1296        0
WebDDoS       0    0     0      0      1        0        0     0     0      0     0        0        9
```
