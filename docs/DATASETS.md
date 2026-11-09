# Datasets & Citations

This project uses the following public research datasets. Their terms require citing the
originating papers in any work that uses them; please retain these citations.

| Dataset | Used for | Status in repo |
|---|---|---|
| **CIC-DDoS2019** | Primary training + same-dataset evaluation (13-class taxonomy) | `data/combined_training_set.parquet`, `data/test_real_v2.parquet` |
| **CIC-IDS2017** | Cross-dataset held-out generalization test | Planned (M6) |
| **CICIoT2023** | IoT-botnet traffic (SYN/UDP flood, benign) | `data/ciciot2023/*.csv` |
| **UNSW-NB15** | Cross-dataset held-out generalization test | Planned (M6) |

> **Evaluation scope note:** `test_real_v2` is a *separate extraction* of CIC-DDoS2019 but
> shares ~13k exact-duplicate flows with the training set — it is the **same recordings
> re-split, not an independent capture**. Reported near-perfect binary attack/benign numbers
> are therefore **same-dataset**; genuine cross-dataset generalization (CIC-IDS2017, UNSW-NB15)
> is measured in M6. See [`EVAL_NOTES.md`](EVAL_NOTES.md).

## Citations

- **CIC-DDoS2019** — I. Sharafaldin, A. H. Lashkari, S. Hakak, and A. A. Ghorbani,
  "Developing Realistic Distributed Denial of Service (DDoS) Attack Dataset and Taxonomy,"
  *IEEE International Carnahan Conference on Security Technology (ICCST)*, 2019.

- **CIC-IDS2017** — I. Sharafaldin, A. H. Lashkari, and A. A. Ghorbani,
  "Toward Generating a New Intrusion Detection Dataset and Intrusion Traffic Characterization,"
  *4th International Conference on Information Systems Security and Privacy (ICISSP)*, 2018.

- **CICIoT2023** — E. C. P. Neto, S. Dadkhah, R. Ferreira, A. Zohourian, R. Lu, and
  A. A. Ghorbani, "CICIoT2023: A Real-Time Dataset and Benchmark for Large-Scale Attacks in
  IoT Environment," *Sensors*, 2023.

- **UNSW-NB15** — N. Moustafa and J. Slay, "UNSW-NB15: A Comprehensive Data Set for Network
  Intrusion Detection Systems (UNSW-NB15 Network Data Set),"
  *Military Communications and Information Systems Conference (MilCIS)*, 2015.

CIC datasets are provided by the Canadian Institute for Cybersecurity (University of New
Brunswick); UNSW-NB15 by UNSW Canberra. Use is subject to each provider's terms.
