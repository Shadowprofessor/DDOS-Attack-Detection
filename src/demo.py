# -*- coding: utf-8 -*-
"""
One-command M1 demo:  python -m src.demo

Drives the real FastAPI scoring app in-process (TestClient — no port to manage):
  1-2) benign + known attacks via a single /score/batch call,
  3)   a Slowloris/R.U.D.Y. low-and-slow alert,
  4)   a GENUINE unseen-class (zero-day) detection with a full outcome breakdown: an OOD
       model trained WITHOUT one attack class is scored on that held-out class.

Config via environment (no private server state is touched):
  DDOS_API_KEYS           demo API key(s)              (default: demo-key)
  DDOS_LOWSLOW_THRESHOLD  low-and-slow concurrency     (default: 20)
"""
import os
import sys

# Configure the service via env BEFORE it is imported (no poking of private state later).
os.environ.setdefault("DDOS_API_KEYS", "demo-key")
os.environ.setdefault("DDOS_LOWSLOW_THRESHOLD", "20")

import numpy as np
import pandas as pd
from fastapi.testclient import TestClient

DATA = "data/test_real_v2.parquet"
HOLDOUT = "LDAP"
HELDOUT_MODEL = f"models/ood_model_heldout_{HOLDOUT}.joblib"
DEMO_KEY = os.environ["DDOS_API_KEYS"].split(",")[0]


def _print(title):
    print("\n" + "=" * 72 + f"\n{title}\n" + "=" * 72)


def main() -> int:
    from src.api import scoring_service as svc
    from src.features.flow_extractor import CICFLOWMETER_FEATURE_NAMES as COLS
    from src.models.ood_detector import OODDetector

    hdr = {"X-API-Key": DEMO_KEY}
    df = pd.read_parquet(DATA)
    feats = [c for c in COLS if c in df.columns]

    def numeric(row, **ov):
        f = {c: float(row[c]) for c in feats}
        f.update(ov)
        return f

    with TestClient(svc.app) as client:
        # 1-2) BENIGN + KNOWN ATTACKS via a single batch call -----------------
        _print("1-2) Benign + known attacks  (single /score/batch call)")
        families = ["Benign", "Syn", "NTP", "UDP", "MSSQL"]
        flows, truth = [], []
        for fam in families:
            sub = df[df.Label == fam]
            if not sub.empty:
                flows.append(numeric(sub.iloc[0]))
                truth.append(fam)
        resp = client.post("/score/batch", json={"flows": flows}, headers=hdr)
        for fam, res in zip(truth, resp.json()["results"]):
            print(f"   true={fam:<8} -> is_attack={res['is_attack']}  "
                  f"predicted={res['attack_family']}  conf={res['confidence']:.2f}")

        # 3) LOW-AND-SLOW (threshold from DDOS_LOWSLOW_THRESHOLD) --------------
        _print("3) Low-and-slow (Slowloris/RUDY) — concurrent starved connections")
        base = df[df.Label == "Benign"].iloc[0]
        alert = None
        for i in range(int(os.environ["DDOS_LOWSLOW_THRESHOLD"]) + 4):
            f = numeric(base, **{"Flow Duration": 30_000_000.0, "Fwd Packets Length Total": 200.0,
                                 "src_ip": f"198.51.100.{i}", "Destination Port": 80})
            alert = client.post("/score/flow", json={"features": f}, headers=hdr).json().get("low_slow")
        print(f"   *** LOW-AND-SLOW ALERT: {alert['attack_hint']} on {alert['dst_ip']}:{alert['dst_port']} "
              f"({alert['concurrent_slow_connections']} concurrent slow conns) ***"
              if alert else "   (no alert — unexpected)")

        # 4) GENUINE unseen-class detection + outcome breakdown ---------------
        _print(f"4) Zero-day: OOD model trained WITHOUT '{HOLDOUT}' — outcome on held-out {HOLDOUT}")
        if not os.path.exists(HELDOUT_MODEL):
            print(f"   (training held-out model excluding {HOLDOUT}, ~30s, one-time)...")
            from src.models.train_ood_model import main as train_ood
            train_ood(["--holdout", HOLDOUT, "--out", HELDOUT_MODEL, "--per-class-cap", "6000"])
        det = OODDetector.load(HELDOUT_MODEL)
        med = getattr(svc.registry, "medians", None)

        unseen = df[df.Label == HOLDOUT]
        ood = other_attack = missed_benign = 0
        example = None
        for _, r in unseen.iterrows():
            a = det.assess_features(numeric(r), med)
            if a["ood_suspected"]:
                ood += 1
                example = example or a["ood_score"]
            elif det.predicted_label(numeric(r), med) == "Benign":
                missed_benign += 1
            else:
                other_attack += 1
        n = max(1, len(unseen))
        print(f"   held-out '{HOLDOUT}' (n={len(unseen)}) outcome breakdown:")
        print(f"     flagged OOD (genuine unseen detection) : {ood / n:6.1%}")
        print(f"     caught as ANOTHER attack family        : {other_attack / n:6.1%}")
        print(f"     MISSED as Benign (the dangerous miss)  : {missed_benign / n:6.1%}")
        seen = df[df.Label != HOLDOUT].sample(n=min(400, len(df)), random_state=3)
        false_ood = float(np.mean([det.assess_features(numeric(r), med)["ood_suspected"]
                                   for _, r in seen.iterrows()]))
        print(f"   known-class false-OOD rate: {false_ood:.1%}  (tau calibrated to ~2%)")
        if example is not None:
            print(f"   *** ZERO-DAY-SUSPECTED example: ood_score={example:.3f} true={HOLDOUT} "
                  f"(held out of training) -> route to Nemotron ***")

    _print("Demo complete")
    print("Honest: results are CIC-DDoS2019 same-dataset; binary attack/benign ~100%, per-class "
          "macro-F1 ~0.52, OOD family-novelty AUROC ~0.61. Cross-dataset pending M6. See docs/EVAL_NOTES.md.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
