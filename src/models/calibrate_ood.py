# -*- coding: utf-8 -*-
"""
Calibrate the serving OOD threshold (tau) on the SERVING ensemble's own confidence.

tau is set so that only `target-false-ood` of KNOWN flows are flagged OOD (default 2%).
Because the ensemble is overconfident, this tau is small but principled — far better than
a hand-picked constant. Saves models/ood_detector.json (loaded by the scoring service).

Run: python -m src.models.calibrate_ood --n 3000 --target-false-ood 0.02
"""
import argparse
import sys

import numpy as np
import pandas as pd

from src.models.ensemble import get_default_ensemble
from src.models.ood_detector import OODDetector, calibrate_tau
from src.features.flow_extractor import CICFLOWMETER_FEATURE_NAMES as COLS


def main(argv=None) -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--data", default="data/test_real_v2.parquet")
    ap.add_argument("--n", type=int, default=3000)
    ap.add_argument("--target-false-ood", type=float, default=0.02)
    ap.add_argument("--mode", default="xgb_only")
    ap.add_argument("--out", default="models/ood_detector.json")
    args = ap.parse_args(argv)

    df = pd.read_parquet(args.data)
    df = df.sample(n=min(args.n, len(df)), random_state=7)
    cols = [c for c in COLS if c in df.columns]
    ens = get_default_ensemble()

    scores = []
    for _, row in df.iterrows():
        feats = {c: float(row[c]) for c in cols}
        _, conf, _ = ens.score_flow(features=feats, mode=args.mode)
        scores.append(1.0 - float(conf))  # OOD score on a KNOWN flow
    tau = calibrate_tau(np.array(scores), args.target_false_ood)
    realized = float((np.array(scores) >= tau).mean())
    OODDetector(tau=tau, target_false_ood=args.target_false_ood).save(args.out)
    print(f"[+] Calibrated serving OOD tau={tau:.4f} for target false-OOD={args.target_false_ood:.0%} "
          f"-> realized={realized:.2%} over {len(df)} known flows. Saved {args.out}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
