#!/usr/bin/env python3
"""
CyberShield Main Security Runner (Entry Point Wrapper)
Runs the complete DDoS detection, ML classifier, Nemotron 3 Ultra 550B AI reasoning,
and automated mitigation pipeline.
"""
import os
import sys

# Add root directory to sys.path
ROOT_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if ROOT_DIR not in sys.path:
    sys.path.insert(0, ROOT_DIR)

if __name__ == "__main__":
    import run_full_simulation
    run_full_simulation.run_simulation()
