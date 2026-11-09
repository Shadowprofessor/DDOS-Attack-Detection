# -*- coding: utf-8 -*-
"""
Live NVIDIA NIM API test — ONE real call through NemotronAgent.

Verifies:
  1. self.provider == "nvidia_nim" (not "openrouter")
  2. Real API call returns a valid response (or a clear error)
  3. No API key value appears in any printed output

Usage: python -m tests.test_nvidia_nim_live
"""
import os
import sys
import json

# Ensure repo root is on path
REPO_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if REPO_ROOT not in sys.path:
    sys.path.insert(0, REPO_ROOT)

from src.agent.nemotron_agent import NemotronAgent


def main():
    api_key = os.environ.get("NVIDIA_API_KEY", "")
    if not api_key:
        print("ERROR: NVIDIA_API_KEY environment variable not set.")
        sys.exit(1)

    print(f"[INFO] NVIDIA_API_KEY present: yes (length={len(api_key)})")

    # Instantiate agent
    agent = NemotronAgent()

    # Verify provider selection
    print(f"[CHECK 1] agent.provider = {agent.provider!r}")
    assert agent.provider == "nvidia_nim", f"Expected 'nvidia_nim', got {agent.provider!r}"
    print("[CHECK 1] PASS — provider is nvidia_nim")

    # Verify model name
    print(f"[INFO] agent.model = {agent.model!r}")
    print(f"[INFO] agent.api_url = {agent.api_url!r}")

    # Build a minimal test prompt
    test_prompt = (
        "Batch Telemetry (1 high-confidence alert with ensemble context):\n"
        "[1] Source: test_harness | Attacker: 10.0.0.99 -> Victim: 10.0.0.1 | "
        "Vector: Syn | Aggregated Confidence: 0.97\n"
        "    Consensus Tier: SINGLE_MODEL\n"
        "    Consensus Summary: Single model active (xgboost): Syn (conf: 0.97).\n"
        "    Per-Model Predictions: XGB=Syn (0.97)\n\n"
        "Formulate mitigation proposals."
    )

    print("\n[CHECK 2] Sending ONE real API call to NVIDIA NIM...")
    parsed_json, raw_text = agent._call_nemotron_api(test_prompt)

    # Verify no key leakage in outputs
    combined_output = json.dumps(parsed_json or {}) + raw_text
    assert api_key not in combined_output, "CRITICAL: API key found in response output!"
    print("[CHECK 3] PASS — no API key value found in any output")

    # Print results
    print(f"\n[RESULT] parsed_json type: {type(parsed_json).__name__}")
    print(f"[RESULT] parsed_json is None: {parsed_json is None}")

    if parsed_json:
        print("[RESULT] Parsed JSON response:")
        print(json.dumps(parsed_json, indent=2))
        print(f"\n[RESULT] Keys in response: {list(parsed_json.keys())}")

        # Check for expected keys
        expected_keys = {"explanation", "attack_type_guess", "severity", "proposed_action", "requires_human_approval"}
        present_keys = set(parsed_json.keys()) & expected_keys
        missing_keys = expected_keys - present_keys
        print(f"[RESULT] Expected keys present: {present_keys}")
        if missing_keys:
            print(f"[RESULT] Missing expected keys: {missing_keys}")
        if parsed_json.get("requires_human_approval") is True:
            print("[RESULT] requires_human_approval = True — CORRECT per safety mandate")
    else:
        print(f"[RESULT] raw_text snippet: {raw_text[:500]}")
        if "HTTP error" in raw_text or "Exception" in raw_text:
            print(f"[WARN] API call failed — degraded mode fallback. Raw: {raw_text}")
        else:
            print(f"[WARN] Could not parse JSON from response.")

    # Final summary
    print("\n" + "=" * 60)
    if parsed_json:
        print("NVIDIA NIM LIVE CALL: SUCCESS — got structured JSON response")
    else:
        print(f"NVIDIA NIM LIVE CALL: FAILED/DEGRADED — {raw_text[:200]}")
    print("=" * 60)

    assert parsed_json is not None, f"NVIDIA NIM call failed: {raw_text[:300]}"
    assert parsed_json.get("requires_human_approval") is True, "requires_human_approval must be True"


def test_nvidia_nim_live_call():
    """Pytest test case for live NVIDIA NIM call."""
    main()


if __name__ == "__main__":
    main()

