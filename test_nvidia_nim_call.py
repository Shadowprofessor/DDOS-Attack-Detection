import os
import sys

sys.path.insert(0, r'C:\Users\Sachit Sharma\Documents\DDoS-Attack-Detection-and-Mitigation-using-Machine-Learning')

# Check environment
nim_key = os.environ.get('NVIDIA_API_KEY')
or_key = os.environ.get('OPENROUTER_API_KEY')

print(f'NVIDIA_API_KEY: {"SET (len=" + str(len(nim_key)) + ")" if nim_key else "NOT SET"}')
print(f'OPENROUTER_API_KEY: {"SET" if or_key else "NOT SET"}')

# Now test the agent
from src.agent.nemotron_agent import NemotronAgent

print("\n=== Testing NemotronAgent provider selection ===")
agent = NemotronAgent()
print(f'Provider selected: {agent.provider}')
print(f'Model: {agent.model}')
print(f'API URL: {agent.api_url}')
print(f'API Key present: {bool(agent.api_key)}')

if agent.provider != 'nvidia_nim':
    print('ERROR: Expected provider "nvidia_nim" but got:', agent.provider)
    sys.exit(1)

# Test one real call
print("\n=== Making ONE real NVIDIA NIM API call ===")
test_prompt = (
    "You are a DDoS threat analyst. Analyze this attack:\n"
    "Attacker: 192.168.1.100 -> Victim: 10.0.0.1\n"
    "Vector: Syn Flood\n"
    "Confidence: 0.95\n"
    "Ensemble: FULL_UNANIMOUS (RF, XGB, LSTM all agree on Syn)\n\n"
    "Return ONLY valid JSON with keys: explanation, attack_type_guess, severity, proposed_action, requires_human_approval"
)

parsed, raw = agent._call_nemotron_api(test_prompt)

print(f'Parsed result: {parsed}')
print(f'Raw response length: {len(raw)} chars')
print(f'Requires human approval: {parsed.get("requires_human_approval") if parsed else "N/A"}')
print(f'Severity: {parsed.get("severity") if parsed else "N/A"}')
print(f'Proposed action: {parsed.get("proposed_action") if parsed else "N/A"}')

if parsed and parsed.get('requires_human_approval') is True:
    print("\n[OK] NVIDIA NIM call SUCCESS - real response received")
    print(f"[OK] Provider correctly shows: {agent.provider}")
else:
    print("\n[FAIL] NVIDIA NIM call FAILED or returned unexpected result")
    sys.exit(1)