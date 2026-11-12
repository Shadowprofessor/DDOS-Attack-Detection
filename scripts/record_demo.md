# Recording the demo GIF (`docs/media/demo.gif`)

Two ways to make it. The README shows whichever you committed last, and its caption must say which one it is.

## A. Automatic: a replay of a recorded live run (what the committed GIF uses)

```powershell
python scripts/record_demo.py                       # default: data/lab_runs/live8/contain_syn_flood.pcap
python scripts/record_demo.py --pcap data/lab_runs/live9/contain_syn_flood.pcap --approve-after 30
```

It needs no WSL, no sudo and no network. It uses the dashboard's Node Playwright (`cd dashboard && npm ci`
once), and Pillow assembles the GIF, so ffmpeg is not needed. In about 90 s it does this, all on 127.0.0.1:

1. Starts the platform with throwaway demo keys and a temporary database.
2. Starts the real bridge, then re-writes the recorded victim-side pcap **and the same run's switch counters**
   (`ovs_ports.jsonl`) at real-time pace with `scripts/pcap_replay_live.py`. No packet is sent anywhere.
3. Drives the website:
   - signs in as the admin and watches **Live attack**;
   - when the incident opens, asks the agent and proposes its top lab step, using the analyst key, as
     `demo_assist.py` does;
   - shows **Why it was flagged** and the **AI containment plan**;
   - approves on **Approvals** at the same delay after the alert as the human did in that run (live8: 33.6 s).
4. A **mock** enforcer reports `applied`, because a replay has no switch. The drop on the switch-counter chart
   is the real recorded drop after the real rule in that run.
5. Every frame carries the caption *"REPLAY of recorded lab traffic (live8) · enforcer mocked · 2× speed"*.
   Output: 960 px wide, ~1–2 MB.

Options: `--speed 3` (shorter), `--width 800` (smaller), `--seconds 56` (how much of the pcap).
Set `NVIDIA_API_KEY` in the environment first if you want the AI verdict from Nemotron instead of the rule
analyst.

## B. Manual: screen-record a real live run

Use this for a GIF that shows the real enforcer, with no mock. Caption it *"Live lab run (Mininet on WSL2)"*.

**Window size.** Put the browser at **1280 × 900**, zoom 100%, on **Live attack**, signed in as `demo-admin-key-0001`.
In Chrome: DevTools → Ctrl+Shift+M → Responsive 1280 × 900. Or resize the window to about that size.

**The four windows** (full detail in [RUNBOOK block H](../docs/RUNBOOK.md)):
```powershell
# 1 server
$env:DDOS_API_KEYS = "demo-analyst-key-01"; $env:DDOS_ADMIN_KEYS = "demo-admin-key-0001"; $env:NVIDIA_API_KEY = "<key>"
python -m uvicorn src.api.app:app --host 127.0.0.1 --port 8000
# 2 bridge
$env:DDOS_LIVE_KEY = "demo-analyst-key-01"; python scripts/live_bridge.py data/lab_runs/live10 --reset
# 3 helper (proposes, cannot approve)
$env:DDOS_LIVE_KEY = "demo-analyst-key-01"; python scripts/demo_assist.py
```
```bash
# 4 WSL
cd "/mnt/c/Users/Sachit Sharma/Documents/Sachit Main/DDoS-Detection-clean"
sudo mn -c; sudo CONTAIN=1 bash lab/live_demo.sh live10
```

**Record.** Click the browser, then press **Win + Alt + R** to start the Xbox Game Bar recording, and press it
again to stop. It saves an `.mp4` in `Videos\Captures`. OBS works too.

**What to capture**, in order, about 60–90 s:
1. Live attack is calm, then the banner turns red and the pop-up appears.
2. Click **Open INC-…** in the pop-up: "Why it was flagged", then scroll to the AI containment plan
   ("Stops ~100%").
3. **Approvals**: *Approve…* → *Approve and enforce*.
4. **Live attack**: Lab containment shows `applied`, and the switch-counter chart drops to 0.

**Convert to a GIF under 10 MB** (install ffmpeg first: `winget install Gyan.FFmpeg`):
```powershell
$in = "$env:USERPROFILE\Videos\Captures\<your file>.mp4"
ffmpeg -y -ss 0 -t 90 -i $in -vf "fps=8,scale=960:-1:flags=lanczos,palettegen=max_colors=128:stats_mode=diff" palette.png
ffmpeg -y -ss 0 -t 90 -i $in -i palette.png -lavfi "fps=8,scale=960:-1:flags=lanczos,setpts=0.5*PTS[x];[x][1:v]paletteuse=dither=bayer:bayer_scale=5:diff_mode=rectangle" docs/media/demo.gif
(Get-Item docs/media/demo.gif).Length / 1MB    # must be < 10
```
`setpts=0.5*PTS` plays it at 2× speed. Over 10 MB? Lower `fps=6` or `scale=800:-1`, or trim with `-ss`/`-t`.
Then update the caption under the GIF in `README.md`.
