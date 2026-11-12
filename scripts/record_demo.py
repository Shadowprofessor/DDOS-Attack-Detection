# -*- coding: utf-8 -*-
"""Record docs/media/demo.gif headlessly from a REPLAYED lab run (v6.1.0). No packets are sent anywhere.

    python scripts/record_demo.py                       # uses data/lab_runs/live8/contain_syn_flood.pcap
    python scripts/record_demo.py --pcap data/lab_runs/live9/contain_syn_flood.pcap --approve-after 33.6

What it does, all on 127.0.0.1:
  1. starts the platform (python -m uvicorn) with throwaway demo keys and a temporary database;
  2. starts the real live bridge on an empty replay folder;
  3. re-writes the recorded victim-side pcap into that folder at real-time pace (scripts/pcap_replay_live.py);
  4. drives the SOC website with the existing Node Playwright (scripts/record_demo.mjs): it signs in as the
     admin, watches Live attack, asks the agent for a plan, proposes the top lab step (analyst key), and
     approves it on the Approvals page at the same delay after the alert as the human did in that live run;
     a MOCK lab enforcer then reports "applied" (there is no switch in a replay);
  5. stitches the screenshots into an optimised GIF with Pillow, every frame captioned
     "REPLAY of recorded lab traffic (<run>) - enforcer mocked - <speed>x".

The traffic drop on the chart is the drop recorded in the pcap after the real approved rule in that run;
the approval click is re-enacted at its recorded time. Label the GIF as a replay wherever it is shown.
"""
from __future__ import annotations

import argparse
import json
import os
import shutil
import subprocess
import sys
import tempfile
import time
import urllib.request
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
ANALYST, ADMIN = "demo-analyst-key-01", "demo-admin-key-0001"


def wait_http(url: str, timeout: float = 120.0) -> None:
    end = time.time() + timeout
    while time.time() < end:
        try:
            with urllib.request.urlopen(url, timeout=2) as r:  # nosec B310 - localhost only
                if r.status == 200:
                    return
        except OSError:
            time.sleep(0.5)
    raise SystemExit(f"{url} did not come up")


def build_gif(frames: list, out: Path, caption: str, frame_ms: int, width: int) -> None:
    from PIL import Image, ImageDraw, ImageFont

    try:
        font = ImageFont.truetype("arial.ttf", 18)
    except OSError:
        font = ImageFont.load_default()
    imgs = []
    for f in frames:
        im = Image.open(f).convert("RGB")
        im = im.resize((width, round(im.height * width / im.width)), Image.LANCZOS)
        framed = Image.new("RGB", (im.width, im.height + 30), (11, 16, 32))  # caption strip below, never over the page
        framed.paste(im, (0, 0))
        d = ImageDraw.Draw(framed)
        tw = d.textlength(caption, font=font)
        d.text(((framed.width - tw) / 2, im.height + 5), caption, fill=(255, 186, 8), font=font)
        im = framed
        imgs.append(im.quantize(colors=96, method=Image.Quantize.MEDIANCUT, dither=Image.Dither.NONE))
    out.parent.mkdir(parents=True, exist_ok=True)
    imgs[0].save(out, save_all=True, append_images=imgs[1:], duration=frame_ms, loop=0, optimize=True, disposal=1)


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--pcap", default="data/lab_runs/live8/contain_syn_flood.pcap")
    ap.add_argument("--approve-after", type=float, default=33.6,
                    help="seconds from the alert to the approval (live8: 33.6 s, from its bridge log)")
    ap.add_argument("--seconds", type=float, default=50.0, help="how much of the pcap to replay")
    ap.add_argument("--port", type=int, default=8777)
    ap.add_argument("--speed", type=float, default=2.0, help="GIF playback speed-up (frames are taken every 0.5 s)")
    ap.add_argument("--width", type=int, default=960)
    ap.add_argument("--out", default="docs/media/demo.gif")
    a = ap.parse_args()

    pcap = REPO / a.pcap
    if not pcap.is_file():
        raise SystemExit(f"{pcap} not found: record a live run first (RUNBOOK block H)")
    run_name = pcap.parent.name
    work = Path(tempfile.mkdtemp(prefix="ddos-gif-"))
    replay_dir, frames_dir = work / "replay", work / "frames"
    replay_dir.mkdir()
    frames_dir.mkdir()
    base = f"http://127.0.0.1:{a.port}"
    env = {**os.environ, "DDOS_API_KEYS": ANALYST, "DDOS_ADMIN_KEYS": ADMIN,
           "DDOS_IR_DATABASE_URL": f"sqlite:///{(work / 'ir.db').as_posix()}",
           "DDOS_PENDING_ACTIONS_PATH": str(work / "actions.json"), "DDOS_DEV_KEY_FILE": str(work / ".dev-keys"),
           "DDOS_LIVE_KEY": ANALYST, "DDOS_API_URL": base, "PYTHONIOENCODING": "utf-8"}
    procs = []
    log = (work / "processes.log").open("w", encoding="utf-8")
    try:
        procs.append(subprocess.Popen([sys.executable, "-m", "uvicorn", "src.api.app:app", "--host", "127.0.0.1",
                                       "--port", str(a.port)], cwd=REPO, env=env, stdout=log, stderr=log))
        wait_http(f"{base}/health")
        procs.append(subprocess.Popen([sys.executable, "scripts/live_bridge.py", str(replay_dir), "--reset"],
                                      cwd=REPO, env=env, stdout=log, stderr=log))
        time.sleep(3)
        node = shutil.which("node") or "node"
        shot = subprocess.Popen([node, str(REPO / "scripts" / "record_demo.mjs")], cwd=REPO / "dashboard", env={
            **env, "BASE": base, "FRAMES": str(frames_dir), "APPROVE_AFTER": str(a.approve_after),
            "DURATION": str(a.seconds + 8), "ANALYST": ANALYST, "ADMIN": ADMIN})
        time.sleep(4)  # the browser is on Live attack before the traffic starts
        cmd = [sys.executable, "scripts/pcap_replay_live.py", str(pcap), "--out", str(replay_dir), "--limit-s", str(a.seconds)]
        if (pcap.parent / "ovs_ports.jsonl").is_file():  # the switch counters of the same run, in step
            cmd += ["--ovs", str(pcap.parent / "ovs_ports.jsonl")]
        subprocess.run(cmd, cwd=REPO, env=env, check=True, stdout=log, stderr=log)
        if shot.wait(timeout=a.seconds + 120) != 0:
            raise SystemExit("browser script failed; see " + str(work / "processes.log"))
        frames = sorted(frames_dir.glob("*.png"))
        if not frames:
            raise SystemExit("no frames captured")
        caption = f"REPLAY of recorded lab traffic ({run_name}) · enforcer mocked · {a.speed:g}× speed"
        out = REPO / a.out
        build_gif(frames, out, caption, int(500 / a.speed), a.width)
        meta = json.loads((frames_dir / "events.json").read_text(encoding="utf-8")) if (frames_dir / "events.json").exists() else {}
        print(f"wrote {out} ({out.stat().st_size / 1e6:.1f} MB, {len(frames)} frames); events: {meta}")
        if out.stat().st_size > 10e6:
            print("warning: over 10 MB - try --width 800 or --speed 3")
    finally:
        for p in reversed(procs):
            p.terminate()
            try:
                p.wait(timeout=10)
            except subprocess.TimeoutExpired:
                p.kill()
        log.close()


if __name__ == "__main__":
    main()
