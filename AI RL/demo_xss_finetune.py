"""
Controlled Fine-Tuning Demo — XSS Real Data

Chứng minh controlled fine-tuning: model 40k ban đầu cần SafetyNet cứu khi
gặp XSS → thu thập dữ liệu thật từ xsser → fine-tune 65 giây → model tự quyết đúng.

Đây là Phase 2 của demo 3-terminal:
  Phase 1: infer.py --model 40k --label xss → xsser chạy → thấy [ESC from RateLimit]
  Phase 2: python3 demo_xss_finetune.py     → 65 giây fine-tune → save model
  Phase 3: infer.py --model finetuned       → xsser chạy → thấy Redirect (không ESC)

Usage:
    cd "AI RL"
    python3 demo_xss_finetune.py
    python3 demo_xss_finetune.py --real-data path/to/xss.jsonl
    python3 demo_xss_finetune.py --replay-steps 10000 --mock-steps 50000
    python3 demo_xss_finetune.py --no-train   # chỉ show BEFORE, không fine-tune
"""

import argparse
import logging
import os
import time

import numpy as np
import torch
from rich.console import Console
from rich.panel import Panel
from rich.progress import BarColumn, Progress, TextColumn, TimeRemainingColumn
from rich.table import Table
from rich.text import Text
from stable_baselines3 import PPO
from stable_baselines3.common.env_util import make_vec_env

from env_ids import (IDSDefenseEnv, MockIPBehavior, PerIPTemporalState,
                     normalize_observation, simulate_effect, compute_attack_signals)

BASE_DIR    = os.path.dirname(os.path.abspath(__file__))
CKPT_40K    = os.path.join(BASE_DIR, "runs", "run_34d_v13", "checkpoints", "model_40000_steps.zip")
OUT_DIR     = os.path.join(BASE_DIR, "runs", "run_finetune_xss")
OUT_MODEL   = os.path.join(OUT_DIR, "finetuned")
REAL_DATA   = os.path.join(BASE_DIR, "xss_real.jsonl")

ACTION_NAMES = ["Allow", "RateLimit", "Redirect", "Block"]
ACTION_CHARS = ["A", "L", "R", "B"]
ACTION_STYLES = ["bright_green", "yellow", "bright_cyan", "bright_red"]

console = Console()

# Suppress SB3 "Logging to ..." spam
logging.getLogger("stable_baselines3").setLevel(logging.WARNING)


# ── Trajectory builder (XSS variant of _make_attack_trajectory) ──────────────

def _make_xss_trajectory() -> list[dict]:
    """22-window XSS escalation path — mirrors _make_attack_trajectory() in demo_live_train.py."""
    rng    = np.random.default_rng(42)
    tstate = PerIPTemporalState()
    prev_effect = [0.0, 0.0, 0.0, 0.0]

    beh_benign = MockIPBehavior('benign',       rng=np.random.default_rng(0))
    beh_noisy  = MockIPBehavior('noisy_normal', rng=np.random.default_rng(1))
    beh_xss    = MockIPBehavior('xss',          rng=np.random.default_rng(2))

    # t01-05: benign warmup | t06-08: noisy | t09: XSS first contact (Allow OK)
    # t10-21: Redirect phase (12 windows → block_ready latches) | t22: Block
    SCRIPT = (
        [(0, beh_benign, 'benign',   0)] * 5  +
        [(1, beh_noisy,  'noisy',    1)] * 3  +
        [(0, beh_xss,    'start',    2)] * 1  +
        [(2, beh_xss,    'redirect', 2)] * 12 +
        [(3, beh_xss,    'block',    3)] * 1
    )

    trajectory = []
    for t, (action, beh, phase, expected) in enumerate(SCRIPT, start=1):
        raw      = beh.get_features()
        obs20    = normalize_observation(raw)
        temporal = tstate.to_obs()
        obs34    = np.concatenate([obs20,
                                   np.array(temporal,    dtype=np.float32),
                                   np.array(prev_effect, dtype=np.float32)])
        trajectory.append({"t": t, "phase": phase, "expected": expected, "obs": obs34})

        effect_t  = simulate_effect(action, raw, rng)
        l7_signal = compute_attack_signals(raw)['l7_presence']
        tstate.stage_action(action, l7_signal=l7_signal)
        tstate.observe_effect(effect_t)
        beh.apply_closed_loop_effect(action)
        beh.step_forward()
        prev_effect = effect_t

    return trajectory


# ── Model inference helpers ───────────────────────────────────────────────────

def _get_probs(model: PPO, obs: np.ndarray) -> np.ndarray:
    """Extract softmax probs from PPO policy. Pattern từ verify_rl_decision.py:117-120."""
    obs_t, _ = model.policy.obs_to_tensor(obs)
    with torch.no_grad():
        dist  = model.policy.get_distribution(obs_t)
        probs = dist.distribution.probs.cpu().numpy().flatten()
    return probs


def _poll_trajectory(model: PPO, trajectory: list[dict]) -> tuple[str, float, float]:
    """Query model on all trajectory windows. Returns (timeline, P(R@t09), P(R@t15))."""
    rows = [_get_probs(model, item["obs"]) for item in trajectory]
    timeline = "".join(ACTION_CHARS[int(p.argmax())] for p in rows)
    return timeline, float(rows[8][2]), float(rows[14][2])   # t09=idx8, t15=idx14


def _fresh_probs(model: PPO, ip_type: str) -> np.ndarray:
    """Single fresh obs (no temporal history) for regression check."""
    beh = MockIPBehavior(ip_type, rng=np.random.default_rng(0))
    obs = np.concatenate([normalize_observation(beh.get_features()),
                          np.zeros(14, dtype=np.float32)])
    return _get_probs(model, obs.astype(np.float32))


# ── Display helpers ───────────────────────────────────────────────────────────

def _fmt_timeline(timeline: str) -> Text:
    """Colorise timeline string."""
    txt = Text()
    for i, ch in enumerate(timeline):
        t = i + 1
        style = ACTION_STYLES[ACTION_CHARS.index(ch)]
        txt.append(ch, style=style)
        if t in (5, 8, 9, 21):
            txt.append(" ", style="default")
    return txt


def _print_section(label: str, timeline: str, p_r09: float, p_r15: float, model: PPO):
    """Print BEFORE or AFTER block."""
    AC = ACTION_CHARS
    idx09 = 8   # t09
    ok09  = "✓" if timeline[idx09] == "R" else "✗"
    style09 = "bright_cyan" if timeline[idx09] == "R" else "red"

    table = Table(box=None, show_header=False, padding=(0, 1))
    table.add_column(style="bold white")
    table.add_column()

    tl_text = _fmt_timeline(timeline)
    table.add_row("Timeline:", tl_text)
    table.add_row("         ",
                  Text("t01-05  t06-08  t09  t10-21             t22",
                       style="dim"))
    table.add_row(f"P(Redirect@t09):",
                  Text(f"{p_r09:.3f}  {ok09}", style=style09))
    table.add_row("P(Redirect@t15):",
                  Text(f"{p_r15:.3f}", style="bright_cyan" if p_r15 > 0.5 else "yellow"))

    console.print(Panel(table, title=f"[bold]{label}[/bold]", border_style="dim"))


def _print_regression(model_b: PPO, model_a: PPO):
    """Regression check table."""
    CHECKS = [
        ("benign",      "bright_green", 0),
        ("sqli",        "bright_cyan",  2),
        ("syn_flood",   "bright_red",   3),
        ("brute_force", "bright_cyan",  2),
    ]
    table = Table(title="Regression check (fresh obs)", box=None, padding=(0, 2))
    table.add_column("Traffic",    style="bold white")
    table.add_column("BEFORE",     justify="left")
    table.add_column("AFTER",      justify="left")
    table.add_column("OK?",        justify="center")

    for ip_type, _style, expected in CHECKS:
        pb = _fresh_probs(model_b, ip_type)
        pa = _fresh_probs(model_a, ip_type)
        ab = ACTION_NAMES[int(pb.argmax())]
        aa = ACTION_NAMES[int(pa.argmax())]
        ok = "✓↑" if pa.argmax() == expected else ("✓" if pb.argmax() == expected else "✗")
        before_str = f"{ab}({pb[int(pb.argmax())]:.2f})"
        after_str  = f"{aa}({pa[int(pa.argmax())]:.2f})"
        table.add_row(ip_type, before_str, after_str, ok)

    console.print(table)


# ── Fine-tune progress callback ───────────────────────────────────────────────

class _ProgressCallback:
    """Minimal callback-compatible class for tracking fine-tune progress."""
    def __init__(self, progress: Progress, task_id, label: str):
        self.progress  = progress
        self.task_id   = task_id
        self.label     = label
        self._steps    = 0

    def update(self, n_steps: int):
        self._steps += n_steps
        self.progress.update(self.task_id, advance=n_steps)


# ── Main ──────────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(description="XSS Controlled Fine-Tuning Demo")
    parser.add_argument("--real-data",     default=REAL_DATA,
                        help="Path to xss_real.jsonl (pre-collected from infer.py + xsser)")
    parser.add_argument("--replay-steps",  type=int, default=10_000,
                        help="Steps for Phase 1 replay fine-tune (default: 10000)")
    parser.add_argument("--mock-steps",    type=int, default=30_000,
                        help="Steps for Phase 2 mock stabilization (default: 30000 → total 80k matches checkpoint B)")
    parser.add_argument("--no-train",      action="store_true",
                        help="Only show BEFORE metrics, skip fine-tuning")
    args = parser.parse_args()

    console.rule("[bold cyan]CONTROLLED FINE-TUNING  |  XSS  |  40k → adapted[/bold cyan]")

    # ── [1/5] Load base model ────────────────────────────────────────────────
    console.print("\n[1/5] Loading base model (40k)...", end=" ")
    model_before = PPO.load(CKPT_40K, device="cpu")
    console.print("[bright_green]✓[/bright_green]")

    # ── [2/5] Build trajectory & show BEFORE ────────────────────────────────
    console.print("[2/5] Building XSS trajectory (22 windows)...", end=" ")
    trajectory = _make_xss_trajectory()
    console.print("[bright_green]✓[/bright_green]")

    tl_b, p_r09_b, p_r15_b = _poll_trajectory(model_before, trajectory)
    console.print()
    _print_section("BEFORE fine-tune (40k)", tl_b, p_r09_b, p_r15_b, model_before)

    if args.no_train:
        console.print("\n[dim]--no-train: exiting before fine-tune.[/dim]")
        return

    # ── [3/5] Phase 1: replay fine-tune on real data ─────────────────────────
    if not os.path.isfile(args.real_data):
        console.print(f"\n[red]Error: real data file not found: {args.real_data}[/red]")
        console.print("[dim]Collect it first:[/dim]")
        console.print(f"  python3 infer.py --watch /tmp/sniffer.jsonl "
                      f"--label xss --training-data {args.real_data}")
        return

    chunk = 2048 * 4  # one rollout buffer (n_steps × n_envs)

    # ── Train model: real + mock ──────────────────────────────────────────────
    console.print(f"\n[3/5] Real+Mock ({args.replay_steps:,} real + {args.mock_steps:,} mock)...")
    with Progress(TextColumn("{task.description}"), BarColumn(bar_width=30),
                  TextColumn("{task.completed}/{task.total}"), TimeRemainingColumn(),
                  console=console) as prog:
        total_steps = args.replay_steps + args.mock_steps
        task = prog.add_task("  real+mock", total=total_steps)
        model_ft = PPO.load(CKPT_40K,
                            env=make_vec_env(
                                lambda: IDSDefenseEnv(mode="replay", training_data=args.real_data),
                                n_envs=4),
                            device="cpu", custom_objects={"tensorboard_log": None}, verbose=0)
        done = 0
        while done < args.replay_steps:
            n = min(chunk, args.replay_steps - done)
            model_ft.learn(n, reset_num_timesteps=False, progress_bar=False, log_interval=9999)
            done += n
            prog.update(task, completed=done)
        model_ft.set_env(make_vec_env(lambda: IDSDefenseEnv(mode="mock"), n_envs=4))
        while done < total_steps:
            n = min(chunk, total_steps - done)
            model_ft.learn(n, reset_num_timesteps=False, progress_bar=False, log_interval=9999)
            done += n
            prog.update(task, completed=done)

    # ── [5/5] AFTER metrics & regression ─────────────────────────────────────
    tl_a, p_r09_a, p_r15_a = _poll_trajectory(model_ft, trajectory)

    console.print()
    _print_section("BEFORE (40k base)",     tl_b, p_r09_b, p_r15_b, model_before)
    _print_section("AFTER  (finetuned)",    tl_a, p_r09_a, p_r15_a, model_ft)

    delta09 = (p_r09_a - p_r09_b) / max(p_r09_b, 1e-6) * 100
    delta15 = (p_r15_a - p_r15_b) / max(p_r15_b, 1e-6) * 100
    summary = Table(box=None, show_header=True, padding=(0, 2))
    summary.add_column("Metric",    style="bold white")
    summary.add_column("BEFORE",    justify="right")
    summary.add_column("AFTER",     justify="right")
    summary.add_column("Δ",         justify="right")
    summary.add_row("P(Redirect@t09)", f"{p_r09_b:.3f}", f"{p_r09_a:.3f}",
                    Text(f"{delta09:+.0f}%", style="bright_cyan"))
    summary.add_row("P(Redirect@t15)", f"{p_r15_b:.3f}", f"{p_r15_a:.3f}",
                    Text(f"{delta15:+.0f}%", style="bright_cyan"))
    console.print(summary)
    console.print()
    _print_regression(model_before, model_ft)

    # Save treatment model
    os.makedirs(OUT_DIR, exist_ok=True)
    model_ft.save(OUT_MODEL)
    console.print(f"\n[bright_green]Model saved:[/bright_green] {OUT_MODEL}.zip")
    console.print("\nRestart infer.py với model đã fine-tune:")
    console.print(f"  [dim]python3 infer.py --watch /tmp/sniffer.jsonl "
                  f"--model runs/run_finetune_xss/finetuned[/dim]")
    console.rule()


if __name__ == "__main__":
    main()
