"""
Live Policy Evolution Demo — RL Defense Agent

Replay lịch sử training của run_34d_v13: load từng checkpoint theo thứ tự,
hiển thị rich terminal dashboard để thấy policy π(a|s) thay đổi real-time.

Mode mặc định dùng cùng một attack trajectory cố định cho mọi checkpoint.
Điều này chứng minh policy evolution: cùng chuỗi evidence, checkpoint non trẻ
có thể chỉ Redirect, checkpoint sau training học được Redirect → Block.

Usage:
    cd "AI RL"
    python3 demo_live_train.py                    # replay trajectory 40k → final
    python3 demo_live_train.py --delay 2.0        # dừng 2s giữa các checkpoint
    python3 demo_live_train.py --from 120000      # bắt đầu từ checkpoint cụ thể
    python3 demo_live_train.py --mode fixed-state # mode cũ: fixed state rời rạc
"""

import argparse
import csv
import os
import time

os.environ.setdefault("MPLCONFIGDIR", "/tmp/matplotlib")

import matplotlib.pyplot as plt
from matplotlib.colors import ListedColormap
import numpy as np
import torch as th
from rich.console import Console
from rich.live import Live
from rich.panel import Panel
from rich.table import Table
from rich.text import Text
from stable_baselines3 import PPO

from env_ids import (IDSDefenseEnv, MockIPBehavior, PerIPTemporalState,
                     normalize_observation, simulate_effect, compute_attack_signals)

# ─── Constants ────────────────────────────────────────────────────────────────

BASE_DIR     = os.path.dirname(os.path.abspath(__file__))
RUN_DIR      = os.path.join(BASE_DIR, "runs", "run_34d_v13")
CKPT_DIR     = os.path.join(RUN_DIR, "checkpoints")
ACTION_NAMES = ["Allow", "RateLimit", "Redirect", "Block"]
ACTION_SHORT = ["Allow", "Limit", "Redirect", "Block"]
ACTION_CHARS = ["A", "L", "R", "B"]  # Allow, rateLimit, Redirect, Block
ACTION_STYLES = ["bright_green", "yellow", "bright_cyan", "bright_red"]
ACTION_GLYPHS = ["■", "■", "■", "■"]
OBS_LABELS = [
    "F01_PacketRate", "F02_SynAckRatio", "F03_InterArrivalTime", "F04_RstRatio",
    "F05_DistinctPorts", "F06_URLConcentration", "F07_HttpIatUniformity",
    "F08_RequestSizeUniformity", "F09_AvgPayloadSize", "F10_FwdBwdRatio",
    "F11_PacketsPerPort", "F12_SqlSpecialChar", "F13_CrsSqliScore",
    "F14_SqlUnionSelect", "F15_SqlComment", "F16_SqlStackedQuery",
    "F17_SqlSelectCount", "F18_CrsXssScore", "F19_JsFunctionCall",
    "F20_HtmlEventHandler",
    "T01_LastAllow", "T02_LastRateLimit", "T03_LastRedirect", "T04_LastBlock",
    "T05_ActionHold", "T06_DamageEma", "T07_EffectTrend", "T08_WindowFill",
    "T09_EscalationScore", "T10_MissBudget",
    "E01_WebHitRatio", "E02_HoneypotHitRatio", "E03_PresenceRatio",
    "E04_ServiceDamage",
]
ACTION_CORRECT = {
    "benign":       0,
    "noisy_normal": 1,
    "brute_force":  2,
    "sqli":         2,
    "xss":          2,
    "syn_flood":    3,
    "scan":         3,
}
TEST_TYPES = list(ACTION_CORRECT.keys())

# ─── Fixed attack trajectory ──────────────────────────────────────────────────

PHASES = [
    ("Benign", 1, 5, 0),
    ("Noisy", 6, 8, 1),
    ("AttackStart", 9, 9, 2),
    ("Redirect", 10, 21, 2),
    ("Block", 22, 22, 3),
]


def _make_attack_trajectory() -> list[dict]:
    """Canonical 23-window brute-force escalation path.

    Fully simulated using env_ids.py primitives — no hardcoded numbers:
      - MockIPBehavior  → 20D sensor features (same generator as training)
      - PerIPTemporalState.to_obs() → 10D temporal slice
      - simulate_effect() → 4D closed-loop feedback (same function as training)
      - compute_attack_signals() → l7_signal (same formula as env.step)

    Action script (scripted agent, represents realistic operator behaviour):
      t01-05  benign         Allow     (clean traffic, no threat)
      t06-08  noisy_normal   RateLimit (elevated but ambiguous)
      t09     brute_force    Allow     (attack just started, signal not yet clear)
      t10-21  brute_force    Redirect  (12 Redirect windows; block_ready latches after t21)
      t22     brute_force    Block     (block_ready latched, decision window)
    """
    rng = np.random.default_rng(42)
    tstate = PerIPTemporalState()
    prev_effect = [0.0, 0.0, 0.0, 0.0]

    beh_benign = MockIPBehavior('benign',       rng=np.random.default_rng(0))
    beh_noisy  = MockIPBehavior('noisy_normal', rng=np.random.default_rng(1))
    beh_brute  = MockIPBehavior('brute_force',  rng=np.random.default_rng(2))

    # (action, behavior, phase_label, expected_action)
    SCRIPT = (
        [(0, beh_benign, 'benign',          0)] * 5   +   # t01-05
        [(1, beh_noisy,  'noisy',           1)] * 3   +   # t06-08
        [(0, beh_brute,  'attack-start',    2)] * 1   +   # t09
        [(2, beh_brute,  'attack-redirect', 2)] * 12  +   # t10-21
        [(3, beh_brute,  'block',           3)] * 1       # t22
    )

    trajectory = []
    for t, (action, beh, phase, expected) in enumerate(SCRIPT, start=1):
        raw = beh.get_features()

        # Build obs from the current state, which already includes the previous
        # window's scripted action/effect. This mirrors the delayed-feedback
        # semantics of IDSDefenseEnv: effect_t becomes visible in obs_{t+1}.
        obs20     = normalize_observation(raw)
        temporal  = tstate.to_obs()
        obs34     = np.concatenate([obs20,
                                    np.array(temporal,     dtype=np.float32),
                                    np.array(prev_effect,  dtype=np.float32)])

        trajectory.append({"t": t, "phase": phase, "expected": expected, "obs": obs34})

        # Update state AFTER obs — mirrors env.step() order
        effect_t  = simulate_effect(action, raw, rng)
        l7_signal = compute_attack_signals(raw)['l7_presence']
        tstate.stage_action(action, l7_signal=l7_signal)
        tstate.observe_effect(effect_t)
        beh.apply_closed_loop_effect(action)
        beh.step_forward()
        prev_effect = effect_t

    return trajectory

# ─── Fixed test observations ───────────────────────────────────────────────────

def _make_fixed_obs() -> dict:
    """Một obs đại diện mỗi loại traffic — không đổi suốt demo.
    Tất cả checkpoints nhìn vào đúng cùng obs này → so sánh π(a|s) fair.
    """
    env = IDSDefenseEnv(mode="mock", seed=0)
    fixed = {}
    for ip_type in TEST_TYPES:
        beh = MockIPBehavior(ip_type, rng=np.random.default_rng(0))
        for _ in range(15):
            beh.step_forward()
        raw   = beh.get_features()
        obs20 = env._normalize_features(raw)[:20]
        obs34 = np.concatenate([obs20, np.zeros(14)]).astype(np.float32)
        fixed[ip_type] = obs34
    return fixed


def _poll_probs(model, fixed_obs: dict) -> tuple[dict, dict]:
    """Lấy π(a|s) trực tiếp từ softmax của policy network — không sample."""
    probs_map  = {}
    action_map = {}
    for ip_type, obs in fixed_obs.items():
        obs_t, _ = model.policy.obs_to_tensor(obs)
        with th.no_grad():
            dist  = model.policy.get_distribution(obs_t)
            probs = dist.distribution.probs.cpu().numpy().flatten()
        probs_map[ip_type]  = probs.tolist()
        action_map[ip_type] = int(probs.argmax())
    return probs_map, action_map


def _policy_probs(model, obs: np.ndarray) -> list[float]:
    obs_t, _ = model.policy.obs_to_tensor(obs)
    with th.no_grad():
        dist = model.policy.get_distribution(obs_t)
        probs = dist.distribution.probs.cpu().numpy().flatten()
    return probs.tolist()


def _poll_trajectory(model, trajectory: list[dict]) -> dict:
    probs = [_policy_probs(model, row["obs"]) for row in trajectory]
    actions = [int(np.argmax(p)) for p in probs]
    expected = [None if row["expected"] is None else int(row["expected"]) for row in trajectory]
    first_block = next((i + 1 for i, a in enumerate(actions) if a == 3), None)
    first_block_idx = next((i for i, row in enumerate(trajectory) if row["expected"] == 3), None)
    scored = [(a, e) for a, e in zip(actions, expected) if e is not None]
    return {
        "probs": probs,
        "actions": actions,
        "timeline": "".join(ACTION_CHARS[a] for a in actions),
        "first_block": first_block,
        "correct": sum(1 for a, e in scored if a == e),
        "scored_steps": len(scored),
        "decision_p_block": float(probs[first_block_idx][3]) if first_block_idx is not None else 0.0,
    }


def _kl_divergence(p: list, q: list, eps: float = 1e-8) -> float:
    """KL(p || q) — đo policy shift từ baseline p sang current q."""
    p = np.array(p, dtype=np.float64) + eps
    q = np.array(q, dtype=np.float64) + eps
    p /= p.sum()
    q /= q.sum()
    return float(np.sum(p * np.log(p / q)))


def _trajectory_kl(base_probs: list[list[float]], cur_probs: list[list[float]]) -> float:
    return float(np.mean([
        _kl_divergence(base, cur)
        for base, cur in zip(base_probs, cur_probs)
    ]))


def _group_timeline(timeline: str) -> str:
    return timeline


def _colored_timeline(timeline: str) -> Text:
    """Color each fixed trajectory phase, not the whole row."""
    text = Text()
    spans = [
        (0, 5, "green"),       # t01-05 benign
        (5, 8, "yellow"),      # t06-08 noisy
        (8, 9, "magenta"),     # t09 attack start
        (9, 21, "cyan"),       # t10-21 redirect/honeypot evidence
        (21, 22, "red"),       # t22 block
    ]
    for idx, (start, end, style) in enumerate(spans):
        if idx > 0:
            text.append("|", style="dim")
        text.append(timeline[start:end], style=style)
    return text


def _action_heatmap(timeline: str) -> Text:
    """Compact visual row: color shows action, separators show traffic phases."""
    text = Text()
    cuts = {5, 8, 9, 21}
    for idx, char in enumerate(timeline):
        if idx in cuts:
            text.append("|", style="dim")
        action = ACTION_CHARS.index(char)
        text.append(ACTION_GLYPHS[action], style=f"bold {ACTION_STYLES[action]}")
    return text


def _prob_cell(value: float, action: int) -> Text:
    styles = ["green", "yellow", "cyan", "red"]
    cell = Text()
    cell.append(f"{value:.2f}", style=styles[action] if value >= 0.5 else "white")
    return cell


def _render_phase_distribution(record: dict, trajectory: list[dict]) -> Table:
    phase_table = Table(show_header=True, header_style="bold magenta", box=None, padding=(0, 1))
    phase_table.add_column("Phase", style="cyan", width=14, no_wrap=True)
    phase_table.add_column("Target", width=8, no_wrap=True)
    phase_table.add_column("Top", width=8, no_wrap=True)
    phase_table.add_column("P(A)", justify="right", width=6, no_wrap=True)
    phase_table.add_column("P(L)", justify="right", width=6, no_wrap=True)
    phase_table.add_column("P(R)", justify="right", width=6, no_wrap=True)
    phase_table.add_column("P(B)", justify="right", width=6, no_wrap=True)

    probs = record["probs"]
    actions = record["actions"]
    for name, start, end, expected in PHASES:
        idxs = range(start - 1, end)
        avg = np.mean([probs[i] for i in idxs], axis=0)
        top = int(np.argmax(avg))
        top_style = "dim" if expected is None else "green" if top == expected else "red"
        phase_table.add_row(
            f"t{start:02d} {name}" if start == end else f"t{start:02d}-{end:02d} {name}",
            "Observe" if expected is None else ACTION_SHORT[expected],
            Text(ACTION_SHORT[top], style=top_style),
            _prob_cell(float(avg[0]), 0),
            _prob_cell(float(avg[1]), 1),
            _prob_cell(float(avg[2]), 2),
            _prob_cell(float(avg[3]), 3),
        )
    return phase_table


def _phase_flow(record: dict) -> tuple[str, str]:
    dominant = []
    p_block = []
    for _, start, end, expected in PHASES:
        if expected is None:
            continue
        idxs = range(start - 1, end)
        avg = np.mean([record["probs"][i] for i in idxs], axis=0)
        dominant.append(ACTION_SHORT[int(np.argmax(avg))])
        p_block.append(f"{float(avg[3]):.2f}")
    return " -> ".join(dominant), " -> ".join(p_block)


def _save_evolution_plot(records: list[dict], out_path: str):
    labels = [rec["label"] for rec in records]
    actions = np.array([rec["actions"] for rec in records], dtype=int)
    p_block = np.array([[p[3] for p in rec["probs"]] for rec in records], dtype=float)
    n_steps = actions.shape[1]

    cmap_actions = ListedColormap(["#2ca02c", "#f1c40f", "#17becf", "#d62728"])
    fig, axes = plt.subplots(
        2, 1, figsize=(13.5, max(6.0, 0.38 * len(records) + 3.0)),
        gridspec_kw={"height_ratios": [1.15, 1.0]},
        constrained_layout=True,
    )

    axes[0].imshow(actions, aspect="auto", interpolation="nearest",
                   cmap=cmap_actions, vmin=0, vmax=3)
    axes[0].set_title(f"Policy action evolution on the same {n_steps}-window attack trajectory",
                      fontsize=14, weight="bold")
    axes[0].set_ylabel("Checkpoint")
    axes[0].set_yticks(range(len(labels)))
    axes[0].set_yticklabels(labels)
    axes[0].set_xticks([0, 4, 7, 8, 20, 22])
    axes[0].set_xticklabels(["t01", "t05", "t08", "t09", "t21", "t22"])

    im = axes[1].imshow(p_block, aspect="auto", interpolation="nearest",
                        cmap="Reds", vmin=0, vmax=1)
    axes[1].set_title("P(Block) over time", fontsize=12, weight="bold")
    axes[1].set_xlabel("Trajectory timestep")
    axes[1].set_ylabel("Checkpoint")
    axes[1].set_yticks(range(len(labels)))
    axes[1].set_yticklabels(labels)
    axes[1].set_xticks([0, 4, 7, 8, 20, 22])
    axes[1].set_xticklabels(["t01", "t05", "t08", "t09", "t21", "t22"])
    fig.colorbar(im, ax=axes[1], fraction=0.025, pad=0.01, label="P(Block)")

    for ax in axes:
        for cut in [4.5, 7.5, 8.5, 20.5]:
            ax.axvline(cut, color="white", linewidth=1.6)
        ax.text(2, -0.9, "benign", ha="center", va="center", fontsize=9)
        ax.text(6, -0.9, "noisy", ha="center", va="center", fontsize=9)
        ax.text(8, -0.9, "start", ha="center", va="center", fontsize=9)
        ax.text(14.5, -0.9, "redirect/honeypot", ha="center", va="center", fontsize=9)
        ax.text(21.5, -0.9, "block", ha="center", va="center", fontsize=9)

    legend_handles = [
        plt.Rectangle((0, 0), 1, 1, color="#2ca02c", label="Allow"),
        plt.Rectangle((0, 0), 1, 1, color="#f1c40f", label="RateLimit"),
        plt.Rectangle((0, 0), 1, 1, color="#17becf", label="Redirect"),
        plt.Rectangle((0, 0), 1, 1, color="#d62728", label="Block"),
    ]
    axes[0].legend(handles=legend_handles, loc="upper right", ncol=4, frameon=False)
    fig.savefig(out_path, dpi=180)
    plt.close(fig)


def _dump_trajectory_csv(trajectory: list[dict], out_path: str):
    with open(out_path, "w", newline="") as f:
        writer = csv.writer(f)
        writer.writerow(["t", "phase", "target_action", *OBS_LABELS])
        for row in trajectory:
            obs = np.asarray(row["obs"], dtype=np.float32)
            writer.writerow([
                row["t"],
                row["phase"],
                "Observe" if row["expected"] is None else ACTION_NAMES[int(row["expected"])],
                *[f"{float(v):.6f}" for v in obs],
            ])


def _validate_trajectory(trajectory: list[dict]):
    if len(trajectory) != 22:
        raise ValueError(f"Expected 22 trajectory steps, got {len(trajectory)}")
    for idx, row in enumerate(trajectory, start=1):
        if row.get("t") != idx:
            raise ValueError(f"Trajectory timestep mismatch at row {idx}: {row.get('t')}")
        obs = np.asarray(row.get("obs"), dtype=np.float32)
        if obs.shape != (34,):
            raise ValueError(f"t={idx}: expected obs shape (34,), got {obs.shape}")
        if not np.all(np.isfinite(obs)):
            raise ValueError(f"t={idx}: obs contains NaN/Inf")
        if np.any(obs < 0.0) or np.any(obs > 1.0):
            raise ValueError(f"t={idx}: obs outside [0,1]")
        if not np.isclose(obs[20:24].sum(), 1.0, atol=1e-5):
            raise ValueError(f"t={idx}: last-action one-hot invalid: {obs[20:24]}")


# ─── Rich renderer ─────────────────────────────────────────────────────────────

def _render(step: int, total_steps: int, ckpt_idx: int, n_ckpts: int,
            probs_map: dict, action_map: dict,
            prev_actions: dict | None,
            baseline_probs: dict | None) -> Panel:

    pct      = step / max(total_steps, 1)
    bar_len  = 28
    filled   = int(bar_len * pct)
    prog_bar = "█" * filled + "░" * (bar_len - filled)

    # ── Header ────────────────────────────────────────────────────────────────
    header = Text()
    header.append("LIVE POLICY UPDATE — RL DEFENSE AGENT", style="bold cyan")
    header.append(f"   checkpoint {ckpt_idx}/{n_ckpts}  (step {step:,})", style="bold white")
    header.append(f"\n{prog_bar}  {pct*100:.0f}%", style="green")

    # ── Policy table ──────────────────────────────────────────────────────────
    show_kl = baseline_probs is not None and ckpt_idx > 1

    pol = Table(show_header=True, header_style="bold magenta", box=None, padding=(0, 1))
    pol.add_column("Traffic",    style="cyan", width=14)
    pol.add_column("Allow",      justify="right", width=7)
    pol.add_column("RateLim",    justify="right", width=8)
    pol.add_column("Redirect",   justify="right", width=9)
    pol.add_column("Block",      justify="right", width=7)
    pol.add_column("π(a|s)",     width=14)
    if show_kl:
        pol.add_column("KL vs 40k", justify="right", width=10)

    total_kl = 0.0
    for ip_type in TEST_TYPES:
        probs  = probs_map[ip_type]
        action = action_map[ip_type]
        expect = ACTION_CORRECT[ip_type]
        correct = (action == expect)

        changed  = (prev_actions is not None and prev_actions.get(ip_type) != action)
        mark     = "✓" if correct else "✗"
        color    = "green" if correct else "red"
        arrow    = " ←" if changed else ""
        decision = Text(f"{ACTION_NAMES[action]} {mark}{arrow}", style=color)

        row = [
            ip_type,
            f"{probs[0]:.2f}",
            f"{probs[1]:.2f}",
            f"{probs[2]:.2f}",
            f"{probs[3]:.2f}",
            decision,
        ]
        if show_kl:
            kl = _kl_divergence(baseline_probs[ip_type], probs)
            total_kl += kl
            kl_color = "green" if kl > 0.3 else "yellow" if kl > 0.05 else "dim"
            row.append(Text(f"{kl:.3f}", style=kl_color))

        pol.add_row(*row)

    # ── Footer note ───────────────────────────────────────────────────────────
    note = Text()
    note.append("P = π(a|s)", style="bold")
    note.append(" — softmax trực tiếp từ policy network  |  ", style="dim")
    note.append("fixed state", style="bold")
    note.append(" cho mọi checkpoint  |  ", style="dim")
    if show_kl:
        kl_color = "green" if total_kl > 1.5 else "yellow" if total_kl > 0.3 else "dim"
        note.append("ΣKL vs 40k: ", style="dim")
        note.append(f"{total_kl:.3f}", style=kl_color)

    # ── Compose ───────────────────────────────────────────────────────────────
    content = Table.grid()
    content.add_row(header)
    content.add_row(Text(""))
    content.add_row(Text("CÙNG STATE s — π(a|s) THAY ĐỔI THEO TRAINING", style="bold yellow"))
    content.add_row(pol)
    content.add_row(Text(""))
    content.add_row(note)

    return Panel(content,
                 title="[bold blue]Demo: Policy π(a|s) — run_34d_v13[/bold blue]",
                 border_style="blue")


def _render_trajectory(step_label: str, ckpt_idx: int, n_ckpts: int,
                       records: list[dict], baseline_probs: list[list[float]],
                       trajectory: list[dict]) -> Panel:
    header = Text()
    header.append("POLICY EVOLUTION ON SAME ATTACK TRAJECTORY", style="bold cyan")
    header.append(f"   checkpoint {ckpt_idx}/{n_ckpts}  ({step_label})", style="bold white")
    header.append("\nLegend: ", style="dim")
    header.append("■ Allow", style="bold bright_green")
    header.append(" | ", style="dim")
    header.append("■ RateLimit", style="bold yellow")
    header.append(" | ", style="dim")
    header.append("■ Redirect", style="bold bright_cyan")
    header.append(" | ", style="dim")
    header.append("■ Block", style="bold bright_red")

    phases = Text()
    phases.append("1-5 benign", style="green")
    phases.append(" | ", style="dim")
    phases.append("6-8 noisy", style="yellow")
    phases.append(" | ", style="dim")
    phases.append("9 attack-start", style="magenta")
    phases.append(" | ", style="dim")
    phases.append("10-21 redirect/evidence", style="cyan")
    phases.append(" | ", style="dim")
    phases.append("22 block", style="red")

    table = Table(show_header=True, header_style="bold magenta", box=None, padding=(0, 1))
    table.add_column("Ckpt", style="cyan", width=5)
    table.add_column("Action heatmap t01→t22", width=27, no_wrap=True)
    table.add_column("Block t", justify="right", width=7, no_wrap=True)
    table.add_column("OK", justify="right", width=5)
    table.add_column("P(Block)", justify="right", width=8, no_wrap=True)

    for rec in records:
        first_block = rec["first_block"]
        first_block_s = str(first_block) if first_block is not None else "-"
        table.add_row(
            rec["label"],
            _action_heatmap(_group_timeline(rec["timeline"])),
            first_block_s,
            f"{rec['correct']}/{rec['scored_steps']}",
            f"{rec['decision_p_block']:.2f}",
        )

    current = records[-1]
    shift = 0.0 if len(records) == 1 else _trajectory_kl(baseline_probs, current["probs"])
    phase_dist = _render_phase_distribution(current, trajectory)
    dominant_flow, block_flow = _phase_flow(current)

    note = Text()
    note.append("Adaptive readout: ", style="bold")
    note.append("same traffic path, but action distribution changes by phase. ", style="dim")
    note.append("Policy shift (KL) vs 40k: ", style="dim")
    note.append(f"{shift:.3f}", style="green" if shift > 0.7 else "yellow" if shift > 0.2 else "dim")

    content = Table.grid()
    content.add_row(header)
    content.add_row(Text(""))
    content.add_row(phases)
    content.add_row(Text(""))
    content.add_row(table)
    content.add_row(Text(""))
    content.add_row(Text(f"CURRENT CHECKPOINT PHASE DISTRIBUTION — {current['label']}",
                         style="bold yellow"))
    content.add_row(phase_dist)
    content.add_row(Text(""))
    flow = Text()
    flow.append("Path: ", style="dim")
    flow.append(dominant_flow, style="bold")
    flow.append("   |   P(Block): ", style="dim")
    flow.append(block_flow, style="bold red")
    content.add_row(flow)
    content.add_row(Text(""))
    content.add_row(note)
    return Panel(content,
                 title="[bold blue]Demo: Policy Evolution — run_34d_v13[/bold blue]",
                 border_style="blue")


# ─── Main ─────────────────────────────────────────────────────────────────────

def parse_args():
    p = argparse.ArgumentParser()
    p.add_argument("--mode", choices=["trajectory", "fixed-state"], default="trajectory",
                   help="trajectory = cùng attack path qua checkpoints; fixed-state = mode cũ")
    p.add_argument("--delay", type=float, default=3.0,
                   help="Giây dừng giữa các checkpoint (default: 3.0)")
    p.add_argument("--from",  dest="from_step", type=int, default=0,
                   help="Bắt đầu từ checkpoint step cụ thể (vd: 120000)")
    p.add_argument("--no-final", action="store_true",
                   help="Không replay final_model.zip sau checkpoint cuối")
    p.add_argument("--plot", default=os.path.join(RUN_DIR, "policy_evolution_trajectory.png"),
                   help="Đường dẫn PNG heatmap xuất ra sau replay trajectory")
    p.add_argument("--dump-trajectory",
                   default=os.path.join(RUN_DIR, "policy_evolution_trajectory_34d.csv"),
                   help="Đường dẫn CSV dump observation vector 34D của trajectory")
    return p.parse_args()


def _load_checkpoint_names(args) -> tuple[list[str], list[int]]:
    ckpts = sorted(
        [f for f in os.listdir(CKPT_DIR) if f.endswith(".zip")],
        key=lambda f: int(f.replace("model_", "").replace("_steps.zip", ""))
    )
    if args.from_step > 0:
        ckpts = [c for c in ckpts
                 if int(c.replace("model_", "").replace("_steps.zip", "")) >= args.from_step]

    steps = [int(c.replace("model_", "").replace("_steps.zip", "")) for c in ckpts]
    return ckpts, steps


def _run_fixed_state_replay(args, console: Console, ckpts: list[str], steps: list[int]):
    total_steps = max(steps)
    n_ckpts = len(ckpts)
    console.print("[bold cyan]RL Defense Agent — Live Policy Replay[/bold cyan]")
    console.print(f"  Run        : {RUN_DIR}")
    console.print(f"  Checkpoints: {n_ckpts}  ({steps[0]:,} → {steps[-1]:,} steps)")
    console.print(f"  Delay      : {args.delay}s giữa các checkpoint\n")

    console.print("[dim]Preparing fixed observations (seed=0, warmup=15)…[/dim]")
    fixed_obs = _make_fixed_obs()
    console.print("[green]✓ Fixed state set sẵn sàng — tất cả checkpoints dùng cùng input[/green]\n")
    time.sleep(1.0)

    # Checkpoint đầu tiên — dùng làm baseline KL
    first_path           = os.path.join(CKPT_DIR, ckpts[0])
    model                = PPO.load(first_path, verbose=0)
    probs_map, action_map = _poll_probs(model, fixed_obs)
    baseline_probs       = {t: list(p) for t, p in probs_map.items()}  # freeze step 40k
    prev_actions         = None

    with Live(
        _render(steps[0], total_steps, 1, n_ckpts,
                probs_map, action_map, prev_actions, baseline_probs),
        refresh_per_second=4,
        console=console,
    ) as live:
        for i, (ckpt_file, step) in enumerate(zip(ckpts, steps)):
            if i > 0:
                ckpt_path             = os.path.join(CKPT_DIR, ckpt_file)
                prev_actions          = dict(action_map)
                model                 = PPO.load(ckpt_path, verbose=0)
                probs_map, action_map = _poll_probs(model, fixed_obs)
                live.update(
                    _render(step, total_steps, i + 1, n_ckpts,
                            probs_map, action_map, prev_actions, baseline_probs)
                )

            time.sleep(args.delay)

    console.print("\n[bold green]Replay hoàn tất![/bold green]")

    # Bảng tóm tắt KL shift
    console.print("\n[bold yellow]Policy shift summary (KL vs checkpoint 40k):[/bold yellow]")
    t = Table()
    t.add_column("Traffic")
    t.add_column("π(a|s) tại 40k")
    t.add_column("π(a|s) tại final")
    t.add_column("KL divergence")
    t.add_column("")
    for ip_type in TEST_TYPES:
        base   = baseline_probs[ip_type]
        final  = probs_map[ip_type]
        kl     = _kl_divergence(base, final)
        action = action_map[ip_type]
        expect = ACTION_CORRECT[ip_type]
        t.add_row(
            ip_type,
            str([f"{p:.2f}" for p in base]),
            str([f"{p:.2f}" for p in final]),
            f"{kl:.3f}",
            "[green]✓[/green]" if action == expect else "[red]✗[/red]",
        )
    console.print(t)


def _run_trajectory_replay(args, console: Console, ckpts: list[str], steps: list[int]):
    model_items = [
        (f"{step//1000}k", os.path.join(CKPT_DIR, ckpt), str(step))
        for ckpt, step in zip(ckpts, steps)
    ]
    final_path = os.path.join(RUN_DIR, "final_model.zip")
    if not args.no_final and os.path.exists(final_path):
        model_items.append(("final", final_path, "final_model"))

    trajectory = _make_attack_trajectory()
    _validate_trajectory(trajectory)
    if args.dump_trajectory:
        _dump_trajectory_csv(trajectory, args.dump_trajectory)
    n_items = len(model_items)
    records = []
    baseline_probs = None

    console.print("[bold cyan]RL Defense Agent — Policy Evolution Replay[/bold cyan]")
    console.print(f"  Run        : {RUN_DIR}")
    console.print(f"  Models     : {n_items}  ({model_items[0][0]} → {model_items[-1][0]})")
    console.print(f"  Trajectory : 23 env-generated windows, same obs for every model")
    console.print(f"  Delay      : {args.delay}s giữa các checkpoint\n")
    console.print("[dim]Preparing env-generated trajectory: benign → noisy → Redirect evidence → Block…[/dim]")
    time.sleep(0.8)

    first_label, first_path, first_step = model_items[0]
    first_model = PPO.load(first_path, verbose=0)
    first_record = _poll_trajectory(first_model, trajectory)
    first_record["label"] = first_label
    records.append(first_record)
    baseline_probs = first_record["probs"]

    with Live(
        _render_trajectory(first_step, 1, n_items, records, baseline_probs, trajectory),
        refresh_per_second=4,
        console=console,
    ) as live:
        for i, (label, path, step_label) in enumerate(model_items):
            if i > 0:
                model = PPO.load(path, verbose=0)
                rec = _poll_trajectory(model, trajectory)
                rec["label"] = label
                records.append(rec)
                live.update(_render_trajectory(step_label, i + 1, n_items, records, baseline_probs,
                                               trajectory))
            time.sleep(args.delay)

    console.print("\n[bold green]Trajectory replay hoàn tất![/bold green]")
    if args.plot:
        _save_evolution_plot(records, args.plot)
        console.print(f"[green]Đã xuất heatmap PNG:[/green] {args.plot}")
    if args.dump_trajectory:
        console.print(f"[green]Đã xuất trajectory 34D CSV:[/green] {args.dump_trajectory}")
    final = records[-1]
    first_b = final["first_block"] if final["first_block"] is not None else "không có"
    console.print(
        f"[bold yellow]Kết luận demo:[/bold yellow] cùng trajectory, final policy first Block ở t={first_b}, "
        f"P(Block at decision t22)={final['decision_p_block']:.2f}. Đây là policy evolution qua training, "
        "không phải online weight update trong runtime."
    )


def main():
    args = parse_args()
    console = Console(color_system="truecolor")
    ckpts, steps = _load_checkpoint_names(args)

    if not ckpts:
        console.print(f"[red]Không tìm thấy checkpoint trong {CKPT_DIR}[/red]")
        return

    if args.mode == "fixed-state":
        _run_fixed_state_replay(args, console, ckpts, steps)
    else:
        _run_trajectory_replay(args, console, ckpts, steps)


if __name__ == "__main__":
    main()
