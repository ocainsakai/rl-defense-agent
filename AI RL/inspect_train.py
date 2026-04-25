"""
Training Step Visualizer — inspect_train.py

Hiển thị từng step bên trong vòng training/rollout của RL agent:
  state (34D obs) → policy distribution → chosen action → reward → next state

Mục đích:
  Chứng minh rõ ràng & xác thực điều gì đang xảy ra inside training loop.
  Dùng đúng IDSDefenseEnv.step() — KHÔNG simulate riêng — để chống "code trick".

Usage:
    cd "AI RL"

    # Mode A: Rollout từ checkpoint (nhanh, deterministic)
    python3 inspect_train.py --mode rollout \\
        --checkpoint runs/run_34d_v13/checkpoints/model_480000_steps \\
        --steps 200

    # Mode B: Hook vào PPO.learn() thật
    python3 inspect_train.py --mode train --steps 500 \\
        --base-checkpoint runs/run_34d_v13/checkpoints/model_40000_steps

    # Step-by-step demo (delay 800ms/step, dễ đọc trước hội đồng)
    python3 inspect_train.py --mode rollout --delay-ms 800 --steps 30

    # No live display (chỉ ghi JSONL + HTML)
    python3 inspect_train.py --mode rollout --no-live --steps 1000
"""

from __future__ import annotations

import argparse
import json
import logging
import os
import sys
import time
from datetime import datetime
from pathlib import Path
from typing import Optional

import gymnasium as gym
import numpy as np
import torch
from rich.console import Console
from rich.layout import Layout
from rich.live import Live
from rich.panel import Panel
from rich.table import Table
from rich.text import Text
from stable_baselines3 import PPO
from stable_baselines3.common.callbacks import BaseCallback
from stable_baselines3.common.env_util import make_vec_env

from env_ids import (
    IDSDefenseEnv,
    compute_action_bonus,
    compute_action_cost,
    compute_attack_signals,
    compute_network_damage,
)

logging.getLogger("stable_baselines3").setLevel(logging.WARNING)

# ── Constants ────────────────────────────────────────────────────────────────

BASE_DIR = Path(__file__).resolve().parent
OUT_DIR = BASE_DIR / "runs" / "inspect"

ACTION_NAMES = ["Allow", "RateLimit", "Redirect", "Block"]
ACTION_CHARS = ["A", "L", "R", "B"]
ACTION_STYLES = ["bright_green", "yellow", "bright_cyan", "bright_red"]

# 20D sensor labels (matches FEATURE_ORDER in System/config/data_params.py)
SENSOR_NAMES = [
    ("F1",  "PacketRate",    "pkt/s"),
    ("F2",  "SynAckRatio",   ""),
    ("F3",  "InterArrival",  "s"),
    ("F4",  "RstRatio",      ""),
    ("F5",  "DistinctPorts", ""),
    ("F6",  "URLConcentr",   ""),
    ("F7",  "HttpIatUnif",   ""),
    ("F8",  "ReqSizeUnif",   ""),
    ("F9",  "AvgPayload",    "B"),
    ("F10", "FwdBwdRatio",   ""),
    ("F11", "PktsPerPort",   ""),
    ("F12", "SqlSpecial",    ""),
    ("F13", "CrsSqliScore",  ""),
    ("F14", "SqlUnion",      ""),
    ("F15", "SqlComment",    ""),
    ("F16", "SqlStacked",    ""),
    ("F17", "SqlSelectCnt",  ""),
    ("F18", "CrsXssScore",   ""),
    ("F19", "JsFnCall",      ""),
    ("F20", "HtmlEvent",     ""),
]

EFFECT_NAMES = [
    ("F21", "WebHitRatio"),
    ("F22", "HoneypotRatio"),
    ("F23", "PresenceRatio"),
    ("F24", "ServiceDamage"),
]


def _bar(value: float, width: int = 12, fill: str = "█", empty: str = "░") -> str:
    """Render a normalized [0,1] value as ASCII bar."""
    n = int(round(max(0.0, min(1.0, value)) * width))
    return fill * n + empty * (width - n)


# ── StepLoggerWrapper ────────────────────────────────────────────────────────

class StepLoggerWrapper(gym.Wrapper):
    """Wraps IDSDefenseEnv to capture every (obs, action, probs, reward, info, next_obs)
    tuple AND temporal-state details, written as JSONL.

    Uses env.step() directly — no simulation. The model_ref (PPO) is queried
    for action probabilities at each step (snapshot of policy state at obs_t).
    """

    def __init__(self, env: IDSDefenseEnv, model_ref: Optional[PPO], log_path: Path):
        super().__init__(env)
        self.model_ref = model_ref
        self.log_path = Path(log_path)
        self.log_path.parent.mkdir(parents=True, exist_ok=True)
        # Truncate log on init
        with open(self.log_path, "w") as f:
            f.write("")

        self.episode_idx = 0
        self.step_in_episode = 0
        self.global_step = 0
        self._last_obs: Optional[np.ndarray] = None
        self.last_record: Optional[dict] = None

    # ── Probability extraction (pattern from verify_rl_decision.py:117-120) ──
    def _get_probs(self, obs: np.ndarray) -> Optional[np.ndarray]:
        if self.model_ref is None:
            return None
        obs_t, _ = self.model_ref.policy.obs_to_tensor(obs.astype(np.float32))
        with torch.no_grad():
            dist = self.model_ref.policy.get_distribution(obs_t)
            probs = dist.distribution.probs.cpu().numpy().flatten()
        return probs

    # ── Snapshot temporal state for the IP that is about to be acted on ──
    def _snapshot_temporal(self, ip: str) -> dict:
        ts = self.env.unwrapped.ip_temporal_state.get(ip)
        if ts is None:
            return {}
        return {
            "session_active":      bool(ts.session_active),
            "block_ready_latched": bool(ts.block_ready_latched),
            "window_len":          int(ts.window_len),
            "redirect_hits":       int(ts.redirect_hits),
            "presence_hits":       int(ts.presence_hits),
            "honeypot_hits":       int(ts.honeypot_hits),
            "miss_count":          int(ts.miss_count),
            "escalation_score":    float(ts.escalation_score),
            "damage_ema":          float(ts.damage_ema),
            "last_action":         int(ts.last_action),
            "action_hold_steps":   int(ts.action_hold_steps),
        }

    def reset(self, **kwargs):
        obs, info = self.env.reset(**kwargs)
        self._last_obs = obs
        return obs, info

    def step(self, action):
        prev_obs = self._last_obs
        # Snapshot IP that is about to be acted (current_ip_idx of underlying env)
        env_u = self.env.unwrapped
        acting_ip = env_u.ip_list[env_u.current_ip_idx]
        acting_ip_type = env_u.ip_types[env_u.current_ip_idx]

        # 1. Snapshot policy distribution BEFORE step (for obs_t)
        probs = self._get_probs(prev_obs)

        # 2. Snapshot temporal state BEFORE step
        temporal_before = self._snapshot_temporal(acting_ip)

        # 3. Compute action_bonus externally for reward decomposition
        # (uses public env_ids functions — same code path as _compute_reward)
        raw_before = list(env_u.ip_behaviors[acting_ip].get_features())
        damage_before = compute_network_damage(raw_before)
        action_bonus = compute_action_bonus(int(action), raw_before, damage_before)
        action_cost_val = compute_action_cost(int(action))

        # 4. Take the actual env step
        obs, reward, done, truncated, info = self.env.step(action)

        # 5. Snapshot temporal state AFTER step (for next-step view)
        temporal_after = self._snapshot_temporal(acting_ip)

        # 6. Get next IP (already advanced in env.step)
        next_ip = env_u.ip_list[env_u.current_ip_idx]
        next_ip_type = env_u.ip_types[env_u.current_ip_idx]

        # 7. Reward shaping = total - service_damage_term - action_cost - action_bonus
        rb = info.get("reward_breakdown", {})
        service_damage_term = float(rb.get("service_damage", 0.0))
        action_cost_term = float(rb.get("action_cost", 0.0))
        shaping_other = float(reward) - service_damage_term - action_cost_term - action_bonus

        record = {
            "episode":         int(self.episode_idx),
            "step_in_ep":      int(self.step_in_episode),
            "global_step":     int(self.global_step),
            "acting_ip":       acting_ip,
            "acting_ip_type":  acting_ip_type,
            "next_ip":         next_ip,
            "next_ip_type":    next_ip_type,
            "obs_prev":        prev_obs.tolist() if prev_obs is not None else None,
            "obs_next":        obs.tolist(),
            "raw_features_before": [float(v) for v in raw_before],
            "raw_features_after":  [float(v) for v in info.get("acted_features_after", [])],
            "effect_prev":     [float(v) for v in info.get("effect_prev", [0, 0, 0, 0])],
            "effect":          [float(v) for v in info.get("effect", [0, 0, 0, 0])],
            "policy_probs":    probs.tolist() if probs is not None else None,
            "action":          int(action),
            "action_name":     ACTION_NAMES[int(action)],
            "reward":          float(reward),
            "reward_breakdown": {
                "action_bonus":     float(action_bonus),
                "action_cost":      float(action_cost_term),
                "service_damage":   float(service_damage_term),
                "shaping_other":    float(shaping_other),
                "total":            float(reward),
            },
            "temporal_before": temporal_before,
            "temporal_after":  temporal_after,
            "step_damage":     float(info.get("step_damage", 0.0)),
            "cumulative_damage": float(info.get("cumulative_damage", 0.0)),
            "done":            bool(done),
            "truncated":       bool(truncated),
        }

        # Append to JSONL
        with open(self.log_path, "a") as f:
            f.write(json.dumps(record) + "\n")

        self.last_record = record
        self._last_obs = obs
        self.step_in_episode += 1
        self.global_step += 1
        if done or truncated:
            self.episode_idx += 1
            self.step_in_episode = 0

        return obs, reward, done, truncated, info


# ── DashboardRenderer ────────────────────────────────────────────────────────

class DashboardRenderer:
    """Multi-panel rich.Live dashboard rendering one step at a time."""

    def __init__(self, console: Console, mode: str, source: str):
        self.console = console
        self.mode = mode
        self.source = source
        self.layout = self._build_layout()
        self.trajectory_history: list[int] = []
        self.live: Optional[Live] = None

    def _build_layout(self) -> Layout:
        layout = Layout()
        layout.split_column(
            Layout(name="header", size=3),
            Layout(name="body"),
            Layout(name="footer", size=4),
        )
        layout["body"].split_row(
            Layout(name="obs_panel", ratio=3),
            Layout(name="decision_panel", ratio=2),
        )
        layout["obs_panel"].split_column(
            Layout(name="sensor", ratio=4),
            Layout(name="temporal", ratio=3),
            Layout(name="effect", ratio=2),
        )
        layout["decision_panel"].split_column(
            Layout(name="policy", ratio=2),
            Layout(name="reward", ratio=3),
            Layout(name="next", ratio=2),
        )
        return layout

    def __enter__(self):
        self.live = Live(self.layout, console=self.console, refresh_per_second=10,
                         screen=False, vertical_overflow="visible")
        self.live.__enter__()
        return self

    def __exit__(self, *args):
        if self.live:
            self.live.__exit__(*args)

    # ── Update dashboard from latest log record ──
    def update(self, rec: dict, total_steps: int):
        self.trajectory_history.append(rec["action"])
        self.layout["header"].update(self._render_header(rec, total_steps))
        self.layout["sensor"].update(self._render_sensor(rec))
        self.layout["temporal"].update(self._render_temporal(rec))
        self.layout["effect"].update(self._render_effect(rec))
        self.layout["policy"].update(self._render_policy(rec))
        self.layout["reward"].update(self._render_reward(rec))
        self.layout["next"].update(self._render_next(rec))
        self.layout["footer"].update(self._render_footer())

    # ── Header ──
    def _render_header(self, rec: dict, total_steps: int) -> Panel:
        ip = rec["acting_ip"]
        ip_type = rec["acting_ip_type"]
        ep = rec["episode"]
        sie = rec["step_in_ep"]
        gs = rec["global_step"]
        title = (f"[bold cyan]inspect_train[/]  |  mode={self.mode}  |  source={self.source}")
        body = Text.assemble(
            ("Episode ", "bold"), (f"{ep+1}", "bright_white"),
            ("  |  Step ", "bold"), (f"{sie+1}", "bright_white"),
            ("  |  global=", "dim"), (f"{gs+1}/{total_steps}", "bright_white"),
            ("  |  IP: ", "bold"), (f"{ip}", "bright_yellow"),
            (f"  ({ip_type})", "dim italic"),
        )
        return Panel(body, title=title, border_style="cyan")

    # ── Observation panels ──
    def _render_sensor(self, rec: dict) -> Panel:
        sensor20 = rec["obs_prev"][:20] if rec["obs_prev"] else [0] * 20
        raw = rec["raw_features_before"]
        table = Table(box=None, show_header=False, padding=(0, 1), expand=True)
        table.add_column(style="dim", width=4)
        table.add_column(style="bold white", width=14)
        table.add_column(justify="right", width=8)
        table.add_column(width=14)

        for i, (code, name, _unit) in enumerate(SENSOR_NAMES):
            norm = float(sensor20[i])
            raw_v = float(raw[i]) if i < len(raw) else 0.0
            bar = _bar(norm)
            # color by feature group
            if i < 11:
                style = "white"
            elif i < 17:
                style = "bright_cyan"  # sqli
            else:
                style = "bright_magenta"  # xss
            table.add_row(code, name, f"{raw_v:>7.2f}", Text(bar, style=style))

        return Panel(table, title="OBSERVATION  ·  Sensor 20D (raw values + normalized bars)",
                     border_style="dim")

    def _render_temporal(self, rec: dict) -> Panel:
        temp = rec["temporal_before"]
        last_action = temp.get("last_action", 0)
        la_name = ACTION_NAMES[last_action]
        block_ready = temp.get("block_ready_latched", False)
        session = temp.get("session_active", False)

        table = Table(box=None, show_header=False, padding=(0, 1), expand=True)
        table.add_column(style="bold white", width=22)
        table.add_column(justify="right", width=10)
        table.add_column(width=14)

        table.add_row("session_active",
                      Text("True" if session else "False",
                           style="bright_green" if session else "dim"),
                      "")
        table.add_row("block_ready_latched",
                      Text("True" if block_ready else "False",
                           style="bright_red" if block_ready else "dim"),
                      "")
        table.add_row("last_action",
                      Text(la_name, style=ACTION_STYLES[last_action]),
                      f"hold={temp.get('action_hold_steps', 0)}")
        table.add_row("redirect_hits",
                      f"{temp.get('redirect_hits', 0)}/15",
                      _bar(temp.get('redirect_hits', 0) / 15))
        table.add_row("presence_hits",
                      f"{temp.get('presence_hits', 0)}/15",
                      _bar(temp.get('presence_hits', 0) / 15))
        table.add_row("honeypot_hits",
                      f"{temp.get('honeypot_hits', 0)}/15",
                      _bar(temp.get('honeypot_hits', 0) / 15))
        table.add_row("escalation_score",
                      f"{temp.get('escalation_score', 0):.3f}",
                      _bar(temp.get('escalation_score', 0)))
        table.add_row("window_len",
                      f"{temp.get('window_len', 0)}/15",
                      _bar(temp.get('window_len', 0) / 15))
        table.add_row("miss_count",
                      f"{temp.get('miss_count', 0)}/3",
                      _bar(temp.get('miss_count', 0) / 3))
        table.add_row("damage_ema",
                      f"{temp.get('damage_ema', 0):.3f}",
                      _bar(temp.get('damage_ema', 0)))

        return Panel(table, title="OBSERVATION  ·  Temporal 10D (per-IP soft session state)",
                     border_style="dim")

    def _render_effect(self, rec: dict) -> Panel:
        eff = rec["effect_prev"]
        table = Table(box=None, show_header=False, padding=(0, 1), expand=True)
        table.add_column(style="dim", width=4)
        table.add_column(style="bold white", width=16)
        table.add_column(justify="right", width=8)
        table.add_column(width=14)
        for i, (code, name) in enumerate(EFFECT_NAMES):
            v = float(eff[i]) if i < len(eff) else 0.0
            table.add_row(code, name, f"{v:.3f}", _bar(v))
        return Panel(table, title="OBSERVATION  ·  Effect_{t-1} 4D (delayed closed-loop feedback)",
                     border_style="dim")

    # ── Decision panels ──
    def _render_policy(self, rec: dict) -> Panel:
        probs = rec["policy_probs"]
        chosen = rec["action"]
        table = Table(box=None, show_header=False, padding=(0, 1), expand=True)
        table.add_column(width=10)
        table.add_column(width=20)
        table.add_column(justify="right", width=8)
        table.add_column(width=4)

        if probs is None:
            table.add_row("(no policy attached)", "", "", "")
        else:
            argmax = int(np.argmax(probs))
            for i, name in enumerate(ACTION_NAMES):
                p = float(probs[i])
                bar = _bar(p, width=18)
                marker = "◄" if i == argmax else " "
                style = ACTION_STYLES[i]
                table.add_row(
                    Text(name, style=style),
                    Text(bar, style=style),
                    f"{p:.3f}",
                    Text(marker, style="bold yellow" if i == argmax else "dim"),
                )

        chosen_text = Text.assemble(
            ("\nCHOSEN ACTION: ", "bold"),
            (f"{chosen} = {ACTION_NAMES[chosen]}", f"bold {ACTION_STYLES[chosen]}"),
        )

        from rich.console import Group
        return Panel(Group(table, chosen_text),
                     title="POLICY DISTRIBUTION (softmax)", border_style="bright_blue")

    def _render_reward(self, rec: dict) -> Panel:
        rb = rec["reward_breakdown"]
        table = Table(box=None, show_header=False, padding=(0, 1), expand=True)
        table.add_column(style="bold white", width=20)
        table.add_column(justify="right", width=10)

        def fmt(v: float) -> Text:
            color = "bright_green" if v > 0 else ("bright_red" if v < 0 else "dim")
            sign = "+" if v > 0 else ""
            return Text(f"{sign}{v:.4f}", style=color)

        table.add_row("action_bonus",   fmt(rb["action_bonus"]))
        table.add_row("action_cost",    fmt(rb["action_cost"]))
        table.add_row("service_damage", fmt(rb["service_damage"]))
        table.add_row("shaping_other",  fmt(rb["shaping_other"]))
        table.add_row("─" * 18, Text("─" * 8, style="dim"))
        total = rb["total"]
        total_color = "bold bright_green" if total > 0 else "bold bright_red"
        sign = "+" if total > 0 else ""
        table.add_row(Text("TOTAL REWARD", style="bold"),
                      Text(f"{sign}{total:.4f}", style=total_color))
        return Panel(table, title="ENV REWARD BREAKDOWN", border_style="bright_yellow")

    def _render_next(self, rec: dict) -> Panel:
        eff = rec["effect"]
        table = Table(box=None, show_header=False, padding=(0, 1), expand=True)
        table.add_column(style="bold white", width=18)
        table.add_column(width=20)
        table.add_row("next IP",
                      Text(f"{rec['next_ip']} ({rec['next_ip_type']})", style="bright_yellow"))
        table.add_row("done",
                      Text(str(rec["done"]),
                           style="bright_red" if rec["done"] else "dim"))
        table.add_row("step_damage", f"{rec['step_damage']:.4f}")
        table.add_row("cumulative_damage", f"{rec['cumulative_damage']:.4f}")
        table.add_row("effect_t F21..F24", f"[{', '.join(f'{v:.2f}' for v in eff)}]")
        return Panel(table, title="NEXT STATE / ENV FEEDBACK", border_style="green")

    # ── Footer trajectory ──
    def _render_footer(self) -> Panel:
        recent = self.trajectory_history[-50:]
        txt = Text()
        for a in recent:
            txt.append(ACTION_CHARS[a], style=ACTION_STYLES[a])
            txt.append(" ")
        legend = Text("\nLegend: ", style="dim")
        for i, name in enumerate(ACTION_NAMES):
            legend.append(f"{ACTION_CHARS[i]}={name}  ", style=ACTION_STYLES[i])
        from rich.console import Group
        return Panel(Group(Text("Trajectory: ", style="bold") + txt, legend),
                     title=f"TRAJECTORY (last {len(recent)} of {len(self.trajectory_history)})",
                     border_style="dim")


# ── Mode A: Rollout from checkpoint ──────────────────────────────────────────

def _run_rollout(args, console: Console, log_path: Path):
    console.print(f"[bold cyan]Loading checkpoint:[/] {args.checkpoint}")
    model = PPO.load(args.checkpoint, device="cpu")
    console.print(f"[bold cyan]Building env:[/] IDSDefenseEnv(mode='mock', seed={args.seed})")
    env = IDSDefenseEnv(mode="mock")
    wrapped = StepLoggerWrapper(env, model_ref=model, log_path=log_path)
    obs, _ = wrapped.reset(seed=args.seed)

    source_label = Path(args.checkpoint).name

    if args.no_live:
        # Headless: just step + log
        console.print(f"[dim]Running {args.steps} steps headlessly → {log_path.name}[/]")
        for _ in range(args.steps):
            action, _ = model.predict(obs, deterministic=args.deterministic)
            obs, _, done, trunc, _ = wrapped.step(int(action))
            if done or trunc:
                obs, _ = wrapped.reset()
        return

    with DashboardRenderer(console, mode="rollout", source=source_label) as renderer:
        for step_i in range(args.steps):
            action, _ = model.predict(obs, deterministic=args.deterministic)
            obs, _, done, trunc, _ = wrapped.step(int(action))
            renderer.update(wrapped.last_record, args.steps)
            if args.delay_ms > 0:
                time.sleep(args.delay_ms / 1000.0)
            if done or trunc:
                obs, _ = wrapped.reset()


# ── Mode B: Training hook ─────────────────────────────────────────────────────

class _DashboardCallback(BaseCallback):
    """Reads JSONL written by StepLoggerWrapper and pushes latest to renderer."""

    def __init__(self, renderer: Optional[DashboardRenderer], log_path: Path,
                 max_steps: int, delay_ms: int):
        super().__init__()
        self.renderer = renderer
        self.log_path = log_path
        self.max_steps = max_steps
        self.delay_ms = delay_ms
        self._last_size = 0

    def _on_step(self) -> bool:
        if self.renderer is None:
            return self.num_timesteps < self.max_steps

        # Read newly appended lines
        try:
            with open(self.log_path, "r") as f:
                f.seek(self._last_size)
                new_data = f.read()
                self._last_size = f.tell()
        except FileNotFoundError:
            return True

        for line in new_data.strip().split("\n"):
            if not line:
                continue
            try:
                rec = json.loads(line)
            except json.JSONDecodeError:
                continue
            self.renderer.update(rec, self.max_steps)
            if self.delay_ms > 0:
                time.sleep(self.delay_ms / 1000.0)

        return self.num_timesteps < self.max_steps


def _run_train(args, console: Console, log_path: Path):
    console.print(f"[bold cyan]Building env:[/] IDSDefenseEnv(mode='mock'), n_envs=1")

    def make_env():
        return StepLoggerWrapper(IDSDefenseEnv(mode="mock"), model_ref=None, log_path=log_path)

    vec_env = make_vec_env(make_env, n_envs=1)

    if args.base_checkpoint:
        console.print(f"[bold cyan]Loading base checkpoint:[/] {args.base_checkpoint}")
        model = PPO.load(args.base_checkpoint, env=vec_env, device="cpu",
                         custom_objects={"tensorboard_log": None}, verbose=0)
        source_label = f"finetune from {Path(args.base_checkpoint).name}"
    else:
        console.print(f"[bold cyan]Initializing fresh PPO model[/]")
        model = PPO("MlpPolicy", vec_env, device="cpu", verbose=0,
                    n_steps=2048, batch_size=128, n_epochs=6,
                    learning_rate=3e-4, gamma=0.995, clip_range=0.15)
        source_label = "fresh PPO"

    if args.no_live:
        console.print(f"[dim]Training {args.steps} steps headlessly → {log_path.name}[/]")
        # Need to attach a model_ref to wrapper post-hoc so probs get logged.
        # Easier: enable model.learn() and let wrapper still capture (probs=None).
        cb = _DashboardCallback(None, log_path, args.steps, 0)
        model.learn(total_timesteps=args.steps, callback=cb,
                    progress_bar=False, log_interval=9999)
        return

    # Update wrapper's model_ref so policy probs get logged during training.
    # vec_env is a DummyVecEnv → access first env's wrapper.
    underlying_wrapper = vec_env.envs[0]
    while not isinstance(underlying_wrapper, StepLoggerWrapper):
        underlying_wrapper = underlying_wrapper.env
    underlying_wrapper.model_ref = model

    with DashboardRenderer(console, mode="train", source=source_label) as renderer:
        cb = _DashboardCallback(renderer, log_path, args.steps, args.delay_ms)
        model.learn(total_timesteps=args.steps, callback=cb,
                    progress_bar=False, log_interval=9999)


# ── HTML report generator ────────────────────────────────────────────────────

HTML_TEMPLATE = """<!DOCTYPE html>
<html><head><meta charset="utf-8"><title>inspect_train report</title>
<script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
<style>
body{font-family:-apple-system,BlinkMacSystemFont,Segoe UI,Roboto,sans-serif;margin:0;background:#0f1419;color:#e6e1cf}
header{background:#1a1f29;padding:18px 24px;border-bottom:2px solid #2a3340}
header h1{margin:0;font-size:20px;color:#7fdbca}
header .meta{color:#888;font-size:13px;margin-top:4px}
.summary{display:grid;grid-template-columns:repeat(auto-fit,minmax(200px,1fr));gap:12px;padding:18px 24px;background:#151a23}
.summary .card{background:#1d242f;padding:14px;border-radius:6px;border-left:3px solid #5ccfe6}
.summary .card .label{font-size:11px;color:#888;text-transform:uppercase;letter-spacing:0.5px}
.summary .card .value{font-size:22px;font-weight:600;margin-top:6px;color:#bae67e}
.charts{display:grid;grid-template-columns:1fr 1fr;gap:16px;padding:18px 24px}
.chart-box{background:#1d242f;padding:14px;border-radius:6px;height:340px}
.chart-box h3{margin:0 0 10px 0;font-size:13px;color:#ffcc66;font-weight:500}
.timeline{background:#1d242f;margin:0 24px 18px;padding:14px;border-radius:6px}
.timeline h3{margin:0 0 10px 0;font-size:13px;color:#ffcc66}
.steps{padding:0 24px 24px}
.step-card{background:#1d242f;border-left:4px solid #5ccfe6;border-radius:4px;padding:12px 16px;margin-bottom:10px;font-family:'SF Mono',Monaco,Consolas,monospace;font-size:12px;line-height:1.5}
.step-card.action-0{border-color:#bae67e}
.step-card.action-1{border-color:#ffcc66}
.step-card.action-2{border-color:#5ccfe6}
.step-card.action-3{border-color:#ff6b6b}
.step-card .head{display:flex;justify-content:space-between;color:#7fdbca;margin-bottom:6px;font-weight:600}
.step-card .row{color:#bbb}
.step-card .pos{color:#bae67e}
.step-card .neg{color:#ff6b6b}
.bar{display:inline-block;height:8px;background:#5ccfe6;vertical-align:middle;margin-left:6px;border-radius:2px}
.tag{display:inline-block;padding:1px 6px;border-radius:3px;font-size:10px;font-weight:600;margin-left:6px}
.tag.bench{background:#bae67e;color:#000}
.tag.rate{background:#ffcc66;color:#000}
.tag.redir{background:#5ccfe6;color:#000}
.tag.block{background:#ff6b6b;color:#fff}
</style></head><body>
<header>
<h1>inspect_train.py — Step-by-step training visualization</h1>
<div class="meta">__META__</div>
</header>
<div class="summary">__SUMMARY__</div>
<div class="charts">
  <div class="chart-box"><h3>Action distribution</h3><canvas id="action_chart"></canvas></div>
  <div class="chart-box"><h3>Reward over steps (cumulative)</h3><canvas id="reward_chart"></canvas></div>
</div>
<div class="timeline">
  <h3>Action trajectory (timeline)</h3>
  <div style="height:60px"><canvas id="trajectory_chart"></canvas></div>
</div>
<div class="steps"><h3 style="color:#ffcc66;font-size:14px;margin:0 0 12px">Per-step detail (first 200 steps)</h3>__STEPS__</div>
<script>
const ACTION_NAMES = ["Allow","RateLimit","Redirect","Block"];
const ACTION_COLORS = ["#bae67e","#ffcc66","#5ccfe6","#ff6b6b"];
const data = __DATA__;

// Action distribution donut
new Chart(document.getElementById('action_chart'),{type:'doughnut',
  data:{labels:ACTION_NAMES,
        datasets:[{data:[0,1,2,3].map(i=>data.filter(d=>d.action===i).length),
                   backgroundColor:ACTION_COLORS}]},
  options:{plugins:{legend:{position:'right',labels:{color:'#ddd'}}},maintainAspectRatio:false}});

// Cumulative reward line
let cum=0; const cumData = data.map(d=>(cum+=d.reward,cum));
new Chart(document.getElementById('reward_chart'),{type:'line',
  data:{labels:data.map((_,i)=>i+1),
        datasets:[{label:'cumulative reward',data:cumData,
                   borderColor:'#7fdbca',backgroundColor:'rgba(127,219,202,0.1)',
                   fill:true,tension:0.2,pointRadius:0}]},
  options:{plugins:{legend:{display:false}},maintainAspectRatio:false,
           scales:{x:{ticks:{color:'#888'},grid:{color:'#2a3340'}},
                   y:{ticks:{color:'#888'},grid:{color:'#2a3340'}}}}});

// Trajectory bars
new Chart(document.getElementById('trajectory_chart'),{type:'bar',
  data:{labels:data.map((_,i)=>i+1),
        datasets:[{data:data.map(d=>1),
                   backgroundColor:data.map(d=>ACTION_COLORS[d.action]),
                   borderWidth:0,barThickness:6}]},
  options:{plugins:{legend:{display:false},tooltip:{callbacks:{
              label:c=>`Step ${c.label}: ${ACTION_NAMES[data[c.dataIndex].action]} (r=${data[c.dataIndex].reward.toFixed(3)})`}}},
           maintainAspectRatio:false,
           scales:{x:{display:false},y:{display:false}}}});
</script></body></html>"""


def _generate_html_report(jsonl_path: Path, html_path: Path, mode: str, source: str,
                          total_steps: int, console: Console):
    records = []
    with open(jsonl_path) as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                records.append(json.loads(line))
            except json.JSONDecodeError:
                continue

    if not records:
        console.print("[red]No records — skipping HTML report[/]")
        return

    # Summary cards
    total_reward = sum(r["reward"] for r in records)
    avg_reward = total_reward / len(records)
    action_counts = [sum(1 for r in records if r["action"] == i) for i in range(4)]
    n_episodes = max((r["episode"] for r in records), default=0) + 1
    cum_damage = records[-1]["cumulative_damage"]

    summary = "".join([
        f'<div class="card"><div class="label">Total steps</div><div class="value">{len(records)}</div></div>',
        f'<div class="card"><div class="label">Episodes</div><div class="value">{n_episodes}</div></div>',
        f'<div class="card"><div class="label">Total reward</div><div class="value">{total_reward:+.2f}</div></div>',
        f'<div class="card"><div class="label">Avg reward/step</div><div class="value">{avg_reward:+.4f}</div></div>',
        f'<div class="card"><div class="label">Cumul. damage</div><div class="value">{cum_damage:.2f}</div></div>',
        f'<div class="card"><div class="label">Allow / RateLim / Redir / Block</div>'
        f'<div class="value" style="font-size:14px">{action_counts[0]}/{action_counts[1]}/{action_counts[2]}/{action_counts[3]}</div></div>',
    ])

    meta = (f"mode={mode} · source={source} · {len(records)} steps · "
            f"{n_episodes} episodes · generated {datetime.now().strftime('%Y-%m-%d %H:%M')}")

    # Per-step cards (cap at 200 to keep HTML manageable)
    tag_class = ["bench", "rate", "redir", "block"]
    steps_html = []
    for r in records[:200]:
        probs = r.get("policy_probs") or [0.0] * 4
        probs_str = " ".join(
            f'{ACTION_NAMES[i]}={probs[i]:.2f}' for i in range(4)
        )
        argmax = int(np.argmax(probs)) if any(probs) else r["action"]
        rb = r["reward_breakdown"]
        temp = r.get("temporal_before", {})
        head = (f"Episode {r['episode']+1} · Step {r['step_in_ep']+1} · global={r['global_step']+1} · "
                f"IP {r['acting_ip']} ({r['acting_ip_type']})")
        action_tag = (f'<span class="tag {tag_class[r["action"]]}">'
                      f'{ACTION_NAMES[r["action"]]}</span>')
        argmax_tag = ('' if argmax == r["action"] else
                      f' <span style="color:#ff6b6b;font-size:10px">(argmax was {ACTION_NAMES[argmax]})</span>')
        reward_class = "pos" if r["reward"] > 0 else "neg"
        sign = "+" if r["reward"] > 0 else ""

        card = f"""<div class="step-card action-{r['action']}">
<div class="head"><span>{head}</span><span>action: {action_tag}{argmax_tag}</span></div>
<div class="row">policy probs: {probs_str}</div>
<div class="row">reward: <span class="{reward_class}">{sign}{r['reward']:.4f}</span> = action_bonus({rb['action_bonus']:+.3f}) + action_cost({rb['action_cost']:+.3f}) + service_damage({rb['service_damage']:+.3f}) + shaping_other({rb['shaping_other']:+.3f})</div>
<div class="row">temporal: session={temp.get('session_active')}, block_ready={temp.get('block_ready_latched')}, redirect_hits={temp.get('redirect_hits',0)}/15, presence_hits={temp.get('presence_hits',0)}/15, escalation_score={temp.get('escalation_score',0):.3f}</div>
<div class="row">effect_t: F21={r['effect'][0]:.2f} F22={r['effect'][1]:.2f} F23={r['effect'][2]:.2f} F24={r['effect'][3]:.2f} → next IP: {r['next_ip']} ({r['next_ip_type']})</div>
</div>"""
        steps_html.append(card)
    if len(records) > 200:
        steps_html.append(f'<p style="color:#888;text-align:center">'
                          f'... {len(records) - 200} more steps in JSONL log</p>')

    # Compact JSON for charts (only what we need)
    chart_data = json.dumps([
        {"action": r["action"], "reward": r["reward"]} for r in records
    ])

    html = (HTML_TEMPLATE
            .replace("__META__", meta)
            .replace("__SUMMARY__", summary)
            .replace("__STEPS__", "\n".join(steps_html))
            .replace("__DATA__", chart_data))

    html_path.write_text(html, encoding="utf-8")
    console.print(f"[bright_green]✓ HTML report:[/] {html_path}")


# ── Main ──────────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        description="Visualize each step inside RL training/rollout loop",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__)
    parser.add_argument("--mode", choices=["rollout", "train"], default="rollout",
                        help="rollout = step env from checkpoint  |  train = hook PPO.learn()")
    parser.add_argument("--checkpoint", default=str(BASE_DIR / "runs" / "run_34d_v13" /
                                                    "checkpoints" / "model_480000_steps"),
                        help="Path to PPO checkpoint (.zip; for --mode rollout)")
    parser.add_argument("--base-checkpoint", default=None,
                        help="Optional base checkpoint to fine-tune from (for --mode train)")
    parser.add_argument("--steps", type=int, default=100,
                        help="Number of env steps to capture (default: 100)")
    parser.add_argument("--seed", type=int, default=42,
                        help="Env reset seed (default: 42)")
    parser.add_argument("--deterministic", action="store_true",
                        help="Use argmax (deterministic) policy (default: stochastic)")
    parser.add_argument("--delay-ms", type=int, default=120,
                        help="Delay per step (ms) for live dashboard readability (default: 120)")
    parser.add_argument("--no-live", action="store_true",
                        help="Skip live dashboard, only write JSONL + HTML report")
    parser.add_argument("--no-html", action="store_true",
                        help="Skip HTML report generation")
    parser.add_argument("--out-dir", default=str(OUT_DIR),
                        help="Output directory (default: AI RL/runs/inspect)")
    args = parser.parse_args()

    out_dir = Path(args.out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    log_path = out_dir / f"{timestamp}_{args.mode}_steps.jsonl"
    html_path = out_dir / f"{timestamp}_{args.mode}_report.html"

    console = Console()
    console.rule(f"[bold cyan]inspect_train  ·  mode={args.mode}  ·  steps={args.steps}[/]")

    if args.mode == "rollout":
        if not Path(args.checkpoint + ".zip").exists() and not Path(args.checkpoint).exists():
            console.print(f"[red]Checkpoint not found:[/] {args.checkpoint}")
            sys.exit(1)
        _run_rollout(args, console, log_path)
        source = Path(args.checkpoint).name
    else:
        _run_train(args, console, log_path)
        source = (f"finetune from {Path(args.base_checkpoint).name}"
                  if args.base_checkpoint else "fresh PPO")

    console.print(f"\n[bright_green]✓ JSONL log:[/] {log_path} ({log_path.stat().st_size:,} bytes)")

    if not args.no_html:
        _generate_html_report(log_path, html_path, args.mode, source, args.steps, console)
        console.print(f"\n[dim]Open in browser:[/] file://{html_path.absolute()}")

    console.rule()


if __name__ == "__main__":
    main()
