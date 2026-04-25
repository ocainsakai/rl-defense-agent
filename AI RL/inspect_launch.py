"""
Interactive launcher cho inspect_train.py — hướng dẫn từng option, giải thích
trước khi chạy. Phù hợp khi demo trước hội đồng hoặc lúc bạn quên flag nào.

Usage:
    cd "AI RL"
    python3 inspect_launch.py
"""
from __future__ import annotations

import os
import re
import subprocess
import sys
from pathlib import Path

from rich.console import Console
from rich.panel import Panel
from rich.prompt import IntPrompt, Prompt, Confirm
from rich.table import Table
from rich.text import Text

BASE_DIR = Path(__file__).resolve().parent
CKPT_DIR = BASE_DIR / "runs" / "run_34d_v13" / "checkpoints"

console = Console()


def show_intro():
    console.rule("[bold cyan]inspect_train.py — Interactive Launcher[/]")
    console.print(Panel(
        Text.assemble(
            ("Tool này hiển thị từng step bên trong vòng training/rollout của RL agent:\n\n",
             "white"),
            ("  • State 34D (sensor 20D + temporal 10D + effect 4D)\n", "dim"),
            ("  • Policy probabilities (softmax 4 actions)\n", "dim"),
            ("  • Action chosen + reward breakdown\n", "dim"),
            ("  • Next state + cumulative damage\n\n", "dim"),
            ("Mục đích: ", "bold"),
            ("trả lời 'AI thấy gì? quyết định ra sao?' với data raw có thể verify lại.\n",
             "white"),
        ),
        title="Mục đích", border_style="cyan"))


def list_checkpoints() -> list[Path]:
    """Tìm tất cả checkpoint .zip có sẵn, sort theo step number."""
    if not CKPT_DIR.exists():
        return []
    ckpts = list(CKPT_DIR.glob("model_*_steps.zip"))

    def step_num(p: Path) -> int:
        m = re.search(r"model_(\d+)_steps", p.stem)
        return int(m.group(1)) if m else 0

    return sorted(ckpts, key=step_num)


def ask_mode() -> str:
    """Mode: rollout vs train"""
    console.print("\n[bold yellow]── BƯỚC 1: Chọn MODE ──[/]")
    table = Table(box=None, padding=(0, 2))
    table.add_column("[bold]#", width=3)
    table.add_column("[bold]Mode", style="bright_cyan")
    table.add_column("[bold]Mô tả")
    table.add_column("[bold]Khi nào dùng", style="dim")
    table.add_row("1", "rollout",
                  "Load checkpoint có sẵn → step env N lần\n[dim]Không có gradient update[/]",
                  "Demo nhanh, show model đã train\nquyết định ra sao trên scenario mock")
    table.add_row("2", "train",
                  "Hook vào PPO.learn() → train thật N steps\n[dim]Có gradient update[/]",
                  "Show model đang HỌC từ rollout\nbuffer (chậm hơn nhiều)")
    console.print(table)
    choice = IntPrompt.ask("\nChọn mode", choices=["1", "2"], default=1)
    return "rollout" if choice == 1 else "train"


def ask_checkpoint(mode: str) -> tuple[str, str | None]:
    """Chọn checkpoint. Return (checkpoint_arg_path, source_label)."""
    ckpts = list_checkpoints()
    if not ckpts:
        console.print("[red]Không tìm thấy checkpoint nào trong[/]", CKPT_DIR)
        sys.exit(1)

    title = ("BƯỚC 2: Chọn CHECKPOINT cần load"
             if mode == "rollout" else
             "BƯỚC 2: Chọn BASE CHECKPOINT để fine-tune từ")
    console.print(f"\n[bold yellow]── {title} ──[/]")
    if mode == "train":
        console.print(
            "[dim]Lưu ý: train mode sẽ TRAIN TIẾP từ checkpoint này. "
            "Nếu skip (Enter), sẽ khởi tạo PPO mới từ random.[/]\n")

    table = Table(box=None, padding=(0, 2))
    table.add_column("[bold]#", width=3, justify="right")
    table.add_column("[bold]Checkpoint", style="bright_cyan")
    table.add_column("[bold]Note", style="dim")

    def step_num(p: Path) -> int:
        m = re.search(r"model_(\d+)_steps", p.stem)
        return int(m.group(1)) if m else 0

    notes = {
         40000: "Early — chưa hội tụ Block phase, hay cần SafetyNet ESC",
         80000: "Mid — đã biết Allow/Redirect, chưa ổn Block",
        200000: "Mid-late — Block đã xuất hiện",
        480000: "Final — policy hội tụ tốt nhất",
        500000: "Final 500k — full training",
    }

    for i, ck in enumerate(ckpts, 1):
        sn = step_num(ck)
        note = notes.get(sn, "")
        table.add_row(str(i), ck.stem, note)

    if mode == "train":
        table.add_row("0", "(skip — fresh PPO)", "Train từ random init, không load gì")

    console.print(table)

    valid = [str(i) for i in range(1, len(ckpts) + 1)]
    if mode == "train":
        valid.append("0")
    default_idx = next((i + 1 for i, c in enumerate(ckpts)
                        if "480000" in c.stem or "500000" in c.stem), len(ckpts))
    choice = IntPrompt.ask("\nChọn", choices=valid, default=default_idx)

    if choice == 0:
        return "", None  # fresh PPO for train mode

    chosen = ckpts[choice - 1]
    # Path WITHOUT .zip extension (PPO.load can take either)
    return str(chosen.with_suffix("")), chosen.stem


def ask_steps() -> int:
    console.print("\n[bold yellow]── BƯỚC 3: Số STEP cần capture ──[/]")
    table = Table(box=None, padding=(0, 2))
    table.add_column("[bold]Steps", style="bright_cyan", justify="right", width=8)
    table.add_column("[bold]Use case", style="dim")
    table.add_column("[bold]Thời gian rollout", style="dim")
    table.add_row("16",  "Cycle 1 — show 16 IP types khác nhau",   "~2 giây")
    table.add_row("32",  "Cycle 2 — bắt đầu thấy effect_t-1 ≠ 0",  "~3 giây")
    table.add_row("100", "Default — đủ cho demo trước hội đồng",   "~10 giây")
    table.add_row("320", "1 episode đầy đủ — đủ thấy escalation",  "~30 giây")
    table.add_row("1000","Long capture — analytics post-hoc",      "~90 giây")
    console.print(table)
    return IntPrompt.ask("\nNhập số steps", default=100)


def ask_display() -> tuple[bool, int]:
    """Return (no_live, delay_ms)."""
    console.print("\n[bold yellow]── BƯỚC 4: Display style ──[/]")
    table = Table(box=None, padding=(0, 2))
    table.add_column("[bold]#", width=3)
    table.add_column("[bold]Style", style="bright_cyan")
    table.add_column("[bold]Mô tả")
    table.add_row("1", "Live dashboard (fast)",
                  "Rich TUI multi-panel cuộn nhanh (delay 120ms/step) — default")
    table.add_row("2", "Live dashboard (demo speed)",
                  "Rich TUI chậm (delay 800ms/step) — đọc kịp từng step trước hội đồng")
    table.add_row("3", "Live dashboard (very slow)",
                  "Rich TUI rất chậm (delay 1500ms/step) — giải thích từng decision")
    table.add_row("4", "Headless (chỉ JSONL + HTML)",
                  "Không show terminal, chỉ ghi file → mở HTML report trong browser")
    console.print(table)
    choice = IntPrompt.ask("\nChọn", choices=["1", "2", "3", "4"], default=2)
    if choice == 1:
        return False, 120
    if choice == 2:
        return False, 800
    if choice == 3:
        return False, 1500
    return True, 0


def ask_deterministic(mode: str) -> bool:
    if mode == "train":
        return False  # training always stochastic
    console.print("\n[bold yellow]── BƯỚC 5: Policy sampling ──[/]")
    console.print(
        "[dim]Stochastic = sample theo softmax (giống lúc train). "
        "Deterministic = always pick argmax (reproducible cho demo).[/]")
    return Confirm.ask("Dùng deterministic (argmax)?", default=False)


def confirm_and_run(args: dict):
    console.print("\n[bold yellow]── XÁC NHẬN ──[/]")
    panel = Table(box=None, padding=(0, 2))
    panel.add_column("[bold]Option", style="bold white")
    panel.add_column("[bold]Value", style="bright_cyan")
    panel.add_row("mode", args["mode"])
    if args["mode"] == "rollout":
        panel.add_row("checkpoint", args["source_label"] or "(none)")
        panel.add_row("deterministic", "yes" if args["deterministic"] else "no")
    else:
        panel.add_row("base_checkpoint", args["source_label"] or "(fresh PPO)")
    panel.add_row("steps", str(args["steps"]))
    panel.add_row("display", "headless" if args["no_live"] else f"live (delay {args['delay_ms']}ms)")
    console.print(panel)

    cmd = ["python3", "inspect_train.py", "--mode", args["mode"], "--steps", str(args["steps"])]
    if args["mode"] == "rollout":
        if args["checkpoint"]:
            cmd += ["--checkpoint", args["checkpoint"]]
        if args["deterministic"]:
            cmd.append("--deterministic")
    else:
        if args["checkpoint"]:
            cmd += ["--base-checkpoint", args["checkpoint"]]
    cmd += ["--delay-ms", str(args["delay_ms"])]
    if args["no_live"]:
        cmd.append("--no-live")

    console.print("\n[dim]Lệnh tương đương:[/]")
    console.print(f"  [bright_black]$ {' '.join(cmd)}[/]")

    if not Confirm.ask("\n[bold]Chạy ngay?[/]", default=True):
        console.print("[dim]Đã hủy. Có thể copy lệnh ở trên để chạy thủ công.[/]")
        return

    console.rule("[bold green]Bắt đầu chạy[/]")
    # Run from BASE_DIR so relative paths work
    subprocess.run(cmd, cwd=str(BASE_DIR))


def main():
    show_intro()

    mode = ask_mode()
    checkpoint, source_label = ask_checkpoint(mode)
    steps = ask_steps()
    no_live, delay_ms = ask_display()
    deterministic = ask_deterministic(mode)

    args = {
        "mode": mode,
        "checkpoint": checkpoint,
        "source_label": source_label,
        "steps": steps,
        "no_live": no_live,
        "delay_ms": delay_ms,
        "deterministic": deterministic,
    }
    confirm_and_run(args)


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        console.print("\n[dim]Đã thoát (Ctrl+C).[/]")
