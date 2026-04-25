"""
Phân tích segment trong actions.log.
Usage:
    python3 analyze_log.py 153 358
    python3 analyze_log.py 545 650
"""
import json, sys

LOG = "actions.log"
AC  = ["Allow", "RateLimit", "Redirect", "Block"]

def analyze(start: int, end: int):
    lines = open(LOG).readlines()
    rows  = []
    for l in lines[start-1 : end]:
        try: rows.append(json.loads(l))
        except: pass

    n = len(rows)
    if n == 0:
        print(f"Không có dòng nào từ {start} đến {end}.")
        return

    print(f"\nSegment dòng {start}–{end}  ({n} windows)")
    print("="*55)

    # Action distribution (RL decision)
    print(f"{'Action':<12} {'Count':>6} {'%':>7}  {'P_avg':>7}  {'P_min':>7}  {'P_max':>7}")
    print("-"*55)
    for ac in AC:
        chosen   = [r for r in rows if r.get("rl_action_name") == ac]
        probs_ac = [r["action_probs"][ac] for r in rows if "action_probs" in r]
        count    = len(chosen)
        pct      = count / n * 100
        avg_p    = sum(probs_ac) / len(probs_ac) if probs_ac else 0
        min_p    = min(probs_ac) if probs_ac else 0
        max_p    = max(probs_ac) if probs_ac else 0
        marker   = " ◄" if count == max(len([r for r in rows if r.get("rl_action_name")==a]) for a in AC) else ""
        print(f"{ac:<12} {count:>6} {pct:>6.1f}%  {avg_p:>7.3f}  {min_p:>7.3f}  {max_p:>7.3f}{marker}")

    # SafetyNet ESC chi tiết
    esc_rows = [(start + i, r) for i, r in enumerate(rows)
                if r.get("rl_action_name") != r.get("final_action_name")]
    print("-"*55)
    print(f"SafetyNet ESC: {len(esc_rows)} lần ({len(esc_rows)/n*100:.1f}%)")
    print(f"Total:         {n} windows")

    if esc_rows:
        print(f"\n{'─'*65}")
        print("Chi tiết ESC:")
        print(f"{'─'*65}")
        for lineno, r in esc_rows:
            rl  = r.get("rl_action_name", "?")
            fin = r.get("final_action_name", "?")
            p   = r.get("action_probs", {})
            trl = r.get("t_redirect_hits", "?")
            tpr = r.get("t_presence_hits", "?")
            tho = r.get("t_honeypot_hits", "?")
            tes = r.get("t_escalation_score", "?")
            tbr = r.get("t_block_ready", "?")
            print(f"  Dòng {lineno:<5}  RL:{rl:<10} → SafetyNet:{fin}")
            print(f"           Probs  A={p.get('Allow',0):.3f}  RL={p.get('RateLimit',0):.3f}"
                  f"  R={p.get('Redirect',0):.3f}  B={p.get('Block',0):.3f}")
            print(f"           State  redirect={trl}  presence={tpr}"
                  f"  honeypot={tho}  esc={tes}  block_ready={tbr}")
            print()

if __name__ == "__main__":
    if len(sys.argv) != 3:
        print("Usage: python3 analyze_log.py <start_line> <end_line>")
        sys.exit(1)
    analyze(int(sys.argv[1]), int(sys.argv[2]))
