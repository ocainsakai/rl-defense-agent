"""
Benchmark Metric Helpers — Taxonomy, compute_metrics(), aggregation utilities.

Imported by evaluate_all.py.
"""

import numpy as np
from itertools import groupby

# ============================================================================
# IP TYPE TAXONOMY
# ============================================================================

BENIGN_TYPES  = {"benign"}
NOISY_TYPES   = {"noisy_normal"}
L7_TYPES      = {"brute_force", "brute_force_ka", "sqli", "xss", "sqli_xss"}
FLOOD_TYPES   = {"scan", "syn_flood"}
ATTACK_TYPES  = L7_TYPES | FLOOD_TYPES
KNOWN_IP_TYPES = ATTACK_TYPES | BENIGN_TYPES | NOISY_TYPES

# Expected exact action per ip_type
OPTIMAL_ACTION = {
    "benign":        0,  # Allow
    "noisy_normal":  1,  # RateLimit
    "brute_force":   2,  # Redirect
    "brute_force_ka":2,  # Redirect
    "sqli_xss":      2,  # Redirect
    "sqli":          2,  # Redirect
    "xss":           2,  # Redirect
    "scan":          3,  # Block
    "syn_flood":     3,  # Block
}

# Mitigation: any action that meaningfully restricts the attacker
MITIGATION_ACTIONS = {
    "scan":          {3},
    "syn_flood":     {3},
    "brute_force":   {2, 3},
    "brute_force_ka":{2, 3},
    "sqli_xss":      {2, 3},
    "sqli":          {2, 3},
    "xss":           {2, 3},
}

ACTION_SEVERITY = {0: 0, 1: 1, 2: 2, 3: 3}
ACTION_NAMES    = {0: "Allow", 1: "RateLimit", 2: "Redirect", 3: "Block"}

# ============================================================================
# METRIC COMPUTATION
# ============================================================================

def _pct(num, den):
    return float(num / den * 100) if den > 0 else 0.0


def compute_metrics(records: list, episode_rewards: list, eval_mode: str = "round_robin") -> dict:
    """
    Compute all benchmark metrics from per-step records.

    Per-step record fields:
        ip_type      : acted_ip_type string
        acted_ip     : IP identifier (for oscillation grouping); may be "unknown"
        action       : int 0-3
        active       : bool — attacker features not suppressed by prior block
        reward       : float per-step reward
        step_damage  : float per-step damage (from info or proxy)
        eval_seed    : int
        ep_idx       : int episode index within eval_seed
        step_idx     : int step index within episode
        eval_mode    : str
        train_seed   : int
    """
    total_steps = len(records)
    if total_steps == 0:
        return {"error": "no records"}

    rewards_arr = np.array(episode_rewards)

    # ── Active-step subsets ──────────────────────────────────────────────────
    active  = [r for r in records if r['active']]
    atk_act = [r for r in active  if r['ip_type'] in ATTACK_TYPES]
    l7_act  = [r for r in active  if r['ip_type'] in L7_TYPES]
    fld_act = [r for r in active  if r['ip_type'] in FLOOD_TYPES]
    ben_act = [r for r in active  if r['ip_type'] in BENIGN_TYPES]
    nsy_act = [r for r in active  if r['ip_type'] in NOISY_TYPES]

    # ── 1. Reward ─────────────────────────────────────────────────────────────
    mean_reward = float(np.mean(rewards_arr))
    std_reward  = float(np.std(rewards_arr))

    # ── 2. Action distribution (% across ALL steps) ──────────────────────────
    ac = [0, 0, 0, 0]
    for r in records:
        ac[r['action']] += 1
    action_dist = [c / total_steps * 100 for c in ac]

    # ── 3. Mitigation rate (attack active, got mitigating action) ────────────
    mitigated = [r for r in atk_act
                 if r['action'] in MITIGATION_ACTIONS.get(r['ip_type'], set())]
    mitigation_rate = _pct(len(mitigated), len(atk_act))

    # ── 4. Exact response rate (active, got OPTIMAL_ACTION) ──────────────────
    exact = [r for r in active
             if r['action'] == OPTIMAL_ACTION.get(r['ip_type'], -1)]
    exact_response_rate = _pct(len(exact), len(active))

    # ── 5. Per ip_type: exact rate + mitigation rate ──────────────────────────
    per_ip_type_exact_rate      = {}
    per_ip_type_mitigation_rate = {}
    for ipt in KNOWN_IP_TYPES:
        ipt_active = [r for r in active if r['ip_type'] == ipt]
        if not ipt_active:
            continue
        opt = OPTIMAL_ACTION.get(ipt, -1)
        per_ip_type_exact_rate[ipt] = _pct(
            sum(1 for r in ipt_active if r['action'] == opt), len(ipt_active))
        mit_set = MITIGATION_ACTIONS.get(ipt, set())
        per_ip_type_mitigation_rate[ipt] = _pct(
            sum(1 for r in ipt_active if r['action'] in mit_set), len(ipt_active)) \
            if mit_set else None

    # ── 6. Honeypot / L7 metrics ──────────────────────────────────────────────
    l7_redirected   = [r for r in l7_act if r['action'] == 2]
    l7_over_blocked = [r for r in l7_act if r['action'] == 3]
    honeypot_capture_rate  = _pct(len(l7_redirected),   len(l7_act))
    l7_exact_redirect_rate = honeypot_capture_rate   # same definition
    l7_over_block_rate     = _pct(len(l7_over_blocked), len(l7_act))

    # ── 7. Benign protection ──────────────────────────────────────────────────
    ben_rl  = [r for r in ben_act if r['action'] == 1]
    ben_red = [r for r in ben_act if r['action'] == 2]
    ben_blk = [r for r in ben_act if r['action'] == 3]
    ben_any = ben_rl + ben_red + ben_blk
    benign_intervention_rate = _pct(len(ben_any), len(ben_act))
    benign_ratelimit_rate    = _pct(len(ben_rl),  len(ben_act))
    benign_redirect_rate     = _pct(len(ben_red), len(ben_act))
    benign_block_rate        = _pct(len(ben_blk), len(ben_act))

    # ── 8. Noisy traffic ──────────────────────────────────────────────────────
    nsy_exact     = [r for r in nsy_act if r['action'] == 1]
    nsy_over      = [r for r in nsy_act
                     if ACTION_SEVERITY[r['action']] > ACTION_SEVERITY[OPTIMAL_ACTION.get('noisy_normal', 1)]]
    noisy_exact_rate          = _pct(len(nsy_exact), len(nsy_act))
    noisy_over_mitigation_rate = _pct(len(nsy_over), len(nsy_act))

    # ── 9. Over / under mitigation (active steps) ────────────────────────────
    over  = [r for r in active
             if r['ip_type'] in OPTIMAL_ACTION
             and ACTION_SEVERITY[r['action']] > ACTION_SEVERITY[OPTIMAL_ACTION[r['ip_type']]]]
    under = [r for r in atk_act
             if r['action'] not in MITIGATION_ACTIONS.get(r['ip_type'], set())]
    over_mitigation_rate  = _pct(len(over),  len(active))
    under_mitigation_rate = _pct(len(under), len(atk_act))

    # ── 10. Service damage ────────────────────────────────────────────────────
    total_damage    = sum(r['step_damage'] for r in records)
    mean_step_damage  = total_damage / total_steps if total_steps > 0 else 0.0
    service_damage_auc = mean_step_damage   # alias

    # ── 11. Action oscillation (per IP, not global consecutive steps) ─────────
    #
    # Group by (eval_mode, train_seed, eval_seed, ep_idx, acted_ip).
    # Within each group sort by step_idx.
    # Oscillation = action changed between consecutive appearances of same IP.
    #
    # Falls back to global consecutive-step oscillation if acted_ip unavailable.
    ip_known = all(r.get('acted_ip', 'unknown') != 'unknown' for r in records)

    osc_changes = 0
    osc_total   = 0

    if ip_known:
        ip_key = lambda r: (r.get('eval_mode',''), r.get('train_seed', 0),
                            r['eval_seed'], r['ep_idx'], r.get('acted_ip',''))
        step_key = lambda r: r.get('step_idx', 0)
        for _, grp in groupby(sorted(records, key=ip_key), key=ip_key):
            grp_list = sorted(grp, key=step_key)
            acts = [g['action'] for g in grp_list]
            if len(acts) > 1:
                osc_changes += sum(acts[i] != acts[i-1] for i in range(1, len(acts)))
                osc_total   += len(acts) - 1
    else:
        # Fallback: global consecutive steps within each episode
        ep_key = lambda r: (r['eval_seed'], r['ep_idx'])
        for _, grp in groupby(sorted(records, key=ep_key), key=ep_key):
            acts = [g['action'] for g in grp]
            if len(acts) > 1:
                osc_changes += sum(acts[i] != acts[i-1] for i in range(1, len(acts)))
                osc_total   += len(acts) - 1

    action_oscillation_rate = _pct(osc_changes, osc_total)

    # ── 12. Confusion matrix (active steps: rows=GT, cols=predicted) ──────────
    cm = np.zeros((4, 4), dtype=int)
    for r in active:
        gt = OPTIMAL_ACTION.get(r['ip_type'])
        if gt is not None:
            cm[gt][r['action']] += 1

    # ── 13. Per-class recall / precision / F1 + macro-F1 ─────────────────────
    per_class_recall    = []
    per_class_precision = []
    per_class_f1        = []
    for cls in range(4):
        tp = int(cm[cls, cls])
        fn = int(cm[cls].sum()) - tp
        fp = int(cm[:, cls].sum()) - tp
        rec  = tp / (tp + fn) if (tp + fn) > 0 else 0.0
        prec = tp / (tp + fp) if (tp + fp) > 0 else 0.0
        f1   = 2*prec*rec / (prec+rec) if (prec+rec) > 0 else 0.0
        per_class_recall.append(float(rec))
        per_class_precision.append(float(prec))
        per_class_f1.append(float(f1))
    macro_f1 = float(np.mean(per_class_f1))

    # ── 14. Legacy metrics (backward compat) ─────────────────────────────────
    atk_all = [(r['ip_type'], r['action']) for r in records if r['ip_type'] in ATTACK_TYPES]
    det_strict = [(ipt, a) for ipt, a in atk_all if a in MITIGATION_ACTIONS.get(ipt, set())]
    det_loose  = [a for _, a in atk_all if a >= 1]
    detection_rate_raw_strict = _pct(len(det_strict), len(atk_all))
    detection_rate_raw_loose  = _pct(len(det_loose),  len(atk_all))

    # ── 15. Dynamic / thesis-control metrics ─────────────────────────────────
    #
    # L7 optimal action depends on escalation state (block_ready_before):
    #   block_ready_before=False → optimal = Redirect (hold, gather honeypot data)
    #   block_ready_before=True  → optimal = Block    (escalate on time)
    #
    # Records only have these fields if env exposes temporal_snapshot in info.
    # Falls back gracefully to 0 if field absent.
    has_dynamic = any('block_ready_before' in r for r in records)

    dyn_exact = 0; dyn_total = 0
    l7_redirect_hold = 0; l7_redirect_hold_total = 0
    l7_ontime_block  = 0; l7_premature_block = 0; l7_late_under = 0
    l7_dyn_total     = 0

    if has_dynamic:
        for r in l7_act:
            block_ready = r.get('block_ready_before', False)
            act = r['action']
            dyn_total += 1
            l7_dyn_total += 1

            if not block_ready:
                # Phase: hold — Redirect is optimal
                l7_redirect_hold_total += 1
                if act == 2:
                    l7_redirect_hold += 1
                    dyn_exact += 1
                elif act == 3:
                    l7_premature_block += 1   # blocked too early
            else:
                # Phase: escalate — Block is optimal
                if act == 3:
                    l7_ontime_block += 1
                    dyn_exact += 1
                elif act == 2:
                    l7_late_under += 1        # still redirecting when should block

        # Also count non-L7 active steps with standard optimal
        for r in active:
            if r['ip_type'] in L7_TYPES:
                continue  # already counted above
            if r['action'] == OPTIMAL_ACTION.get(r['ip_type'], -1):
                dyn_exact += 1
            dyn_total += 1

    dynamic_exact_response_rate = _pct(dyn_exact, dyn_total) if has_dynamic else None
    l7_redirect_hold_rate       = _pct(l7_redirect_hold, l7_redirect_hold_total) if has_dynamic else None
    l7_ontime_block_rate        = _pct(l7_ontime_block,  l7_dyn_total) if has_dynamic else None
    l7_premature_block_rate     = _pct(l7_premature_block, l7_dyn_total) if has_dynamic else None
    l7_late_under_escalation_rate = _pct(l7_late_under, l7_dyn_total) if has_dynamic else None

    # Safe intervention: action was necessary (active attack) and correct severity
    safe_int = [r for r in active
                if r['ip_type'] in ATTACK_TYPES
                and r['action'] in MITIGATION_ACTIONS.get(r['ip_type'], set())]
    safe_intervention_rate = _pct(len(safe_int), len(active))

    # ── 16. Security-Usability Tradeoff Metrics ──────────────────────────────
    #
    # mitigation_efficiency = mitigation_rate / benign_intervention_rate
    #   How much attack mitigation is obtained per unit of benign-user intervention.
    #   "Benign intervention" = any non-Allow action on benign traffic (RateLimit,
    #   Redirect, or Block) — a broad proxy for operational disruption to legit users.
    #   This is NOT equivalent to false positive rate; it is a tradeoff indicator.
    #   All models are evaluated deterministically (deterministic=True), so lower
    #   benign intervention is an empirical property of the learned policy, not of
    #   stochastic sampling at eval time.
    #
    # benign_harm_score = 1×RL + 2×Redirect + 3×Block on benign steps
    #   Weights reflect operational severity: blocking > redirecting > rate-limiting.
    #   Provides a severity-aware alternative to the flat benign_intervention_rate.
    #
    # weighted_mitigation_efficiency = mitigation_rate / benign_harm_score
    #   Same concept as mitigation_efficiency but penalises harsher benign actions
    #   more heavily.
    mitigation_efficiency = (mitigation_rate / benign_intervention_rate
                             if benign_intervention_rate > 0 else float('inf'))

    benign_harm_score = (1.0 * benign_ratelimit_rate
                         + 2.0 * benign_redirect_rate
                         + 3.0 * benign_block_rate)
    weighted_mitigation_efficiency = (mitigation_rate / benign_harm_score
                                      if benign_harm_score > 0 else float('inf'))

    # ── 17. Security Score (SS) ───────────────────────────────────────────────
    #
    # Severity-distance weighted threat response across all active attack steps.
    # Score = f(|action - OPTIMAL_ACTION|) so the same credit scale applies to every
    # ip_type — flood steps and L7 steps are comparable.
    #
    # Distance table (d = |action − optimal|):
    #   d=0  → 1.00  exact match
    #   d=1  → 0.50  one level off (over- or under-mitigation)
    #   d=2  → 0.25  two levels off
    #   d≥3  → 0.00  maximum distance
    #
    # Special rule: action=0 (Allow) on any attack → 0.00, overriding the distance
    # formula. This creates an intentional discontinuity for L7 types (optimal=2):
    # Allow sits at d=2, which the formula would score 0.25, but we floor it to 0.0.
    # Rationale: doing nothing is a qualitatively different failure from acting at
    # the wrong severity level. This design choice must be stated explicitly in the
    # thesis: "for L7 threats, Allow scores 0.0 while RateLimit scores 0.5, even
    # though both are one or two severity levels from optimal."
    #
    # Examples:
    #   scan/syn_flood (optimal=3): Allow→0.0, RL→0.25, Redirect→0.50, Block→1.0
    #   sqli/xss (optimal=2):       Allow→0.0, RL→0.50, Redirect→1.0,  Block→0.50
    #
    # Known design limitation: the action space is treated as ordinal with equal
    # gaps — d=1(Allow→RL) and d=1(Redirect→Block) both score 0.50, even though
    # operationally "Redirect→Block" is a more significant escalation. This is a
    # metric simplification; the thesis should acknowledge it alongside the choice
    # to prioritise uniform scoring over operational gap calibration.
    # All steps are equally weighted; damage-proportional weighting (step_damage)
    # would capture flood-vs-L7 severity difference at the cost of reward coupling.
    #
    # Returns None (not 0.0) when no attack steps are present — downstream tables
    # show N/A rather than misleading 0.0.
    _SS_DIST_SCORE = {0: 1.0, 1: 0.5, 2: 0.25}   # distance → score; ≥3 → 0.0

    ss_scores = []
    for r in atk_act:
        opt = OPTIMAL_ACTION.get(r['ip_type'], -1)
        if opt == -1:
            continue
        if r['action'] == 0:
            ss_scores.append(0.0)
        else:
            ss_scores.append(_SS_DIST_SCORE.get(abs(r['action'] - opt), 0.0))
    security_score = float(np.mean(ss_scores) * 100) if ss_scores else None

    # ── 18. Availability Score (AS) ──────────────────────────────────────────
    #
    # Severity-weighted service continuity for benign users.
    #
    #   1.0000  Allow      — full service
    #   0.6667  RateLimit  — throttled but real service accessible (HTTP 429)
    #   0.3333  Redirect   — redirected to honeypot; real service inaccessible
    #   0.0     Block      — complete outage
    #
    # Weights use uniform Δ = 1/3 per action level. This is itself an assumption —
    # that each severity step causes equal loss of availability. It is not "no
    # assumption"; it is a neutral choice that avoids relying on honeypot response
    # content (which is implementation-specific). The thesis should state: "we adopt
    # uniform spacing as a conservative, defensible baseline; the actual availability
    # loss per action level may differ in deployment."
    # The same ordinal-gap limitation noted for SS applies here: Allow→RateLimit and
    # RateLimit→Redirect are treated as equal steps, even though the latter
    # transitions users from real service to a honeypot (qualitatively more severe).
    #
    # Known limitations (by design, not fixable at metric level):
    #   - Temporal: RateLimit for 1 step then Allow scores identically to RateLimit
    #     for 100 steps. Duration of disruption is not captured.
    #   - NAT: each IP counts as one "user." A corporate NAT gateway behind one IP
    #     and a residential user behind another IP are weighted equally.
    #
    # Returns None (not 100.0) when no benign steps — avoids inflating SAB.
    _AVAIL_WEIGHT = {0: 1.0, 1: round(2/3, 4), 2: round(1/3, 4), 3: 0.0}
    avail_scores = [_AVAIL_WEIGHT[r['action']] for r in ben_act]
    availability_score = float(np.mean(avail_scores) * 100) if avail_scores else None

    # ── 19. Security-Availability Balance (SAB) ───────────────────────────────
    #
    # Harmonic mean of SS and AS (both normalised to [0,1]).
    # Analogous to F1: rewards agents that are strong on BOTH axes simultaneously;
    # a near-zero score on either axis collapses the composite.
    # None if either SS or AS is None (no data on that axis).
    if security_score is None or availability_score is None:
        sab = None
    else:
        ss_n = security_score / 100.0
        as_n = availability_score / 100.0
        sab = float(2 * ss_n * as_n / (ss_n + as_n) * 100) if (ss_n + as_n) > 0 else 0.0


    return {
        # ── Core ──────────────────────────────────────────────────────────────
        "eval_mode":                 eval_mode,
        "mean_reward":               mean_reward,
        "std_reward":                std_reward,
        "action_dist":               action_dist,
        "total_steps":               total_steps,
        "episode_rewards":           episode_rewards,

        # ── Tier 1: Algorithmic Baseline ──────────────────────────────────────
        "mitigation_rate":           mitigation_rate,
        "detection_rate":            mitigation_rate,        # alias
        "exact_response_rate":       exact_response_rate,
        "macro_f1":                  macro_f1,
        "per_class_recall":          per_class_recall,
        "per_class_precision":       per_class_precision,
        "per_class_f1":              per_class_f1,
        "confusion_matrix":          cm.tolist(),
        "per_ip_type_exact_rate":    per_ip_type_exact_rate,
        "per_ip_type_mitigation_rate": per_ip_type_mitigation_rate,
        "detection_rate_raw_strict": detection_rate_raw_strict,
        "detection_rate_raw_loose":  detection_rate_raw_loose,

        # ── Tier 2: Operational Suitability ───────────────────────────────────
        # L7/Honeypot
        "honeypot_capture_rate":     honeypot_capture_rate,
        "l7_exact_redirect_rate":    l7_exact_redirect_rate,
        "l7_over_block_rate":        l7_over_block_rate,
        # Benign
        "benign_intervention_rate":  benign_intervention_rate,
        "benign_ratelimit_rate":     benign_ratelimit_rate,
        "benign_redirect_rate":      benign_redirect_rate,
        "benign_block_rate":         benign_block_rate,
        "fp_rate":                   benign_block_rate,      # compat alias
        # Noisy
        "noisy_exact_rate":          noisy_exact_rate,
        "noisy_over_mitigation_rate":noisy_over_mitigation_rate,
        # Response quality
        "over_mitigation_rate":      over_mitigation_rate,
        "under_mitigation_rate":     under_mitigation_rate,
        "service_damage_auc":        float(service_damage_auc),
        "mean_step_damage":          float(mean_step_damage),
        # Stability
        "action_oscillation_rate":   action_oscillation_rate,
        "oscillation_method":        "per_ip" if ip_known else "global_fallback",

        # ── Tier 3: Thesis-control / dynamic metrics ─────────────────────────
        "has_dynamic_metrics":            has_dynamic,
        "dynamic_exact_response_rate":    dynamic_exact_response_rate,
        "l7_redirect_hold_rate":          l7_redirect_hold_rate,
        "l7_ontime_block_rate":           l7_ontime_block_rate,
        "l7_premature_block_rate":        l7_premature_block_rate,
        "l7_late_under_escalation_rate":  l7_late_under_escalation_rate,
        "safe_intervention_rate":         safe_intervention_rate,
        # ── Security-Usability Tradeoff (operational indicators, not primary winners)
        "mitigation_efficiency":          mitigation_efficiency,
        "benign_harm_score":              benign_harm_score,
        "weighted_mitigation_efficiency": weighted_mitigation_efficiency,
        # ── Security / Availability composite scores ──────────────────────────
        "security_score":                 security_score,
        "availability_score":             availability_score,
        "security_availability_balance":  sab,

        # ── Step counts ───────────────────────────────────────────────────────
        "n_total_steps":             total_steps,
        "n_active_steps":            len(active),
        "n_active_attack_steps":     len(atk_act),
        "n_active_l7_steps":         len(l7_act),
        "n_active_flood_steps":      len(fld_act),
        "n_active_benign_steps":     len(ben_act),
        "n_active_noisy_steps":      len(nsy_act),
        "n_total_attack_steps":      len(atk_all),
    }


# ============================================================================
# AGGREGATION
# ============================================================================

_SCALAR_METRICS = [
    "mean_reward",
    "mitigation_rate", "exact_response_rate", "macro_f1",
    "honeypot_capture_rate", "l7_exact_redirect_rate", "l7_over_block_rate",
    "benign_intervention_rate", "benign_ratelimit_rate",
    "benign_redirect_rate", "benign_block_rate", "fp_rate",
    "noisy_exact_rate", "noisy_over_mitigation_rate",
    "over_mitigation_rate", "under_mitigation_rate",
    "service_damage_auc", "mean_step_damage",
    "action_oscillation_rate",
    "detection_rate_raw_strict", "detection_rate_raw_loose",
    # dynamic/thesis (None when env doesn't expose temporal_snapshot)
    "safe_intervention_rate",
    "dynamic_exact_response_rate",
    "l7_redirect_hold_rate",
    "l7_ontime_block_rate",
    "l7_premature_block_rate",
    "l7_late_under_escalation_rate",
    # security-usability tradeoff (ratio metrics — aggregate recomputed from agg rates)
    "benign_harm_score",
    "mitigation_efficiency",
    "weighted_mitigation_efficiency",
    # security / availability composite (SAB recomputed from agg SS+AS in aggregate_seeds)
    "security_score",
    "availability_score",
    "security_availability_balance",
]


def aggregate_seeds(seed_results: dict) -> dict:
    """
    Aggregate per-train-seed results into mean ± 95% CI.
    seed_results: {str(train_seed): metrics_dict, ...}
    """
    keys = [k for k in seed_results if not k.startswith("_")]
    if not keys:
        return {}

    def _agg(metric):
        vals = [seed_results[k][metric] for k in keys
                if metric in seed_results[k]
                and seed_results[k][metric] is not None
                and seed_results[k][metric] != float('inf')]
        if not vals:
            return None, 0.0, 0.0
        arr = np.array(vals, dtype=float)
        m   = float(np.mean(arr))
        s   = float(np.std(arr, ddof=1)) if len(arr) > 1 else 0.0
        ci  = float(1.96 * s / np.sqrt(len(arr))) if len(arr) > 1 else 0.0
        return m, s, ci

    out = {"n_seeds": len(keys)}
    for metric in _SCALAR_METRICS:
        m, s, ci = _agg(metric)
        out[metric]           = m
        out[metric + "_std"]  = s
        out[metric + "_ci95"] = ci

    # Convenience aliases
    _, std_r, ci_r = _agg("mean_reward")
    out["std_reward"] = std_r
    out["ci95"]       = ci_r

    # Action dist mean
    act_dists = np.array([seed_results[k]["action_dist"] for k in keys])
    out["action_dist_mean"] = act_dists.mean(axis=0).tolist()

    # Confusion matrix mean
    cms = np.array([seed_results[k]["confusion_matrix"] for k in keys])
    out["confusion_matrix_mean"] = cms.mean(axis=0).tolist()

    # Per-class recall / precision / F1 mean
    for field in ("per_class_recall", "per_class_precision", "per_class_f1"):
        arrs = [seed_results[k][field] for k in keys if field in seed_results[k]]
        if arrs:
            out[field + "_mean"] = np.array(arrs).mean(axis=0).tolist()

    # Per ip_type exact rate mean (dict of dicts → dict of means)
    ipt_exact = {}
    for ipt in KNOWN_IP_TYPES:
        vals = [seed_results[k]["per_ip_type_exact_rate"].get(ipt)
                for k in keys
                if "per_ip_type_exact_rate" in seed_results[k]
                and seed_results[k]["per_ip_type_exact_rate"].get(ipt) is not None]
        if vals:
            ipt_exact[ipt] = float(np.mean(vals))
    out["per_ip_type_exact_rate_mean"] = ipt_exact

    # Ratio metrics recomputed from aggregate rates — more stable than mean(per-seed ratios)
    # because per-seed denominators can be near-zero causing high variance.
    # Use `or 0` so that None (key present, no valid seeds) collapses to 0 safely.
    agg_mit  = out.get("mitigation_rate") or 0
    agg_ben  = out.get("benign_intervention_rate") or 0
    agg_rl   = out.get("benign_ratelimit_rate") or 0
    agg_red  = out.get("benign_redirect_rate") or 0
    agg_blk  = out.get("benign_block_rate") or 0

    out["mitigation_efficiency"] = (agg_mit / agg_ben if agg_ben > 0 else float("inf"))

    agg_harm = 1.0 * agg_rl + 2.0 * agg_red + 3.0 * agg_blk
    out["benign_harm_score"] = agg_harm
    out["weighted_mitigation_efficiency"] = (agg_mit / agg_harm if agg_harm > 0 else float("inf"))

    # SAB recomputed from aggregate SS and AS — avoids inflated CI from per-seed harmonic means.
    # out.get() without default: returns None when key exists but value is None.
    agg_ss = out.get("security_score")
    agg_as = out.get("availability_score")
    if agg_ss is None or agg_as is None:
        out["security_availability_balance"] = None
    else:
        out["security_availability_balance"] = (
            2 * agg_ss * agg_as / (agg_ss + agg_as) if (agg_ss + agg_as) > 0 else 0.0
        )

    return out