#!/usr/bin/env python3
"""
Feature Analysis Script - Test payload features against real datasets.

Tests:
  - SQLi features on sqli.csv + sqliv2.csv
  - XSS  features on XSS_dataset.csv
  - All payload features on CSIC dataset (realistic HTTP context)

Metrics per feature:
  - TPR (True Positive Rate / Recall)
  - FPR (False Positive Rate)
  - F1 Score
  - Mean value for attack vs normal

ARCHITECTURE:
  compute_all() calls ACTUAL production feature classes.
  CRS-powered features (F18, F25) load patterns from:
    REQUEST-942-APPLICATION-ATTACK-SQLI.conf  (19 rules at PL1)
    REQUEST-941-APPLICATION-ATTACK-XSS.conf   (22 rules + 9 phrases at PL1)
"""

import sys, os, time, re, warnings
from urllib.parse import urlparse

warnings.filterwarnings('ignore')
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import pandas as pd

# ── Production feature classes ─────────────────────────────────────────────────
from feature.context import FeatureContext
from feature.calculators.payload_features import (
    F9_PayloadLength, F10_PayloadEntropy,
    F11_SqliKeyword, F12_SqlSpecialChar,
    F13_XssKeyword, F14_XssSpecialChar,
)
from feature.calculators.sqli_features import (
    F18_CrsSquliScore,
    F19_SqlUnionSelect,
    F20_SqlComment,
    F22_SqlStackedQuery,
    F23_SqlSelectCount,
)
from feature.calculators.xss_features import (
    F25_CrsXssScore,
    F26_JsFunctionCall,
    F27_HtmlEventHandler,
)

# ── Feature instances (module-level, created once) ─────────────────────────────
_f9   = F9_PayloadLength()
_f10  = F10_PayloadEntropy()
_f11  = F11_SqliKeyword()
_f12  = F12_SqlSpecialChar()
_f13  = F13_XssKeyword()
_f14  = F14_XssSpecialChar()
_f18  = F18_CrsSquliScore()    # CRS 942 score — broad coverage
_f19  = F19_SqlUnionSelect()   # UNION SELECT — data extraction
_f20  = F20_SqlComment()       # --, #, /**/ — query truncation
_f22  = F22_SqlStackedQuery()  # ; DROP/DELETE — destructive
_f23  = F23_SqlSelectCount()
_f25  = F25_CrsXssScore()      # NEW: CRS 941 score (replaces F25, F28-F30)
_f26  = F26_JsFunctionCall()
_f27  = F27_HtmlEventHandler()


# ============================================================
# MOCK OBJECTS (simulate FlowState/LayerInfo without Scapy)
# ============================================================

class MockLayerInfo:
    def __init__(self, payload_bytes=b'', http_uri=None, http_user_agent=None):
        self.has_http        = True
        self.has_payload     = bool(payload_bytes) or bool(http_uri)
        self.payload_bytes   = payload_bytes or b''
        self.payload_length  = len(self.payload_bytes)
        self.http_uri        = http_uri
        self.http_user_agent = http_user_agent
        self.http_method     = 'POST'
        self.http_host       = 'localhost'
        self.http_status     = None
        self.has_tcp         = True
        self.tcp_flags       = 'PA'
        self.tcp_sport       = 54321
        self.tcp_dport       = 80
        self.tcp_seq         = 0
        self.tcp_ack         = 1000
        self.tcp_window      = 65535
        self.timestamp       = time.time()
        self.has_ip          = True
        self.src_ip          = '10.0.0.1'
        self.dst_ip          = '10.0.0.2'
        self.ttl             = 64
        self.ip_len          = 100
        self.protocol        = 6
        self.ip_version      = 4
        self.x_real_ip       = None
        self.x_request_id    = None
        self.has_dns         = False
        self.dns_query       = None


class MockFlowState:
    def __init__(self, packets, window_size=1.0):
        self.flow_key    = ('10.0.0.1', '10.0.0.2', 54321, 80, 6)
        self.window_size = window_size
        self._fwd        = list(packets)
        self._bwd        = []
        self.created_at  = time.time()
        self.last_update = self.created_at
        self._x_real_ip  = None

    def get_fwd_packets(self):       return self._fwd
    def get_bwd_packets(self):       return self._bwd
    def get_packet_count(self):      return len(self._fwd) + len(self._bwd)
    def get_fwd_packet_count(self):  return len(self._fwd)
    def get_bwd_packet_count(self):  return len(self._bwd)
    def get_distinct_ports(self):
        return {p.tcp_dport for p in self._fwd if p.has_tcp and p.tcp_dport}
    def get_fwd_payload_lengths(self):
        return [p.payload_length for p in self._fwd if p.has_payload]
    def get_fwd_payloads(self):
        return [p.payload_bytes for p in self._fwd if p.has_payload and p.payload_bytes]
    def get_fwd_tcp_flags_count(self):
        counts = {'SYN':0,'ACK':0,'FIN':0,'RST':0,'PSH':0,'URG':0}
        for p in self._fwd:
            if p.has_tcp and p.tcp_flags:
                f = str(p.tcp_flags)
                if 'S' in f: counts['SYN'] += 1
                if 'A' in f: counts['ACK'] += 1
                if 'F' in f: counts['FIN'] += 1
                if 'R' in f: counts['RST'] += 1
                if 'P' in f: counts['PSH'] += 1
        return counts
    def get_bwd_tcp_flags_count(self):
        return {'SYN':0,'ACK':0,'FIN':0,'RST':0,'PSH':0,'URG':0}

    @property
    def src_ip(self):          return self.flow_key[0]
    @property
    def x_real_ip(self):       return self._x_real_ip
    @property
    def effective_src_ip(self):return self._x_real_ip or self.flow_key[0]
    @property
    def dst_ip(self):          return self.flow_key[1]
    @property
    def src_port(self):        return self.flow_key[2]
    @property
    def dst_port(self):        return self.flow_key[3]
    @property
    def protocol(self):        return self.flow_key[4]


def make_flow(payload_text, uri=None, user_agent=None):
    if isinstance(payload_text, str):
        payload_bytes = payload_text.encode('utf-8', errors='ignore')
    else:
        payload_bytes = payload_text or b''
    pkt = MockLayerInfo(payload_bytes=payload_bytes, http_uri=uri, http_user_agent=user_agent)
    return MockFlowState([pkt])


# ============================================================
# COMPUTE ALL FEATURES FOR ONE SAMPLE
# ============================================================

def compute_all(payload_text, uri=None, user_agent=None):
    """Compute all payload features using production feature classes."""
    flow = make_flow(payload_text, uri=uri, user_agent=user_agent)
    ctx  = FeatureContext([flow])

    r = {}

    # ── Payload features (F9-F14) ──────────────────────────────────────────────
    r['F9']  = _f9.calculate([flow],  context=ctx)
    r['F10'] = _f10.calculate([flow], context=ctx)
    r['F11'] = _f11.calculate([flow], context=ctx)
    r['F12'] = _f12.calculate([flow], context=ctx)
    r['F13'] = _f13.calculate([flow], context=ctx)
    r['F14'] = _f14.calculate([flow], context=ctx)

    # ── SQLi features (F18-F20, F22, F23) ─────────────────────────────────────
    r['F18'] = _f18.calculate([flow], context=ctx)   # CRS 942: 19 rules
    r['F19'] = _f19.calculate([flow], context=ctx)   # UNION SELECT
    r['F20'] = _f20.calculate([flow], context=ctx)   # comment (--, #, /**/)
    r['F22'] = _f22.calculate([flow], context=ctx)   # stacked (; DROP...)
    r['F23'] = _f23.calculate([flow], context=ctx)

    # ── CRS XSS score + kept features (F25, F26, F27) ─────────────────────────
    r['F25'] = _f25.calculate([flow], context=ctx)   # CRS 941: 22 rules + 9 phrases
    r['F26'] = _f26.calculate([flow], context=ctx)
    r['F27'] = _f27.calculate([flow], context=ctx)

    return r


# ============================================================
# BATCH PROCESSING
# ============================================================

def batch_compute(df, payload_col, label_col, uri_col=None, ua_col=None, sample_size=None):
    if sample_size and len(df) > sample_size:
        n   = sample_size // 2
        pos = df[df[label_col] == 1].sample(min(n, (df[label_col]==1).sum()), random_state=42)
        neg = df[df[label_col] == 0].sample(min(n, (df[label_col]==0).sum()), random_state=42)
        df  = pd.concat([pos, neg]).reset_index(drop=True)

    rows = []
    for _, row in df.iterrows():
        payload = str(row[payload_col]) if pd.notna(row[payload_col]) else ''
        uri     = str(row[uri_col])    if uri_col and pd.notna(row.get(uri_col,''))  else None
        ua      = str(row[ua_col])     if ua_col  and pd.notna(row.get(ua_col,''))   else None
        label   = int(row[label_col])
        try:
            feats = compute_all(payload, uri=uri, user_agent=ua)
            feats['label'] = label
            rows.append(feats)
        except Exception:
            pass

    return pd.DataFrame(rows)


# ============================================================
# METRICS
# ============================================================

def eval_at_threshold(values, labels, t):
    tp = sum(1 for v, l in zip(values, labels) if v >= t and l == 1)
    fp = sum(1 for v, l in zip(values, labels) if v >= t and l == 0)
    fn = sum(1 for v, l in zip(values, labels) if v <  t and l == 1)
    tn = sum(1 for v, l in zip(values, labels) if v <  t and l == 0)
    tpr  = tp / max(tp + fn, 1)
    fpr  = fp / max(fp + tn, 1)
    prec = tp / max(tp + fp, 1)
    f1   = 2 * prec * tpr / max(prec + tpr, 1e-9)
    return {'TPR': tpr, 'FPR': fpr, 'Prec': prec, 'F1': f1, 'Thr': t,
            'TP': tp, 'FP': fp, 'TN': tn, 'FN': fn}


def best_threshold_metrics(values, labels):
    vals   = list(values)
    labs   = list(labels)
    unique = sorted(set(vals))

    is_binary = set(unique).issubset({0.0, 1.0})
    if is_binary:
        return eval_at_threshold(vals, labs, 0.5)

    if len(unique) > 200:
        step   = max(1, len(unique) // 200)
        unique = unique[::step]

    candidates = [t for t in unique if t > min(unique)]
    if not candidates:
        return eval_at_threshold(vals, labs, unique[0])

    best = {'F1': -1}
    for t in candidates:
        m = eval_at_threshold(vals, labs, t)
        if m['F1'] > best['F1']:
            best = m
    return best


def verdict(m):
    if   m['F1'] >= 0.75 and m['FPR'] <= 0.15: return "KEEP   [OK]"
    elif m['F1'] >= 0.55 and m['FPR'] <= 0.30: return "WEAK   [~] "
    else:                                         return "REMOVE [X] "


def print_table(results_df, features, title):
    print(f"\n{'='*80}")
    print(f"  {title}")
    print(f"{'='*80}")
    n_att = (results_df['label'] == 1).sum()
    n_nor = (results_df['label'] == 0).sum()
    print(f"  Samples: {len(results_df)}  |  Attack: {n_att}  |  Normal: {n_nor}")
    print(f"{'='*80}")
    hdr = f"{'Feature':<14} {'Atk Mean':>10} {'Nor Mean':>10} {'TPR':>7} {'FPR':>7} {'F1':>7} {'Threshold':>11}  {'Verdict'}"
    print(hdr)
    print("-" * 82)
    decisions = {}
    for feat in features:
        if feat not in results_df.columns:
            continue
        atk_mean = results_df[results_df['label']==1][feat].mean()
        nor_mean = results_df[results_df['label']==0][feat].mean()
        m = best_threshold_metrics(results_df[feat], results_df['label'])
        v = verdict(m)
        decisions[feat] = v
        print(f"{feat:<14} {atk_mean:>10.4f} {nor_mean:>10.4f} {m['TPR']:>7.3f} {m['FPR']:>7.3f} {m['F1']:>7.3f} {m['Thr']:>11.4f}  {v}")
    return decisions


# ============================================================
# MAIN
# ============================================================

def main():
    print("\n" + "="*80)
    print("  FEATURE ANALYSIS — CRS-powered features vs Real Datasets")
    print("  Network features F1-F5, F15-F17 need PCAP — skipped here.")
    print("="*80)

    print("\n[1/4] Loading datasets...")
    SAMPLE = 3000

    df_sqli1 = pd.read_csv('dataset/sqli.csv',   encoding='utf-16')[['Sentence','Label']].dropna()
    df_sqli2 = pd.read_csv('dataset/sqliv2.csv',  encoding='utf-16')[['Sentence','Label']].dropna()
    df_sqli  = pd.concat([df_sqli1, df_sqli2], ignore_index=True)
    df_sqli['Label'] = df_sqli['Label'].astype(int)
    print(f"  SQLi  : {len(df_sqli):>6} rows  | Attack={(df_sqli['Label']==1).sum():>5} Normal={(df_sqli['Label']==0).sum():>5}")

    df_xss        = pd.read_csv('dataset/XSS_dataset.csv')[['Sentence','Label']].dropna()
    df_xss['Label'] = df_xss['Label'].astype(int)
    print(f"  XSS   : {len(df_xss):>6} rows  | Attack={(df_xss['Label']==1).sum():>5} Normal={(df_xss['Label']==0).sum():>5}")

    df_csic = pd.read_csv('dataset/csic_database.csv')
    df_csic['label'] = (df_csic.iloc[:, 0] == 'Anomalous').astype(int)
    def extract_uri(url):
        if not isinstance(url, str): return ''
        url = re.sub(r'\s+HTTP/\S+', '', url)
        try:
            p = urlparse(url); return p.path + ('?' + p.query if p.query else '')
        except: return url
    df_csic['uri']     = df_csic['URL'].apply(extract_uri)     if 'URL'        in df_csic.columns else ''
    df_csic['body']    = df_csic['content'].fillna('')          if 'content'    in df_csic.columns else ''
    df_csic['ua']      = df_csic['User-Agent'].fillna('')       if 'User-Agent' in df_csic.columns else ''
    df_csic['payload'] = df_csic['body']
    print(f"  CSIC  : {len(df_csic):>6} rows  | Attack={(df_csic['label']==1).sum():>5} Normal={(df_csic['label']==0).sum():>5}")

    # ── TEST A: SQLi features ──────────────────────────────────────────────────
    print("\n[2/4] Computing SQLi features on SQLi dataset...")
    r_sqli = batch_compute(df_sqli, 'Sentence', 'Label', sample_size=SAMPLE)
    SQLI_FEATS = ['F11', 'F12', 'F18', 'F19', 'F20', 'F22', 'F23']
    d_sqli = print_table(r_sqli, SQLI_FEATS,
        "SQLi Features — sqli.csv + sqliv2.csv  [F18=CRS942, F19=UNION, F20=Comment, F22=Stacked]")

    # ── TEST B: XSS features ───────────────────────────────────────────────────
    print("\n[3/4] Computing XSS features on XSS dataset...")
    r_xss = batch_compute(df_xss, 'Sentence', 'Label', sample_size=SAMPLE)
    XSS_FEATS = ['F13', 'F14', 'F25', 'F26', 'F27']
    d_xss = print_table(r_xss, XSS_FEATS,
        "XSS Features — XSS_dataset.csv  [F25=CRS941 score]")

    # ── TEST C: CSIC (realistic HTTP) ─────────────────────────────────────────
    print("\n[4/4] Computing features on CSIC dataset (realistic HTTP)...")
    r_csic = batch_compute(df_csic, 'payload', 'label',
                           uri_col='uri', ua_col='ua', sample_size=SAMPLE)
    CSIC_FEATS = ['F9', 'F10', 'F11', 'F12', 'F13', 'F14', 'F18', 'F19', 'F20', 'F22', 'F25', 'F27']
    d_csic = print_table(r_csic, CSIC_FEATS,
        "All Payload Features — CSIC (URI + User-Agent + Body)")

    # ── FINAL SUMMARY ─────────────────────────────────────────────────────────
    print("\n" + "="*80)
    print("  FINAL DECISION SUMMARY")
    print("="*80)
    all_feats = [
        ('F9',  'PayloadLength',    'csic'),
        ('F10', 'PayloadEntropy',   'csic'),
        ('F11', 'SqliKeyword',      'sqli'),
        ('F12', 'SqlSpecialChar',   'sqli'),
        ('F13', 'XssKeyword',       'xss'),
        ('F14', 'XssSpecialChar',   'xss'),
        ('F18', 'CrsSquliScore',    'sqli'),
        ('F19', 'SqlUnionSelect',   'sqli'),
        ('F20', 'SqlComment',       'sqli'),
        ('F22', 'SqlStackedQuery',  'sqli'),
        ('F23', 'SqlSelectCount',   'sqli'),
        ('F25', 'CrsXssScore',      'xss'),
        ('F26', 'JsFunctionCall',   'xss'),
        ('F27', 'HtmlEventHandler', 'xss'),
    ]
    src_map = {'sqli': d_sqli, 'xss': d_xss, 'csic': d_csic}
    print(f"\n{'Code':<6} {'Feature Name':<20} {'Dataset':<8} {'Decision'}")
    print("-" * 55)
    keep_list = []
    for code, name, src in all_feats:
        dec = src_map[src].get(code, 'N/A')
        print(f"  {code:<4} {name:<20} {src:<8} {dec}")
        if 'KEEP' in dec:
            keep_list.append(code)

    print(f"\n{'='*80}")
    print(f"  KEEP ({len(keep_list)}): {', '.join(keep_list)}")
    print(f"  Note: F1,F2,F4,F5,F15,F16,F17 need PCAP — kept based on theory.")
    print(f"{'='*80}\n")


if __name__ == '__main__':
    main()
