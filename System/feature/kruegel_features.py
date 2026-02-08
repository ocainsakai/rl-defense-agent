"""
feature/kruegel_features.py

Web-based Anomaly Detection Features
Based on: Kruegel & Vigna, "Anomaly Detection of Web-based Attacks", CCS 2003

6 Models:
  1. Attribute Length       - Chebyshev inequality on param value lengths
  2. Character Distribution - ICD + chi-squared test on char frequency
  3. Structural Inference   - Markov-inspired regex structure matching
  4. Token Finder           - Detect enumeration vs random param values
  5. Attribute Presence     - Track param subsets per program/endpoint
  6. Attribute Order        - Track param ordering per program/endpoint

Usage:
    from feature.kruegel_features import KruegelFeatureExtractor

    extractor = KruegelFeatureExtractor()

    # Training phase (learn normal profiles)
    for uri in normal_uris:
        extractor.train(uri)
    extractor.finalize_training()

    # Detection phase (score anomalies)
    scores = extractor.detect(suspicious_uri)
    # scores = dict with per-model anomaly scores [0.0 = normal, 1.0 = anomalous]
"""

from __future__ import annotations

import math
import re
from collections import defaultdict
from typing import Dict, List, Optional, Tuple
from urllib.parse import urlparse, parse_qs, unquote_plus


# ============================================================================
# URI PARSER
# ============================================================================

def parse_uri(uri: str) -> Tuple[str, Dict[str, List[str]]]:
    """
    Parse URI into (path, params).

    Supports:
      - Standard query string: /path?a=1&b=2
      - Bare path: /path (returns empty params)

    Returns:
        (path, params_dict) where params_dict = {name: [values]}
    """
    if not uri:
        return ("", {})

    # Decode URL encoding
    uri = unquote_plus(uri)

    # Parse
    parsed = urlparse(uri if "://" in uri else f"http://dummy{uri}")
    path = parsed.path or "/"
    params = parse_qs(parsed.query, keep_blank_values=True)

    return (path, params)


# ============================================================================
# MODEL 1: ATTRIBUTE LENGTH (Section 4.1)
# ============================================================================

class AttributeLengthModel:
    """
    Detect anomalous parameter lengths using Chebyshev inequality.

    Training: Compute mean (mu) and variance (sigma^2) of param lengths.
    Detection: p(l) = sigma^2 / (l - mu)^2

    A low probability means the length deviates significantly from normal.
    """

    def __init__(self):
        # {param_name: [lengths seen during training]}
        self._lengths: Dict[str, List[int]] = defaultdict(list)
        # {param_name: (mean, variance)}
        self._profiles: Dict[str, Tuple[float, float]] = {}

    def train(self, param_name: str, value: str) -> None:
        self._lengths[param_name].append(len(value))

    def finalize(self) -> None:
        for name, lengths in self._lengths.items():
            n = len(lengths)
            if n == 0:
                continue
            mu = sum(lengths) / n
            variance = sum((l - mu) ** 2 for l in lengths) / n if n > 1 else 0.0
            self._profiles[name] = (mu, variance)

    def detect(self, param_name: str, value: str) -> float:
        """
        Return probability [0, 1] that this length is normal.
        1.0 = perfectly normal, 0.0 = highly anomalous.
        """
        if param_name not in self._profiles:
            return 1.0  # Unknown param, no profile

        mu, variance = self._profiles[param_name]
        l = len(value)
        distance = (l - mu) ** 2

        if distance == 0:
            return 1.0  # Exactly at mean

        if variance == 0:
            # Zero variance means all training samples had same length
            return 1.0 if l == mu else 0.0

        # Chebyshev: p = sigma^2 / (l - mu)^2
        p = variance / distance
        return min(p, 1.0)


# ============================================================================
# MODEL 2: CHARACTER DISTRIBUTION (Section 4.2)
# ============================================================================

class CharDistributionModel:
    """
    Detect anomalous character distributions using ICD + chi-squared test.

    Training: Build Idealized Character Distribution (ICD) per param.
    Detection: Chi-squared goodness-of-fit test against ICD.

    ICD = sorted relative frequencies of all 256 byte values, averaged
    across all training samples.
    """

    # Bins for chi-squared test (from paper Table 1)
    BINS = [
        (0, 0),      # Most frequent char only
        (1, 3),      # 2nd-4th most frequent
        (4, 6),      # 5th-7th
        (7, 11),     # 8th-12th
        (12, 15),    # 13th-16th
        (16, 255),   # All remaining
    ]

    # Chi-squared critical values for 5 degrees of freedom
    # p-values: 0.95, 0.90, 0.75, 0.50, 0.25, 0.10, 0.05, 0.01
    CHI2_TABLE = [
        (1.145, 0.95), (1.610, 0.90), (3.455, 0.75), (5.348, 0.50),
        (6.626, 0.25), (9.236, 0.10), (11.070, 0.05), (15.086, 0.01),
    ]

    def __init__(self):
        # {param_name: [sorted_relative_freq_256 for each sample]}
        self._distributions: Dict[str, List[List[float]]] = defaultdict(list)
        # {param_name: ICD (256 values)}
        self._icd: Dict[str, List[float]] = {}

    def train(self, param_name: str, value: str) -> None:
        dist = self._compute_char_distribution(value)
        self._distributions[param_name].append(dist)

    def finalize(self) -> None:
        for name, dists in self._distributions.items():
            if not dists:
                continue
            # ICD = average of all sorted character distributions
            icd = [0.0] * 256
            for dist in dists:
                for i in range(256):
                    icd[i] += dist[i]
            n = len(dists)
            icd = [v / n for v in icd]
            self._icd[name] = icd

    def detect(self, param_name: str, value: str) -> float:
        """
        Return probability [0, 1] that char distribution is normal.
        1.0 = normal, close to 0.0 = anomalous.
        """
        if param_name not in self._icd or len(value) < 3:
            return 1.0

        icd = self._icd[param_name]
        observed_dist = self._compute_char_distribution(value)
        length = len(value)

        # Compute chi-squared statistic using bins
        chi2 = 0.0
        for bin_start, bin_end in self.BINS:
            observed = sum(observed_dist[i] for i in range(bin_start, bin_end + 1)) * length
            expected = sum(icd[i] for i in range(bin_start, bin_end + 1)) * length
            if expected > 0:
                chi2 += (observed - expected) ** 2 / expected

        # Look up p-value from chi-squared table (5 degrees of freedom)
        p = self._chi2_to_p(chi2)
        return p

    @staticmethod
    def _compute_char_distribution(value: str) -> List[float]:
        """Compute sorted relative frequency distribution (256 values)."""
        if not value:
            return [0.0] * 256

        freq = [0] * 256
        raw = value.encode('utf-8', errors='ignore')
        for b in raw:
            freq[b] += 1

        total = len(raw)
        rel_freq = [f / total for f in freq]

        # Sort in descending order (ICD definition from paper)
        rel_freq.sort(reverse=True)
        return rel_freq

    @classmethod
    def _chi2_to_p(cls, chi2: float) -> float:
        """Convert chi-squared value to approximate p-value using table."""
        # If chi2 is very small, distribution matches well
        if chi2 <= cls.CHI2_TABLE[0][0]:
            return 1.0

        for threshold, p_value in cls.CHI2_TABLE:
            if chi2 <= threshold:
                return p_value

        # chi2 exceeds all thresholds
        return 0.0


# ============================================================================
# MODEL 3: STRUCTURAL INFERENCE (Section 4.3)
# ============================================================================

class StructuralModel:
    """
    Detect anomalous parameter structure.

    Simplified from Markov model in paper to regex-based structure matching.
    Converts parameter values to structural patterns:
      - 'a' = letter, 'd' = digit, 's' = special char
      - Groups consecutive same-type chars

    Training: Collect structural patterns per param.
    Detection: Check if new pattern matches any known pattern.
    """

    def __init__(self):
        # {param_name: set of structural patterns}
        self._patterns: Dict[str, set] = defaultdict(set)

    def train(self, param_name: str, value: str) -> None:
        pattern = self._to_structural_pattern(value)
        self._patterns[param_name].add(pattern)

    def finalize(self) -> None:
        pass  # Patterns already stored

    def detect(self, param_name: str, value: str) -> float:
        """
        Return 1.0 if structure matches known patterns, 0.0 otherwise.
        """
        if param_name not in self._patterns:
            return 1.0  # Unknown param

        pattern = self._to_structural_pattern(value)

        if pattern in self._patterns[param_name]:
            return 1.0  # Exact match

        # Partial match: check if pattern is "similar" to any known
        # Similarity = same type sequence, just different lengths
        for known in self._patterns[param_name]:
            if self._patterns_similar(pattern, known):
                return 0.8  # Similar but not exact

        return 0.0  # No match at all

    @staticmethod
    def _to_structural_pattern(value: str) -> str:
        """
        Convert value to structural pattern.

        Examples:
          "admin123"  -> "a+d+"
          "../../etc" -> "s+a+s+a+"
          "12345"     -> "d+"
          "abc-def"   -> "a+s+a+"
        """
        if not value:
            return ""

        pattern_chars = []
        for c in value:
            if c.isalpha():
                pattern_chars.append('a')
            elif c.isdigit():
                pattern_chars.append('d')
            else:
                pattern_chars.append('s')

        # Collapse consecutive same chars: "aaaddd" -> "a+d+"
        if not pattern_chars:
            return ""

        result = [pattern_chars[0]]
        for i in range(1, len(pattern_chars)):
            if pattern_chars[i] != pattern_chars[i - 1]:
                result.append('+')
                result.append(pattern_chars[i])
        result.append('+')

        return ''.join(result)

    @staticmethod
    def _patterns_similar(p1: str, p2: str) -> bool:
        """Check if two patterns have the same type sequence."""
        # Extract type sequence: "a+d+s+" -> "ads"
        types1 = p1.replace('+', '')
        types2 = p2.replace('+', '')
        return types1 == types2


# ============================================================================
# MODEL 4: TOKEN FINDER (Section 4.4)
# ============================================================================

class TokenFinderModel:
    """
    Detect if param values are from a finite enumeration.

    Training: Track correlation between total occurrences and distinct values.
    Detection: If param is enumeration, new values must be in known set.

    Uses statistical correlation (rho) between f(x)=x and g(x) where g
    increases when new value seen, decreases when existing value seen.
    """

    def __init__(self):
        # {param_name: (list of values, set of distinct values)}
        self._values: Dict[str, List[str]] = defaultdict(list)
        self._distinct: Dict[str, set] = defaultdict(set)
        # {param_name: (is_enum: bool, known_tokens: set)}
        self._profiles: Dict[str, Tuple[bool, set]] = {}

    def train(self, param_name: str, value: str) -> None:
        self._values[param_name].append(value)
        self._distinct[param_name].add(value)

    def finalize(self) -> None:
        for name, values in self._values.items():
            distinct = self._distinct[name]

            if len(values) < 5:
                # Too few samples to determine
                self._profiles[name] = (False, set())
                continue

            # Compute correlation rho between f and g
            rho = self._compute_correlation(values)

            if rho < 0:
                # Negative correlation = enumeration
                self._profiles[name] = (True, set(distinct))
            else:
                # Positive correlation = random values
                self._profiles[name] = (False, set())

    def detect(self, param_name: str, value: str) -> float:
        """
        Return 1.0 if value is acceptable, 0.0 if not.
        """
        if param_name not in self._profiles:
            return 1.0  # Unknown param

        is_enum, known_tokens = self._profiles[param_name]

        if not is_enum:
            return 1.0  # Random values, anything goes

        # Enumeration: value must be in known set
        return 1.0 if value in known_tokens else 0.0

    @staticmethod
    def _compute_correlation(values: List[str]) -> float:
        """Compute Pearson correlation between f(x)=x and g(x)."""
        n = len(values)
        if n < 3:
            return 0.0

        seen = set()
        f_vals = []
        g_vals = []
        g_current = 0

        for i, v in enumerate(values):
            f_vals.append(i + 1)
            if v not in seen:
                g_current += 1
                seen.add(v)
            else:
                g_current -= 1
            g_vals.append(g_current)

        # Pearson correlation
        mean_f = sum(f_vals) / n
        mean_g = sum(g_vals) / n

        cov = sum((f_vals[i] - mean_f) * (g_vals[i] - mean_g) for i in range(n)) / n
        var_f = sum((f - mean_f) ** 2 for f in f_vals) / n
        var_g = sum((g - mean_g) ** 2 for g in g_vals) / n

        if var_f == 0 or var_g == 0:
            return 0.0

        return cov / math.sqrt(var_f * var_g)


# ============================================================================
# MODEL 5: ATTRIBUTE PRESENCE/ABSENCE (Section 4.5)
# ============================================================================

class AttributePresenceModel:
    """
    Detect anomalous parameter combinations.

    Training: Record all distinct subsets of param names per endpoint.
    Detection: Check if current param subset was seen during training.
    """

    def __init__(self):
        # {path: set of frozenset(param_names)}
        self._known_subsets: Dict[str, set] = defaultdict(set)

    def train(self, path: str, param_names: frozenset) -> None:
        self._known_subsets[path].add(param_names)

    def finalize(self) -> None:
        pass

    def detect(self, path: str, param_names: frozenset) -> float:
        """
        Return 1.0 if param subset is known, 0.0 if anomalous.
        """
        if path not in self._known_subsets:
            return 1.0  # Unknown path

        return 1.0 if param_names in self._known_subsets[path] else 0.0


# ============================================================================
# MODEL 6: ATTRIBUTE ORDER (Section 4.6)
# ============================================================================

class AttributeOrderModel:
    """
    Detect anomalous parameter ordering.

    Training: Build precedence graph of param order per endpoint.
    Detection: Check if current order violates known precedence.
    """

    def __init__(self):
        # {path: set of (a_before, a_after) pairs}
        self._order_pairs: Dict[str, set] = defaultdict(set)

    def train(self, path: str, param_names_ordered: List[str]) -> None:
        # Add all pairwise order constraints
        for i in range(len(param_names_ordered)):
            for j in range(i + 1, len(param_names_ordered)):
                self._order_pairs[path].add(
                    (param_names_ordered[i], param_names_ordered[j])
                )

    def finalize(self) -> None:
        # Remove cycles using SCC detection (simplified)
        for path in self._order_pairs:
            self._remove_cycles(path)

    def detect(self, path: str, param_names_ordered: List[str]) -> float:
        """
        Return 1.0 if order is consistent, 0.0 if violated.
        """
        if path not in self._order_pairs:
            return 1.0

        pairs = self._order_pairs[path]
        for i in range(len(param_names_ordered)):
            for j in range(i + 1, len(param_names_ordered)):
                a_i = param_names_ordered[i]
                a_j = param_names_ordered[j]
                # Check if reverse order exists in constraints
                if (a_j, a_i) in pairs and (a_i, a_j) not in pairs:
                    return 0.0  # Violation

        return 1.0

    def _remove_cycles(self, path: str) -> None:
        """Remove cyclic order constraints (simplified Tarjan)."""
        pairs = self._order_pairs[path]
        to_remove = set()

        for a, b in pairs:
            if (b, a) in pairs:
                # Bidirectional = cycle, remove both
                to_remove.add((a, b))
                to_remove.add((b, a))

        self._order_pairs[path] -= to_remove


# ============================================================================
# MAIN EXTRACTOR: Combines all 6 models
# ============================================================================

class KruegelFeatureExtractor:
    """
    Web-based anomaly detection using 6 Kruegel-Vigna models.

    Two phases:
    1. Training: Feed normal URIs to build profiles
    2. Detection: Score new URIs for anomalies

    Output: Dict with 6 anomaly scores + combined score.
    Each score: 0.0 = highly anomalous, 1.0 = normal.
    Final anomaly_score: 0.0 = normal, 1.0 = highly anomalous (inverted).
    """

    # Weights for combining model scores (from paper Equation 1)
    WEIGHTS = {
        'length': 0.20,
        'char_dist': 0.20,
        'structure': 0.15,
        'token': 0.15,
        'presence': 0.15,
        'order': 0.15,
    }

    def __init__(self):
        self.length_model = AttributeLengthModel()
        self.char_dist_model = CharDistributionModel()
        self.structure_model = StructuralModel()
        self.token_model = TokenFinderModel()
        self.presence_model = AttributePresenceModel()
        self.order_model = AttributeOrderModel()
        self._is_trained = False

    def train(self, uri: str) -> None:
        """Train all models with a single URI."""
        path, params = parse_uri(uri)

        if not params:
            return

        param_names_ordered = list(params.keys())
        param_names_set = frozenset(param_names_ordered)

        # Train per-attribute models
        for name, values in params.items():
            for value in values:
                self.length_model.train(name, value)
                self.char_dist_model.train(name, value)
                self.structure_model.train(name, value)
                self.token_model.train(name, value)

        # Train per-query models
        self.presence_model.train(path, param_names_set)
        self.order_model.train(path, param_names_ordered)

    def finalize_training(self) -> None:
        """Finalize all model profiles after training phase."""
        self.length_model.finalize()
        self.char_dist_model.finalize()
        self.structure_model.finalize()
        self.token_model.finalize()
        self.presence_model.finalize()
        self.order_model.finalize()
        self._is_trained = True

    def detect(self, uri: str) -> Dict[str, float]:
        """
        Score a URI for anomalies using all 6 models.

        Returns:
            Dict with keys:
              - length_prob: [0,1] probability from length model
              - char_dist_prob: [0,1] probability from char distribution
              - structure_prob: [0,1] probability from structural model
              - token_prob: [0,1] probability from token finder
              - presence_prob: [0,1] probability from presence model
              - order_prob: [0,1] probability from order model
              - anomaly_score: [0,1] combined anomaly (0=normal, 1=attack)
              - is_anomalous: bool
        """
        path, params = parse_uri(uri)

        if not params:
            return self._no_params_result()

        param_names_ordered = list(params.keys())
        param_names_set = frozenset(param_names_ordered)

        # Per-attribute scores (min across all attributes)
        length_probs = []
        char_dist_probs = []
        structure_probs = []
        token_probs = []

        for name, values in params.items():
            for value in values:
                length_probs.append(self.length_model.detect(name, value))
                char_dist_probs.append(self.char_dist_model.detect(name, value))
                structure_probs.append(self.structure_model.detect(name, value))
                token_probs.append(self.token_model.detect(name, value))

        # Use minimum probability (most anomalous attribute determines score)
        length_p = min(length_probs) if length_probs else 1.0
        char_dist_p = min(char_dist_probs) if char_dist_probs else 1.0
        structure_p = min(structure_probs) if structure_probs else 1.0
        token_p = min(token_probs) if token_probs else 1.0

        # Per-query scores
        presence_p = self.presence_model.detect(path, param_names_set)
        order_p = self.order_model.detect(path, param_names_ordered)

        # Combined anomaly score (paper Equation 1)
        # anomaly = sum(w * (1 - p)) for each model
        w = self.WEIGHTS
        anomaly_score = (
            w['length'] * (1 - length_p) +
            w['char_dist'] * (1 - char_dist_p) +
            w['structure'] * (1 - structure_p) +
            w['token'] * (1 - token_p) +
            w['presence'] * (1 - presence_p) +
            w['order'] * (1 - order_p)
        )

        return {
            'length_prob': round(length_p, 4),
            'char_dist_prob': round(char_dist_p, 4),
            'structure_prob': round(structure_p, 4),
            'token_prob': round(token_p, 4),
            'presence_prob': round(presence_p, 4),
            'order_prob': round(order_p, 4),
            'anomaly_score': round(anomaly_score, 4),
            'is_anomalous': anomaly_score > 0.5,
        }

    def detect_raw(self, uri: str) -> List[float]:
        """Return anomaly scores as vector [length, char, struct, token, presence, order, combined]."""
        result = self.detect(uri)
        return [
            result['length_prob'],
            result['char_dist_prob'],
            result['structure_prob'],
            result['token_prob'],
            result['presence_prob'],
            result['order_prob'],
            result['anomaly_score'],
        ]

    @staticmethod
    def _no_params_result() -> Dict[str, float]:
        return {
            'length_prob': 1.0,
            'char_dist_prob': 1.0,
            'structure_prob': 1.0,
            'token_prob': 1.0,
            'presence_prob': 1.0,
            'order_prob': 1.0,
            'anomaly_score': 0.0,
            'is_anomalous': False,
        }

    @staticmethod
    def get_feature_names() -> List[str]:
        return [
            'kruegel_length_prob',
            'kruegel_char_dist_prob',
            'kruegel_structure_prob',
            'kruegel_token_prob',
            'kruegel_presence_prob',
            'kruegel_order_prob',
            'kruegel_anomaly_score',
        ]
