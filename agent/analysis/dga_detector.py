"""Lightweight DGA (Domain Generation Algorithm) detector.

Scores domain names for DGA characteristics using multiple heuristics.
Runs synchronously on every DNS event before any LLM call.
Must complete in < 1ms per domain (pure math, no I/O).
"""

from __future__ import annotations

import math
from dataclasses import dataclass, field

# Pre-computed English bigram frequencies (relative frequency of letter pairs).
# Source: aggregated from English text corpus analysis.
# Higher values = more common in English.
_ENGLISH_BIGRAMS: dict[str, float] = {
    "th": 3.56, "he": 3.07, "in": 2.43, "er": 2.05, "an": 1.99,
    "re": 1.85, "on": 1.76, "at": 1.49, "en": 1.45, "nd": 1.35,
    "ti": 1.34, "es": 1.34, "or": 1.28, "te": 1.27, "of": 1.17,
    "ed": 1.17, "is": 1.13, "it": 1.12, "al": 1.09, "ar": 1.07,
    "st": 1.05, "to": 1.05, "nt": 1.04, "ng": 0.95, "se": 0.93,
    "ha": 0.93, "as": 0.87, "ou": 0.87, "io": 0.83, "le": 0.83,
    "ve": 0.83, "co": 0.79, "me": 0.79, "de": 0.76, "hi": 0.76,
    "ri": 0.73, "ro": 0.73, "ic": 0.70, "ne": 0.69, "ea": 0.69,
    "ra": 0.69, "ce": 0.65, "li": 0.62, "ch": 0.60, "ll": 0.58,
    "be": 0.58, "ma": 0.57, "si": 0.55, "om": 0.55, "ur": 0.54,
}

_VOWELS = set("aeiou")


@dataclass
class DGAResult:
    domain: str
    score: float  # 0.0 (definitely legit) to 1.0 (definitely DGA)
    entropy: float
    consonant_vowel_ratio: float
    bigram_score: float
    is_dga_candidate: bool  # True if score > threshold
    reasons: list[str] = field(default_factory=list)


def analyze_domain(
    domain: str,
    threshold: float = 0.6,
    allowlist: set[str] | None = None,
) -> DGAResult:
    """Score a domain name for DGA characteristics.

    Args:
        domain: The domain name to analyze.
        threshold: Score above which is_dga_candidate is True.
        allowlist: Set of known-good domains to skip analysis for.

    Returns:
        DGAResult with score and component metrics.
    """
    domain = domain.lower().rstrip(".")

    # Check allowlist
    if allowlist:
        # Check if domain itself or its parent is in the allowlist
        for allowed in allowlist:
            if domain == allowed or domain.endswith("." + allowed):
                return DGAResult(
                    domain=domain,
                    score=0.0,
                    entropy=0.0,
                    consonant_vowel_ratio=0.0,
                    bigram_score=0.0,
                    is_dga_candidate=False,
                    reasons=["Allowlisted"],
                )

    # Extract second-level domain (strip TLD)
    parts = domain.split(".")
    if len(parts) < 2:
        # Single label (no TLD) - can't meaningfully analyze
        return DGAResult(
            domain=domain,
            score=0.0,
            entropy=0.0,
            consonant_vowel_ratio=0.0,
            bigram_score=0.0,
            is_dga_candidate=False,
            reasons=["Single label domain"],
        )

    # For subdomains like "abc.evil.example.com", analyze the subdomain parts
    # excluding the TLD
    sld = parts[0] if len(parts) >= 2 else domain

    reasons: list[str] = []
    scores: list[float] = []

    # 1. Shannon entropy
    entropy = _shannon_entropy(sld)
    entropy_score = min(max((entropy - 2.5) / 2.0, 0.0), 1.0)  # Normalize: 2.5-4.5 -> 0-1
    scores.append(entropy_score)
    if entropy > 3.5:
        reasons.append(f"High entropy: {entropy:.2f}")

    # 2. Consonant-to-vowel ratio
    cv_ratio = _consonant_vowel_ratio(sld)
    # Normal English has ~0.4-0.6 vowels per alpha char
    # DGA tends to be < 0.2 or > 0.7
    cv_score = 0.0
    if cv_ratio < 0.15 or cv_ratio > 0.75:
        cv_score = 1.0
        reasons.append(f"Unusual vowel ratio: {cv_ratio:.2f}")
    elif cv_ratio < 0.25 or cv_ratio > 0.65:
        cv_score = 0.5
    scores.append(cv_score)

    # 3. Domain length
    length_score = 0.0
    if len(sld) > 20:
        length_score = 1.0
        reasons.append(f"Very long domain: {len(sld)} chars")
    elif len(sld) > 15:
        length_score = 0.6
        reasons.append(f"Long domain: {len(sld)} chars")
    elif len(sld) > 10:
        length_score = 0.2
    scores.append(length_score)

    # 4. Bigram frequency
    bigram_freq = _bigram_frequency_score(sld)
    bigram_score = min(max(1.0 - (bigram_freq / 0.8), 0.0), 1.0)  # Low freq = high score
    scores.append(bigram_score)
    if bigram_freq < 0.2:
        reasons.append(f"Low bigram frequency: {bigram_freq:.2f}")

    # 5. Numeric ratio
    numeric_ratio = _numeric_ratio(sld)
    numeric_score = min(numeric_ratio * 2.0, 1.0)  # > 50% digits = max score
    scores.append(numeric_score)
    if numeric_ratio > 0.3:
        reasons.append(f"High numeric ratio: {numeric_ratio:.2f}")

    # Composite score (weighted average)
    weights = [0.30, 0.15, 0.15, 0.25, 0.15]  # entropy, cv, length, bigram, numeric
    composite = sum(s * w for s, w in zip(scores, weights, strict=False))

    return DGAResult(
        domain=domain,
        score=round(composite, 4),
        entropy=round(entropy, 4),
        consonant_vowel_ratio=round(cv_ratio, 4),
        bigram_score=round(bigram_freq, 4),
        is_dga_candidate=composite > threshold,
        reasons=reasons,
    )


def _shannon_entropy(s: str) -> float:
    """Calculate Shannon entropy of a string."""
    if not s:
        return 0.0
    freq: dict[str, int] = {}
    for c in s:
        freq[c] = freq.get(c, 0) + 1
    length = len(s)
    return -sum(
        (count / length) * math.log2(count / length)
        for count in freq.values()
    )


def _consonant_vowel_ratio(s: str) -> float:
    """Calculate vowel ratio (vowels / alpha chars)."""
    alpha_chars = [c for c in s.lower() if c.isalpha()]
    if not alpha_chars:
        return 0.0
    vowels = sum(1 for c in alpha_chars if c in _VOWELS)
    return vowels / len(alpha_chars)


def _bigram_frequency_score(s: str) -> float:
    """Average English bigram frequency of consecutive character pairs.

    Higher = more English-like. Lower = more random.
    """
    s = s.lower()
    if len(s) < 2:
        return 0.0
    total = 0.0
    count = 0
    for i in range(len(s) - 1):
        bigram = s[i:i + 2]
        if bigram[0].isalpha() and bigram[1].isalpha():
            total += _ENGLISH_BIGRAMS.get(bigram, 0.0)
            count += 1
    if count == 0:
        return 0.0
    return total / count


def _numeric_ratio(s: str) -> float:
    """Ratio of digits to total characters."""
    if not s:
        return 0.0
    digits = sum(1 for c in s if c.isdigit())
    return digits / len(s)
