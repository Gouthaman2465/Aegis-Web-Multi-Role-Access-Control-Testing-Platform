"""Unit tests for finding candidate rules, confidence arithmetic, and severity downgrade."""

from aegis_scanner.diff.scoring import (
    Signals,
    is_finding_candidate,
    confidence_score,
    adjust_severity,
)


def _base_signals(**kwargs):
    defaults = {
        "original_has_content": True,
        "similarity": 0.95,
        "stability": 1.0,
        "personalized": False,
        "has_source_identifiers": False,
        "served_own_data": False,
        "id_in_path": True,
        "body_len": 250,
        "sensitive_fields": False,
        "looks_public": False,
    }
    defaults.update(kwargs)
    return Signals(**defaults)


def test_candidate_rule_0_no_content():
    # Rule 0: If original has no meaningful content, it cannot be a finding candidate
    sig = _base_signals(original_has_content=False)
    assert is_finding_candidate(sig) is False


def test_candidate_rule_1_served_own_data():
    # Rule 1: Server returned tested account's own data
    sig = _base_signals(served_own_data=True)
    assert is_finding_candidate(sig) is False


def test_candidate_rule_2_personalized_without_source_data():
    # Rule 2: Original had source data, but replay does not contain it
    sig = _base_signals(personalized=True, has_source_identifiers=False)
    assert is_finding_candidate(sig) is False

    # When replay DOES contain source data, it is a candidate
    sig_ok = _base_signals(personalized=True, has_source_identifiers=True)
    assert is_finding_candidate(sig_ok) is True


def test_candidate_rule_3_unstable():
    # Rule 4: Stability < 0.5 is too dynamic
    sig = _base_signals(stability=0.45)
    assert is_finding_candidate(sig) is False


def test_candidate_rule_4_low_similarity():
    # Rule 3: Required similarity below threshold
    sig = _base_signals(similarity=0.70, stability=1.0)
    assert is_finding_candidate(sig) is False


def test_confidence_arithmetic_cases():
    # Case 1: High confidence finding with all signals
    # 50 (base) + 25 (source id) + 15 (id in path) + 10 (len>=100) + 10 (sensitive) = 110 -> 100 clamped
    sig_high = _base_signals(
        similarity=1.0,
        stability=1.0,
        has_source_identifiers=True,
        id_in_path=True,
        body_len=150,
        sensitive_fields=True,
        looks_public=False,
    )
    assert confidence_score(sig_high) == 100

    # Case 2: Public endpoint penalty (-30) drops confidence below 50
    # 50 (base) - 30 (public) = 20
    sig_public = _base_signals(
        similarity=1.0,
        stability=1.0,
        has_source_identifiers=False,
        id_in_path=False,
        body_len=50,
        sensitive_fields=False,
        looks_public=True,
    )
    score_pub = confidence_score(sig_public)
    assert score_pub == 20
    assert score_pub < 50

    # Case 3: Partial signals without source ID
    # 50 (base) + 15 (id_in_path) + 10 (len>=100) = 75
    sig_med = _base_signals(
        similarity=1.0,
        stability=1.0,
        has_source_identifiers=False,
        id_in_path=True,
        body_len=200,
        sensitive_fields=False,
        looks_public=False,
    )
    assert confidence_score(sig_med) == 75

    # Case 4: Moderate similarity on dynamic page
    # 50 * (0.8 / 1.0) = 40 + 15 (id) + 10 (len) = 65 (< 70)
    sig_mod = _base_signals(
        similarity=0.8,
        stability=1.0,
        has_source_identifiers=False,
        id_in_path=True,
        body_len=120,
        sensitive_fields=False,
        looks_public=False,
    )
    assert confidence_score(sig_mod) == 65


def test_severity_downgrade():
    # Confidence >= 70 retains severity
    assert adjust_severity("High", confidence=85) == "High"
    assert adjust_severity("Medium", confidence=70) == "Medium"

    # Confidence < 70 downgrades by one level
    assert adjust_severity("Critical", confidence=65) == "High"
    assert adjust_severity("High", confidence=65) == "Medium"
    assert adjust_severity("Medium", confidence=55) == "Low"
    assert adjust_severity("Low", confidence=50) == "Info"
    assert adjust_severity("Info", confidence=50) == "Info"
