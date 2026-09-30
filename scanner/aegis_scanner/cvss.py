"""CVSS v3.1 Base Score calculator implementing the FIRST official specification."""

import math
from typing import Optional

AV_WEIGHTS = {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.2}
AC_WEIGHTS = {"L": 0.77, "H": 0.44}
PR_WEIGHTS_U = {"N": 0.85, "L": 0.62, "H": 0.27}
PR_WEIGHTS_C = {"N": 0.85, "L": 0.68, "H": 0.50}
UI_WEIGHTS = {"N": 0.85, "R": 0.62}
CIA_WEIGHTS = {"H": 0.56, "L": 0.22, "N": 0.0}

REQUIRED_METRICS = {"AV", "AC", "PR", "UI", "S", "C", "I", "A"}


def _cvss_roundup(val: float) -> float:
    """Implement official CVSS v3.1 integer-based roundup function."""
    int_input = round(val * 100000)
    if int_input % 10000 == 0:
        return int_input / 100000.0
    return (math.floor(int_input / 10000) + 1) / 10.0


def base_score(vector: str) -> float:
    """Calculate CVSS v3.1 Base Score from a vector string.

    Example vector: "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N" -> 6.5
    Raises ValueError on invalid or missing metrics.
    """
    clean_vec = vector.strip()
    if clean_vec.startswith("CVSS:3.1/"):
        clean_vec = clean_vec[len("CVSS:3.1/"):]

    parts = clean_vec.split("/")
    metrics: dict[str, str] = {}
    for part in parts:
        if not part or ":" not in part:
            continue
        k, v = part.split(":", 1)
        metrics[k.upper()] = v.upper()

    if not REQUIRED_METRICS.issubset(metrics.keys()):
        missing = REQUIRED_METRICS - set(metrics.keys())
        raise ValueError(f"Missing required CVSS metrics: {missing}")

    av_key = metrics["AV"]
    ac_key = metrics["AC"]
    pr_key = metrics["PR"]
    ui_key = metrics["UI"]
    s_key = metrics["S"]
    c_key = metrics["C"]
    i_key = metrics["I"]
    a_key = metrics["A"]

    if av_key not in AV_WEIGHTS:
        raise ValueError(f"Invalid AV value: {av_key}")
    if ac_key not in AC_WEIGHTS:
        raise ValueError(f"Invalid AC value: {ac_key}")
    if ui_key not in UI_WEIGHTS:
        raise ValueError(f"Invalid UI value: {ui_key}")
    if s_key not in ("U", "C"):
        raise ValueError(f"Invalid Scope value: {s_key}")
    if c_key not in CIA_WEIGHTS or i_key not in CIA_WEIGHTS or a_key not in CIA_WEIGHTS:
        raise ValueError("Invalid CIA metric value")

    scope_changed = (s_key == "C")
    if scope_changed:
        if pr_key not in PR_WEIGHTS_C:
            raise ValueError(f"Invalid PR value: {pr_key}")
        pr_weight = PR_WEIGHTS_C[pr_key]
    else:
        if pr_key not in PR_WEIGHTS_U:
            raise ValueError(f"Invalid PR value: {pr_key}")
        pr_weight = PR_WEIGHTS_U[pr_key]

    av = AV_WEIGHTS[av_key]
    ac = AC_WEIGHTS[ac_key]
    ui = UI_WEIGHTS[ui_key]
    c = CIA_WEIGHTS[c_key]
    i = CIA_WEIGHTS[i_key]
    a = CIA_WEIGHTS[a_key]

    iss = 1.0 - ((1.0 - c) * (1.0 - i) * (1.0 - a))
    if iss <= 0:
        return 0.0

    if not scope_changed:
        impact = 6.42 * iss
    else:
        impact = 7.52 * (iss - 0.029) - 3.25 * ((iss - 0.02) ** 15)

    exploitability = 8.22 * av * ac * pr_weight * ui

    if impact <= 0:
        return 0.0

    if not scope_changed:
        score = min(impact + exploitability, 10.0)
    else:
        score = min(1.08 * (impact + exploitability), 10.0)

    return _cvss_roundup(score)


def severity_from_score(score: Optional[float]) -> str:
    """Return severity string band corresponding to CVSS base score."""
    if score is None or score <= 0.0:
        return "Info"
    if score < 4.0:
        return "Low"
    if score < 7.0:
        return "Medium"
    if score < 9.0:
        return "High"
    return "Critical"
