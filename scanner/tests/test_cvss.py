"""Unit tests for CVSS v3.1 calculation and severity mapping."""

import pytest
from aegis_scanner.cvss import base_score, severity_from_score


def test_cvss_exact_vectors():
    # 1. Critical vector
    vec1 = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
    assert base_score(vec1) == 9.8

    # 2. High vector (Unauthenticated information disclosure)
    vec2 = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N"
    assert base_score(vec2) == 7.5

    # 3. Medium vector (Low privilege info disclosure / BOLA)
    vec3 = "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N"
    assert base_score(vec3) == 6.5

    # 4. Zero impact vector
    vec4 = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N"
    assert base_score(vec4) == 0.0

    # 5. Scope-changed maximum vector
    vec5 = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H"
    assert base_score(vec5) == 10.0


def test_cvss_invalid_vector():
    with pytest.raises(ValueError):
        base_score("INVALID_VECTOR")

    with pytest.raises(ValueError):
        # Missing AV
        base_score("AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H")

    with pytest.raises(ValueError):
        # Invalid PR value
        base_score("AV:N/AC:L/PR:Z/UI:N/S:U/C:H/I:H/A:H")


def test_severity_bands():
    assert severity_from_score(None) == "Info"
    assert severity_from_score(0.0) == "Info"
    assert severity_from_score(0.1) == "Low"
    assert severity_from_score(3.9) == "Low"
    assert severity_from_score(4.0) == "Medium"
    assert severity_from_score(6.9) == "Medium"
    assert severity_from_score(7.0) == "High"
    assert severity_from_score(8.9) == "High"
    assert severity_from_score(9.0) == "Critical"
    assert severity_from_score(10.0) == "Critical"
