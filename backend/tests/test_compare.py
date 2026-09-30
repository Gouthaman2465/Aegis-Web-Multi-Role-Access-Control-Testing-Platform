"""Unit and API tests for scan comparison service and endpoint."""

import pytest
from app.models.finding import Finding
from app.models.scan import Scan
from app.models.target import Target
from app.services.compare_service import compare_scans


def _create_target(db, user, name="Target"):
    t = Target(
        owner_id=user.id,
        name=name,
        base_url=f"http://example.com/{name.lower()}",
        scope_hosts=["example.com"],
        ownership_status="verified",
        ownership_token="token",
    )
    db.add(t)
    db.commit()
    db.refresh(t)
    return t


def _create_scan(db, user, target):
    s = Scan(
        owner_id=user.id,
        target_id=target.id,
        status="completed",
        options={},
    )
    db.add(s)
    db.commit()
    db.refresh(s)
    return s


def _create_finding(db, scan, fp, status="open", title="Finding"):
    f = Finding(
        scan_id=scan.id,
        fingerprint=fp,
        type="HORIZONTAL_ACCESS",
        title=title,
        severity="High",
        confidence=90,
        cvss_score=7.5,
        cvss_vector="CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N",
        cwe="CWE-639",
        owasp="A01:2021",
        method="GET",
        url=f"http://example.com/item/{fp}",
        signature="GET /item/{id}",
        source_role="alice",
        tested_role="bob",
        description="Desc",
        remediation="Remediation",
        status=status,
        evidence={},
    )
    db.add(f)
    db.commit()
    db.refresh(f)
    return f


def test_compare_scans_service_sets_and_excludes_false_positives(db_session, regular_user):
    target = _create_target(db_session, regular_user, "Target 1")
    scan_a = _create_scan(db_session, regular_user, target)
    scan_b = _create_scan(db_session, regular_user, target)

    f_fixed = _create_finding(db_session, scan_a, fp="fp_fixed", title="Fixed Finding")
    f_persisting_a = _create_finding(db_session, scan_a, fp="fp_persisting", title="Persisting Finding")
    f_fp = _create_finding(db_session, scan_a, fp="fp_false_positive", status="false_positive", title="FP Finding")

    f_persisting_b = _create_finding(db_session, scan_b, fp="fp_persisting", title="Persisting Finding")
    f_new = _create_finding(db_session, scan_b, fp="fp_new", title="New Finding")

    findings_a = [f_fixed, f_persisting_a, f_fp]
    findings_b = [f_persisting_b, f_new]

    result = compare_scans(scan_a, scan_b, findings_a, findings_b)

    new_fps = {item["fingerprint"] for item in result["new"]}
    fixed_fps = {item["fingerprint"] for item in result["fixed"]}
    persisting_fps = {item["fingerprint"] for item in result["persisting"]}

    assert new_fps == {"fp_new"}
    assert fixed_fps == {"fp_fixed"}
    assert persisting_fps == {"fp_persisting"}
    assert "fp_false_positive" not in new_fps
    assert "fp_false_positive" not in fixed_fps
    assert "fp_false_positive" not in persisting_fps


def test_compare_endpoint_different_targets_raises_400(client, db_session, regular_user, user_auth_headers):
    target_1 = _create_target(db_session, regular_user, "Target 1")
    target_2 = _create_target(db_session, regular_user, "Target 2")

    scan_1 = _create_scan(db_session, regular_user, target_1)
    scan_2 = _create_scan(db_session, regular_user, target_2)

    resp = client.get(f"/api/v1/scans/{scan_1.id}/compare/{scan_2.id}", headers=user_auth_headers)
    assert resp.status_code == 400
    assert "different targets" in resp.json()["detail"]


def test_compare_endpoint_success(client, db_session, regular_user, user_auth_headers):
    target = _create_target(db_session, regular_user, "Target 1")
    scan_1 = _create_scan(db_session, regular_user, target)
    scan_2 = _create_scan(db_session, regular_user, target)

    _create_finding(db_session, scan_1, fp="fp_1", title="Finding 1")
    _create_finding(db_session, scan_2, fp="fp_1", title="Finding 1")
    _create_finding(db_session, scan_2, fp="fp_2", title="Finding 2")

    resp = client.get(f"/api/v1/scans/{scan_1.id}/compare/{scan_2.id}", headers=user_auth_headers)
    assert resp.status_code == 200
    data = resp.json()
    assert len(data["new"]) == 1
    assert data["new"][0]["fingerprint"] == "fp_2"
    assert len(data["persisting"]) == 1
    assert data["persisting"][0]["fingerprint"] == "fp_1"
    assert len(data["fixed"]) == 0
