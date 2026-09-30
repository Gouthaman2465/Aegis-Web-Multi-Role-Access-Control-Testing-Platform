import React, { useEffect, useState } from 'react';
import { useParams, Link } from 'react-router-dom';
import { getFinding, updateFinding } from '../api/client';
import { Finding } from '../api/types';
import { ConfidenceBar } from '../components/ConfidenceBar';
import { DiffViewer } from '../components/DiffViewer';
import { SeverityBadge } from '../components/SeverityBadge';

export const FindingDetailPage: React.FC = () => {
  const { id } = useParams<{ id: string }>();
  const findingId = parseInt(id || '', 10);

  const [finding, setFinding] = useState<Finding | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  // Triage state
  const [status, setStatus] = useState<string>('open');
  const [note, setNote] = useState<string>('');
  const [savingTriage, setSavingTriage] = useState(false);
  const [saveSuccess, setSaveSuccess] = useState(false);

  useEffect(() => {
    const fetchFinding = async () => {
      if (isNaN(findingId)) return;
      try {
        setLoading(true);
        const data = await getFinding(findingId);
        setFinding(data);
        setStatus(data.status);
        setNote(data.note || '');
      } catch (err: any) {
        setError(err.detail || err.message || 'Failed to load finding details.');
      } finally {
        setLoading(false);
      }
    };
    fetchFinding();
  }, [findingId]);

  const handleSaveTriage = async (e: React.FormEvent) => {
    e.preventDefault();
    setSavingTriage(true);
    setSaveSuccess(false);
    try {
      const updated = await updateFinding(findingId, {
        status,
        note: note.trim() || undefined,
      });
      setFinding(updated);
      setSaveSuccess(true);
      setTimeout(() => setSaveSuccess(false), 3000);
    } catch (err: any) {
      alert(`Save error: ${err.detail || err.message}`);
    } finally {
      setSavingTriage(false);
    }
  };

  if (loading) return <div className="loading-state">Loading vulnerability details...</div>;
  if (!finding) return <div className="error-state">Finding not found.</div>;

  return (
    <div className="page-container">
      <div className="breadcrumb">
        <Link to={`/scans/${finding.scan_id}`}>&larr; Back to Scan #{finding.scan_id}</Link>
      </div>

      {error && <div className="alert alert-error">{error}</div>}

      {/* Header card with classification */}
      <div className="card finding-header-card">
        <div className="finding-header-top">
          <div className="finding-title-group">
            <div className="finding-badge-row">
              <SeverityBadge severity={finding.severity} />
              <span className="type-badge">{finding.type}</span>
              <span className="fingerprint-badge">FP: <code>{finding.fingerprint}</code></span>
            </div>
            <h2>{finding.title}</h2>
            <div className="finding-url-meta">
              <strong>Target URL: </strong>
              <code className="url-code">{finding.url}</code>
            </div>
            <div className="finding-sig-meta">
              <strong>Signature: </strong>
              <code>{finding.method} {finding.signature}</code>
            </div>
          </div>

          <div className="finding-score-box">
            <div className="score-value">{finding.cvss_score.toFixed(1)}</div>
            <div className="score-label">CVSS v3.1</div>
            <div className="confidence-meter">
              <span className="meter-label">Detection Confidence:</span>
              <ConfidenceBar confidence={finding.confidence} />
            </div>
          </div>
        </div>

        <div className="finding-metadata-grid">
          <div className="meta-item">
            <span className="meta-label">CWE</span>
            <span className="meta-val">{finding.cwe}</span>
          </div>
          <div className="meta-item">
            <span className="meta-label">OWASP</span>
            <span className="meta-val">{finding.owasp}</span>
          </div>
          <div className="meta-item">
            <span className="meta-label">Source Role</span>
            <span className="meta-val"><code>{finding.source_role}</code></span>
          </div>
          <div className="meta-item">
            <span className="meta-label">Tested Role</span>
            <span className="meta-val"><code>{finding.tested_role}</code></span>
          </div>
          <div className="meta-item full-width">
            <span className="meta-label">CVSS Vector</span>
            <code className="meta-val cvss-vector">{finding.cvss_vector}</code>
          </div>
        </div>
      </div>

      {/* Description & Remediation */}
      <div className="grid-2-columns">
        <div className="card">
          <h3>Vulnerability Description</h3>
          <p className="finding-description-text">{finding.description}</p>
        </div>

        <div className="card">
          <h3>Remediation Guidance</h3>
          <p className="finding-remediation-text">{finding.remediation}</p>
        </div>
      </div>

      {/* Raw Differential Verification Evidence */}
      <div className="card">
        <h3>Replay Verification Evidence</h3>
        <p className="card-subtitle">
          Side-by-side comparison between the response recorded by <code>{finding.source_role}</code> and
          the response replayed by <code>{finding.tested_role}</code>. All sensitive authorization tokens have
          been redacted.
        </p>

        <DiffViewer evidence={finding.evidence} />
      </div>

      {/* Triage & Analyst Notes */}
      <div className="card">
        <h3>Triage &amp; Status Workflow</h3>
        {saveSuccess && <div className="alert alert-success">Finding updated successfully.</div>}

        <form onSubmit={handleSaveTriage} className="standard-form">
          <div className="form-row">
            <div className="form-group flex-1">
              <label htmlFor="triage-status">Status</label>
              <select
                id="triage-status"
                value={status}
                onChange={(e) => setStatus(e.target.value)}
                className="select-input"
              >
                <option value="open">Open</option>
                <option value="false_positive">False Positive</option>
                <option value="fixed">Fixed</option>
                <option value="accepted">Risk Accepted</option>
              </select>
            </div>

            <div className="form-group flex-2">
              <label htmlFor="triage-note">Analyst Note (Optional, max 1000 chars)</label>
              <input
                id="triage-note"
                type="text"
                maxLength={1000}
                value={note}
                onChange={(e) => setNote(e.target.value)}
                placeholder="Document verification context or Jira ticket reference"
              />
            </div>
          </div>

          <button type="submit" className="btn btn-primary" disabled={savingTriage}>
            {savingTriage ? 'Updating...' : 'Save Triage Status'}
          </button>
        </form>
      </div>
    </div>
  );
};
