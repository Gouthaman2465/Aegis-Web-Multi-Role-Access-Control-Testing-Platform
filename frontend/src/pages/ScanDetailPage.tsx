import React, { useEffect, useState } from 'react';
import { useParams, Link, useNavigate } from 'react-router-dom';
import {
  cancelScan,
  getMarkdownReport,
  getScan,
  getScanEndpoints,
  getScanEvents,
  getScanFindings,
  listScans,
} from '../api/client';
import { Endpoint, Finding, Scan, ScanEvent } from '../api/types';
import { EventLog } from '../components/EventLog';
import { FindingsTable } from '../components/FindingsTable';
import { ProgressBar } from '../components/ProgressBar';
import { useInterval } from '../hooks/useInterval';

export const ScanDetailPage: React.FC = () => {
  const { id } = useParams<{ id: string }>();
  const scanId = parseInt(id || '', 10);
  const navigate = useNavigate();

  const [scan, setScan] = useState<Scan | null>(null);
  const [events, setEvents] = useState<ScanEvent[]>([]);
  const [findings, setFindings] = useState<Finding[]>([]);
  const [endpoints, setEndpoints] = useState<Endpoint[]>([]);
  const [otherScans, setOtherScans] = useState<Scan[]>([]);
  const [compareTargetScanId, setCompareTargetScanId] = useState<string>('');

  const [activeTab, setActiveTab] = useState<'findings' | 'endpoints' | 'summary' | 'compare'>('findings');
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [cancelling, setCancelling] = useState(false);

  const loadInitialData = async () => {
    if (isNaN(scanId)) return;
    try {
      setLoading(true);
      const [sData, evData, fData, epData, allScans] = await Promise.all([
        getScan(scanId),
        getScanEvents(scanId, 0),
        getScanFindings(scanId),
        getScanEndpoints(scanId),
        listScans(),
      ]);
      setScan(sData);
      setEvents(evData);
      setFindings(fData);
      setEndpoints(epData);

      const targetPeers = allScans.filter((s) => s.target_id === sData.target_id && s.id !== scanId);
      setOtherScans(targetPeers);
      if (targetPeers.length > 0) {
        setCompareTargetScanId(targetPeers[0].id.toString());
      }
    } catch (err: any) {
      setError(err.detail || err.message || 'Failed to load scan details.');
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    loadInitialData();
  }, [scanId]);

  // Incremental polling while queued or running
  const isActive = scan?.status === 'queued' || scan?.status === 'running';

  useInterval(
    async () => {
      if (!isActive) return;
      try {
        const latestScan = await getScan(scanId);
        setScan(latestScan);

        const lastEventId = events.length > 0 ? events[events.length - 1].id : 0;
        const newEvents = await getScanEvents(scanId, lastEventId);
        if (newEvents.length > 0) {
          setEvents((prev) => [...prev, ...newEvents]);
        }

        // When scan completes during polling, load final endpoints and findings
        if (latestScan.status === 'completed' || latestScan.status === 'failed' || latestScan.status === 'cancelled') {
          const [fData, epData] = await Promise.all([
            getScanFindings(scanId),
            getScanEndpoints(scanId),
          ]);
          setFindings(fData);
          setEndpoints(epData);
        }
      } catch (pollErr) {
        console.error('Polling error:', pollErr);
      }
    },
    isActive ? 2000 : null
  );

  const handleCancel = async () => {
    if (!window.confirm('Request cancellation of this scan?')) return;
    try {
      setCancelling(true);
      const updated = await cancelScan(scanId);
      setScan(updated);
    } catch (err: any) {
      setError(err.detail || err.message || 'Failed to cancel scan.');
    } finally {
      setCancelling(false);
    }
  };

  const handleDownloadReport = async () => {
    try {
      const md = await getMarkdownReport(scanId);
      const blob = new Blob([md], { type: 'text/markdown;charset=utf-8' });
      const url = URL.createObjectURL(blob);
      const link = document.createElement('a');
      link.href = url;
      link.download = `aegis-scan-${scanId}-report.md`;
      document.body.appendChild(link);
      link.click();
      document.body.removeChild(link);
      URL.revokeObjectURL(url);
    } catch (err: any) {
      alert(`Export error: ${err.detail || err.message}`);
    }
  };

  const handleCompareNavigate = () => {
    if (!compareTargetScanId) return;
    navigate(`/scans/${scanId}/compare/${compareTargetScanId}`);
  };

  if (loading) return <div className="loading-state">Loading scan progress...</div>;
  if (!scan) return <div className="error-state">Scan not found.</div>;

  return (
    <div className="page-container">
      <div className="scan-detail-header">
        <div>
          <div className="breadcrumb">
            <Link to={`/targets/${scan.target_id}`}>&larr; Target Overview</Link>
          </div>
          <h2>
            Scan #{scan.id}{' '}
            <span className={`status-badge status-${scan.status}`}>{scan.status.toUpperCase()}</span>
          </h2>
          <span className="scan-date-meta">
            Created: {new Date(scan.created_at).toLocaleString()}
            {scan.finished_at && ` • Finished: ${new Date(scan.finished_at).toLocaleString()}`}
          </span>
        </div>

        <div className="scan-actions-bar">
          {isActive && (
            <button
              onClick={handleCancel}
              className="btn btn-danger-outline"
              disabled={cancelling || scan.cancel_requested}
            >
              {scan.cancel_requested ? 'Cancelling...' : 'Cancel Scan'}
            </button>
          )}
          <button onClick={handleDownloadReport} className="btn btn-secondary">
            📥 Download Report (.md)
          </button>
        </div>
      </div>

      {error && <div className="alert alert-error">{error}</div>}
      {scan.error_message && (
        <div className="alert alert-error">
          <strong>Scan Error:</strong> {scan.error_message}
        </div>
      )}

      {/* Progress & Live Event Stream */}
      <div className="card">
        <ProgressBar
          percent={scan.progress_percent}
          stage={scan.progress_stage}
          status={scan.status}
        />
        <div className="event-stream-section">
          <h4>Execution Events ({events.length})</h4>
          <EventLog events={events} />
        </div>
      </div>

      {/* Tabs navigation */}
      <div className="tabs-container">
        <div className="tab-headers">
          <button
            className={`tab-btn ${activeTab === 'findings' ? 'active' : ''}`}
            onClick={() => setActiveTab('findings')}
          >
            Findings ({findings.length})
          </button>
          <button
            className={`tab-btn ${activeTab === 'endpoints' ? 'active' : ''}`}
            onClick={() => setActiveTab('endpoints')}
          >
            Observed Endpoints ({endpoints.length})
          </button>
          <button
            className={`tab-btn ${activeTab === 'summary' ? 'active' : ''}`}
            onClick={() => setActiveTab('summary')}
          >
            Statistical Summary
          </button>
          <button
            className={`tab-btn ${activeTab === 'compare' ? 'active' : ''}`}
            onClick={() => setActiveTab('compare')}
          >
            Compare Scans
          </button>
        </div>

        <div className="tab-body card">
          {activeTab === 'findings' && <FindingsTable findings={findings} />}

          {activeTab === 'endpoints' && (
            <div className="endpoints-view">
              {endpoints.length === 0 ? (
                <p className="empty-message">No endpoints recorded.</p>
              ) : (
                <table className="data-table">
                  <thead>
                    <tr>
                      <th>Account</th>
                      <th>Method</th>
                      <th>Signature</th>
                      <th>URL</th>
                      <th>Status</th>
                      <th>Type</th>
                    </tr>
                  </thead>
                  <tbody>
                    {endpoints.map((ep) => (
                      <tr key={ep.id}>
                        <td>
                          <code>{ep.account_label}</code>
                        </td>
                        <td>
                          <strong>{ep.method}</strong>
                        </td>
                        <td>
                          <code>{ep.signature}</code>
                        </td>
                        <td className="url-cell" title={ep.url}>
                          {ep.url}
                        </td>
                        <td>{ep.status_code}</td>
                        <td>{ep.resource_type}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              )}
            </div>
          )}

          {activeTab === 'summary' && (
            <div className="summary-view">
              <div className="summary-stats-grid">
                <div className="stat-card">
                  <div className="stat-value">{scan.summary?.requests_recorded ?? 0}</div>
                  <div className="stat-label">Requests Recorded</div>
                </div>
                <div className="stat-card">
                  <div className="stat-value">{scan.summary?.replays_sent ?? 0}</div>
                  <div className="stat-label">Replays Executed</div>
                </div>
                <div className="stat-card">
                  <div className="stat-value">{scan.summary?.discarded_low_confidence ?? 0}</div>
                  <div className="stat-label">Low-Confidence Discards</div>
                </div>
                <div className="stat-card">
                  <div className="stat-value">{findings.length}</div>
                  <div className="stat-label">Verified Access Flaws</div>
                </div>
              </div>

              <div className="severity-breakdown-box">
                <h4>Findings by Severity</h4>
                <div className="severity-bar-breakdown">
                  {Object.entries(scan.summary?.findings_by_severity || {}).map(([sev, count]) => (
                    <div key={sev} className="sev-item">
                      <span className={`sev-tag tag-${sev.toLowerCase()}`}>{sev}</span>
                      <strong className="sev-count">{count}</strong>
                    </div>
                  ))}
                </div>
              </div>
            </div>
          )}

          {activeTab === 'compare' && (
            <div className="compare-select-view">
              <h4>Compare With Previous Scan</h4>
              <p>Identify newly introduced, persisting, and remediated access-control vulnerabilities.</p>
              {otherScans.length === 0 ? (
                <p className="empty-message">No other scans exist for this target to compare against.</p>
              ) : (
                <div className="compare-control-row">
                  <select
                    value={compareTargetScanId}
                    onChange={(e) => setCompareTargetScanId(e.target.value)}
                    className="select-input"
                  >
                    {otherScans.map((s) => (
                      <option key={s.id} value={s.id}>
                        Scan #{s.id} ({new Date(s.created_at).toLocaleDateString()} - {s.status})
                      </option>
                    ))}
                  </select>
                  <button onClick={handleCompareNavigate} className="btn btn-primary">
                    Compare Scans &rarr;
                  </button>
                </div>
              )}
            </div>
          )}
        </div>
      </div>
    </div>
  );
};
