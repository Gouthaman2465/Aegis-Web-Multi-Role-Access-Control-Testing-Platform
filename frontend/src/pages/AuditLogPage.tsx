import React, { useEffect, useState } from 'react';
import { getAuditLogs } from '../api/client';
import { AuditLog } from '../api/types';

export const AuditLogPage: React.FC = () => {
  const [logs, setLogs] = useState<AuditLog[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [offset, setOffset] = useState(0);
  const limit = 25;

  const fetchLogs = async (currentOffset: number) => {
    try {
      setLoading(true);
      setError(null);
      const data = await getAuditLogs(limit, currentOffset);
      setLogs(data);
    } catch (err: any) {
      setError(err.detail || err.message || 'Failed to retrieve administrative audit logs.');
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchLogs(offset);
  }, [offset]);

  const handlePrev = () => {
    setOffset((prev) => Math.max(0, prev - limit));
  };

  const handleNext = () => {
    setOffset((prev) => prev + limit);
  };

  return (
    <div className="page-container">
      <div className="page-header">
        <div>
          <h2>System Audit Log</h2>
          <p className="page-subtitle">
            Immutable administrative record of security operations, credentials usage, and scan events.
          </p>
        </div>
      </div>

      {error && <div className="alert alert-error">{error}</div>}

      <div className="card">
        {loading ? (
          <div className="loading-state">Loading audit trail...</div>
        ) : logs.length === 0 ? (
          <div className="empty-state">No audit entries found.</div>
        ) : (
          <div className="audit-table-wrapper">
            <table className="data-table audit-table">
              <thead>
                <tr>
                  <th>Timestamp (UTC)</th>
                  <th>Action</th>
                  <th>User ID</th>
                  <th>IP Address</th>
                  <th>Resource</th>
                  <th>Details</th>
                </tr>
              </thead>
              <tbody>
                {logs.map((log) => (
                  <tr key={log.id}>
                    <td className="log-time-cell">
                      {new Date(log.created_at).toLocaleString()}
                    </td>
                    <td>
                      <span className="action-pill">{log.action}</span>
                    </td>
                    <td>{log.user_id !== null ? log.user_id : 'System'}</td>
                    <td>{log.ip || '–'}</td>
                    <td>
                      {log.resource_type ? (
                        <code>
                          {log.resource_type}:{log.resource_id}
                        </code>
                      ) : (
                        '–'
                      )}
                    </td>
                    <td className="log-details-cell">
                      <pre className="inline-json-pre">
                        {JSON.stringify(log.details, null, 2)}
                      </pre>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}

        <div className="pagination-controls">
          <button
            onClick={handlePrev}
            className="btn btn-secondary btn-small"
            disabled={offset === 0 || loading}
          >
            &larr; Previous
          </button>
          <span className="pagination-info">Showing entries {offset + 1} &ndash; {offset + logs.length}</span>
          <button
            onClick={handleNext}
            className="btn btn-secondary btn-small"
            disabled={logs.length < limit || loading}
          >
            Next &rarr;
          </button>
        </div>
      </div>
    </div>
  );
};
