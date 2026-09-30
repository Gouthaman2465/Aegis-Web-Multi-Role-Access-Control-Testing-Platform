import React, { useState } from 'react';
import { Link } from 'react-router-dom';
import { Finding } from '../api/types';
import { ConfidenceBar } from './ConfidenceBar';
import { SeverityBadge } from './SeverityBadge';

interface FindingsTableProps {
  findings: Finding[];
}

export const FindingsTable: React.FC<FindingsTableProps> = ({ findings }) => {
  const [sevFilter, setSevFilter] = useState<string>('All');
  const [typeFilter, setTypeFilter] = useState<string>('All');
  const [statusFilter, setStatusFilter] = useState<string>('All');

  const filtered = findings.filter((f) => {
    if (sevFilter !== 'All' && f.severity !== sevFilter) return false;
    if (typeFilter !== 'All' && f.type !== typeFilter) return false;
    if (statusFilter !== 'All' && f.status !== statusFilter) return false;
    return true;
  });

  return (
    <div className="findings-table-wrapper">
      <div className="findings-filters">
        <div className="filter-group">
          <label htmlFor="sev-select">Severity:</label>
          <select
            id="sev-select"
            value={sevFilter}
            onChange={(e) => setSevFilter(e.target.value)}
          >
            <option value="All">All Severities</option>
            <option value="Critical">Critical</option>
            <option value="High">High</option>
            <option value="Medium">Medium</option>
            <option value="Low">Low</option>
            <option value="Info">Info</option>
          </select>
        </div>

        <div className="filter-group">
          <label htmlFor="type-select">Type:</label>
          <select
            id="type-select"
            value={typeFilter}
            onChange={(e) => setTypeFilter(e.target.value)}
          >
            <option value="All">All Types</option>
            <option value="HORIZONTAL_ACCESS">Horizontal IDOR</option>
            <option value="VERTICAL_ACCESS">Vertical Escalation</option>
            <option value="UNAUTHENTICATED_ACCESS">Unauthenticated</option>
          </select>
        </div>

        <div className="filter-group">
          <label htmlFor="status-select">Status:</label>
          <select
            id="status-select"
            value={statusFilter}
            onChange={(e) => setStatusFilter(e.target.value)}
          >
            <option value="All">All Statuses</option>
            <option value="open">Open</option>
            <option value="false_positive">False Positive</option>
            <option value="fixed">Fixed</option>
            <option value="accepted">Accepted</option>
          </select>
        </div>

        <div className="filter-count">
          Showing {filtered.length} of {findings.length} findings
        </div>
      </div>

      {filtered.length === 0 ? (
        <div className="empty-state">No matching findings.</div>
      ) : (
        <table className="data-table findings-table">
          <thead>
            <tr>
              <th>Severity</th>
              <th>Vulnerability Title</th>
              <th>Endpoint / Signature</th>
              <th>Type</th>
              <th>Tested Role</th>
              <th>Confidence</th>
              <th>Status</th>
              <th>Action</th>
            </tr>
          </thead>
          <tbody>
            {filtered.map((f) => (
              <tr key={f.id}>
                <td>
                  <SeverityBadge severity={f.severity} />
                </td>
                <td className="finding-title-cell">
                  <Link to={`/findings/${f.id}`} className="finding-link">
                    {f.title}
                  </Link>
                </td>
                <td className="finding-sig-cell">
                  <code>{f.signature}</code>
                </td>
                <td>
                  <span className="type-tag">{f.type}</span>
                </td>
                <td>
                  <code>{f.tested_role}</code>
                </td>
                <td>
                  <ConfidenceBar confidence={f.confidence} />
                </td>
                <td>
                  <span className={`status-pill status-${f.status}`}>{f.status}</span>
                </td>
                <td>
                  <Link to={`/findings/${f.id}`} className="btn-small">
                    Inspect
                  </Link>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      )}
    </div>
  );
};
