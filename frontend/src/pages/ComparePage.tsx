import React, { useEffect, useState } from 'react';
import { useParams, Link } from 'react-router-dom';
import { compareScans, getScan } from '../api/client';
import { CompareResult, FindingSummary, Scan } from '../api/types';
import { SeverityBadge } from '../components/SeverityBadge';

export const ComparePage: React.FC = () => {
  const { id, otherId } = useParams<{ id: string; otherId: string }>();
  const scanAId = parseInt(id || '', 10);
  const scanBId = parseInt(otherId || '', 10);

  const [scanA, setScanA] = useState<Scan | null>(null);
  const [scanB, setScanB] = useState<Scan | null>(null);
  const [comparison, setComparison] = useState<CompareResult | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    const fetchComparison = async () => {
      if (isNaN(scanAId) || isNaN(scanBId)) return;
      try {
        setLoading(true);
        const [aData, bData, cmpData] = await Promise.all([
          getScan(scanAId),
          getScan(scanBId),
          compareScans(scanAId, scanBId),
        ]);
        setScanA(aData);
        setScanB(bData);
        setComparison(cmpData);
      } catch (err: any) {
        setError(err.detail || err.message || 'Failed to compare scans.');
      } finally {
        setLoading(false);
      }
    };
    fetchComparison();
  }, [scanAId, scanBId]);

  if (loading) return <div className="loading-state">Comparing access control findings...</div>;
  if (error) return <div className="alert alert-error">{error}</div>;
  if (!comparison) return <div className="error-state">Comparison unavailable.</div>;

  const renderFindingColumn = (
    title: string,
    items: FindingSummary[],
    colorClass: string,
    desc: string
  ) => (
    <div className={`compare-column ${colorClass}`}>
      <div className="compare-column-header">
        <h3>{title}</h3>
        <span className="compare-count-badge">{items.length}</span>
      </div>
      <p className="column-desc">{desc}</p>

      {items.length === 0 ? (
        <div className="empty-column-msg">None detected.</div>
      ) : (
        <div className="compare-cards-list">
          {items.map((item) => (
            <div key={item.id} className="compare-card">
              <div className="card-top">
                <SeverityBadge severity={item.severity} />
                <span className="card-type-tag">{item.type}</span>
              </div>
              <h5 className="card-title">
                <Link to={`/findings/${item.id}`}>{item.title}</Link>
              </h5>
              <code className="card-sig">{item.signature}</code>
              <div className="card-footer">
                <span>Confidence: {item.confidence}%</span>
                <span className={`status-pill status-${item.status}`}>{item.status}</span>
              </div>
            </div>
          ))}
        </div>
      )}
    </div>
  );

  return (
    <div className="page-container">
      <div className="breadcrumb">
        <Link to={`/scans/${scanAId}`}>&larr; Back to Scan #{scanAId}</Link>
      </div>

      <div className="compare-page-header">
        <h2>Regression Analysis: Scan #{scanAId} vs Scan #{scanBId}</h2>
        <p className="page-subtitle">
          Comparing baseline Scan #{scanAId} against Scan #{scanBId}. Findings marked as false positives are
          excluded.
        </p>
      </div>

      <div className="compare-three-columns">
        {renderFindingColumn(
          'New Vulnerabilities',
          comparison.new,
          'col-new',
          'Vulnerabilities newly introduced in Scan #' + scanBId
        )}

        {renderFindingColumn(
          'Remediated / Fixed',
          comparison.fixed,
          'col-fixed',
          'Vulnerabilities resolved since Scan #' + scanAId
        )}

        {renderFindingColumn(
          'Persisting Flaws',
          comparison.persisting,
          'col-persisting',
          'Vulnerabilities active across both scans'
        )}
      </div>
    </div>
  );
};
