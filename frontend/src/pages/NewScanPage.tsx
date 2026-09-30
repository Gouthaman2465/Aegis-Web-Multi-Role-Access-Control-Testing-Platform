import React, { useEffect, useState } from 'react';
import { useParams, useNavigate, Link } from 'react-router-dom';
import { createScan, getTarget, listAccounts } from '../api/client';
import { ScanOptions, Target, TargetAccount } from '../api/types';

export const NewScanPage: React.FC = () => {
  const { id } = useParams<{ id: string }>();
  const targetId = parseInt(id || '', 10);
  const navigate = useNavigate();

  const [target, setTarget] = useState<Target | null>(null);
  const [accounts, setAccounts] = useState<TargetAccount[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  // Scan Options Form State
  const [maxPages, setMaxPages] = useState<number>(30);
  const [maxDepth, setMaxDepth] = useState<number>(3);
  const [requestDelay, setRequestDelay] = useState<number>(200);
  const [seedPaths, setSeedPaths] = useState<string>('/dashboard\n/orders\n/profile');
  const [ethicsConfirmed, setEthicsConfirmed] = useState(false);
  const [submitting, setSubmitting] = useState(false);

  useEffect(() => {
    const fetchData = async () => {
      try {
        setLoading(true);
        const [tData, accData] = await Promise.all([
          getTarget(targetId),
          listAccounts(targetId),
        ]);
        setTarget(tData);
        setAccounts(accData);
      } catch (err: any) {
        setError(err.detail || err.message || 'Failed to load target profile.');
      } finally {
        setLoading(false);
      }
    };
    fetchData();
  }, [targetId]);

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!ethicsConfirmed) {
      setError('You must confirm authorization before initiating testing.');
      return;
    }
    setError(null);
    setSubmitting(true);

    try {
      const paths = seedPaths
        .split('\n')
        .map((p) => p.trim())
        .filter((p) => p.length > 0);

      const options: ScanOptions = {
        max_pages: maxPages,
        max_depth: maxDepth,
        request_delay_ms: requestDelay,
        seed_paths: paths,
      };

      const scan = await createScan(targetId, options);
      navigate(`/scans/${scan.id}`);
    } catch (err: any) {
      setError(err.detail || err.message || 'Failed to launch scan.');
      setSubmitting(false);
    }
  };

  if (loading) return <div className="loading-state">Loading scan pre-flight checks...</div>;
  if (!target) return <div className="error-state">Target not found.</div>;

  const isVerified = target.ownership_status === 'verified' || target.ownership_status === 'lab';
  const hasMinAccounts = accounts.length >= 2;
  const canScan = isVerified && hasMinAccounts;

  return (
    <div className="page-container narrow">
      <div className="breadcrumb">
        <Link to={`/targets/${target.id}`}>&larr; Back to {target.name}</Link>
      </div>

      <div className="card">
        <h2>Launch Access-Control Scan</h2>
        <p className="card-subtitle">
          Target: <strong>{target.name}</strong> ({target.base_url})
        </p>

        {error && <div className="alert alert-error">{error}</div>}

        {!canScan && (
          <div className="alert alert-warning">
            <strong>Scan Prerequisites Incomplete:</strong>
            <ul>
              {!isVerified && <li>Target domain ownership must be verified or marked as a lab instance.</li>}
              {!hasMinAccounts && (
                <li>
                  At least 2 test accounts are required to evaluate privilege boundaries (currently{' '}
                  {accounts.length} configured).
                </li>
              )}
            </ul>
          </div>
        )}

        <form onSubmit={handleSubmit} className="standard-form">
          <div className="form-row">
            <div className="form-group flex-1">
              <label htmlFor="max-pages">Max Crawl Pages (1-100)</label>
              <input
                id="max-pages"
                type="number"
                min={1}
                max={100}
                value={maxPages}
                onChange={(e) => setMaxPages(parseInt(e.target.value, 10))}
                disabled={!canScan}
              />
            </div>

            <div className="form-group flex-1">
              <label htmlFor="max-depth">Max Crawl Depth (1-5)</label>
              <input
                id="max-depth"
                type="number"
                min={1}
                max={5}
                value={maxDepth}
                onChange={(e) => setMaxDepth(parseInt(e.target.value, 10))}
                disabled={!canScan}
              />
            </div>

            <div className="form-group flex-1">
              <label htmlFor="req-delay">Request Delay (ms)</label>
              <input
                id="req-delay"
                type="number"
                min={0}
                max={2000}
                step={50}
                value={requestDelay}
                onChange={(e) => setRequestDelay(parseInt(e.target.value, 10))}
                disabled={!canScan}
              />
            </div>
          </div>

          <div className="form-group">
            <label htmlFor="seed-paths">Seed URL Paths (one per line, starting with /)</label>
            <textarea
              id="seed-paths"
              rows={4}
              value={seedPaths}
              onChange={(e) => setSeedPaths(e.target.value)}
              placeholder="/dashboard&#10;/orders&#10;/profile"
              disabled={!canScan}
            />
            <small className="form-hint">
              Paths where crawler will begin exploration after logging into each account.
            </small>
          </div>

          <div className="ethics-notice-box">
            <h4>Authorization &amp; Ethical Notice</h4>
            <p>
              Aegis-Web performs automated authenticated replay testing. Only test applications you own or
              have explicit, written authorization to evaluate. All requests use read-only HTTP GET verification.
            </p>
            <label className="checkbox-label">
              <input
                type="checkbox"
                checked={ethicsConfirmed}
                onChange={(e) => setEthicsConfirmed(e.target.checked)}
                disabled={!canScan}
              />
              <span>I confirm I am authorized to test access controls on this application.</span>
            </label>
          </div>

          <button
            type="submit"
            className="btn btn-primary btn-block"
            disabled={!canScan || !ethicsConfirmed || submitting}
          >
            {submitting ? 'Enqueueing Scan...' : 'Start Access Control Assessment'}
          </button>
        </form>
      </div>
    </div>
  );
};
