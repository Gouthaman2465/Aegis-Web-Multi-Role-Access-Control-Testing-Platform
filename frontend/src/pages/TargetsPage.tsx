import React, { useEffect, useState } from 'react';
import { Link } from 'react-router-dom';
import { createTarget, listTargets } from '../api/client';
import { Target } from '../api/types';

export const TargetsPage: React.FC = () => {
  const [targets, setTargets] = useState<Target[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  // Form state
  const [name, setName] = useState('');
  const [baseUrl, setBaseUrl] = useState('');
  const [scopeHosts, setScopeHosts] = useState('');
  const [creating, setCreating] = useState(false);
  const [formError, setFormError] = useState<string | null>(null);

  const fetchTargets = async () => {
    try {
      setLoading(true);
      const data = await listTargets();
      setTargets(data);
    } catch (err: any) {
      setError(err.message || 'Failed to load targets.');
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchTargets();
  }, []);

  const handleCreateTarget = async (e: React.FormEvent) => {
    e.preventDefault();
    setFormError(null);
    setCreating(true);

    try {
      const hosts = scopeHosts
        .split(/[,\n]/)
        .map((h) => h.trim())
        .filter((h) => h.length > 0);

      await createTarget({
        name: name.trim(),
        base_url: baseUrl.trim(),
        scope_hosts: hosts.length > 0 ? hosts : undefined,
      });

      setName('');
      setBaseUrl('');
      setScopeHosts('');
      await fetchTargets();
    } catch (err: any) {
      setFormError(err.detail || err.message || 'Failed to register target.');
    } finally {
      setCreating(false);
    }
  };

  return (
    <div className="page-container">
      <div className="page-header">
        <div>
          <h2>Target Applications</h2>
          <p className="page-subtitle">Configure web applications for access-control vulnerability assessment.</p>
        </div>
      </div>

      {error && <div className="alert alert-error">{error}</div>}

      <div className="grid-2-columns">
        {/* Targets List */}
        <div className="card">
          <h3>Registered Targets ({targets.length})</h3>
          {loading ? (
            <p>Loading targets...</p>
          ) : targets.length === 0 ? (
            <p className="empty-message">No targets registered yet. Add one using the form.</p>
          ) : (
            <div className="target-list">
              {targets.map((t) => (
                <div key={t.id} className="target-card-item">
                  <div className="target-card-main">
                    <Link to={`/targets/${t.id}`} className="target-title-link">
                      <h4>{t.name}</h4>
                    </Link>
                    <span className="target-url">{t.base_url}</span>
                    <div className="target-scope-tags">
                      Scope: {t.scope_hosts.join(', ') || 'Default host'}
                    </div>
                  </div>
                  <div className="target-card-actions">
                    <span className={`status-badge status-${t.ownership_status}`}>
                      {t.ownership_status.toUpperCase()}
                    </span>
                    <Link to={`/targets/${t.id}`} className="btn btn-secondary btn-small">
                      Manage &rarr;
                    </Link>
                  </div>
                </div>
              ))}
            </div>
          )}
        </div>

        {/* New Target Form */}
        <div className="card">
          <h3>Register New Target</h3>
          <p className="card-subtitle">
            Target must be verified via domain token or marked as a lab instance before scanning.
          </p>

          {formError && <div className="alert alert-error">{formError}</div>}

          <form onSubmit={handleCreateTarget} className="standard-form">
            <div className="form-group">
              <label htmlFor="target-name">Target Name *</label>
              <input
                id="target-name"
                type="text"
                required
                value={name}
                onChange={(e) => setName(e.target.value)}
                placeholder="e.g. Acme Corp Portal"
              />
            </div>

            <div className="form-group">
              <label htmlFor="target-url">Base URL *</label>
              <input
                id="target-url"
                type="url"
                required
                value={baseUrl}
                onChange={(e) => setBaseUrl(e.target.value)}
                placeholder="http://127.0.0.1:8000 or https://app.example.com"
              />
              <small className="form-hint">Scheme and host only. Subpaths not recommended as base.</small>
            </div>

            <div className="form-group">
              <label htmlFor="scope-hosts">In-Scope Hosts (optional)</label>
              <textarea
                id="scope-hosts"
                rows={3}
                value={scopeHosts}
                onChange={(e) => setScopeHosts(e.target.value)}
                placeholder="app.example.com, *.api.example.com"
              />
              <small className="form-hint">Comma or line-separated. Wildcards (*.example.com) allowed.</small>
            </div>

            <button type="submit" className="btn btn-primary" disabled={creating}>
              {creating ? 'Registering...' : 'Register Target'}
            </button>
          </form>
        </div>
      </div>
    </div>
  );
};
