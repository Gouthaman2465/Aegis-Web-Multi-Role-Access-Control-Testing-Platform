import React, { useEffect, useState } from 'react';
import { useParams, Link, useNavigate } from 'react-router-dom';
import {
  createAccount,
  deleteAccount,
  deleteTarget,
  getTarget,
  listAccounts,
  markTargetLab,
  verifyTarget,
} from '../api/client';
import { AccountCreate, Target, TargetAccount } from '../api/types';
import { useAuth } from '../auth/AuthContext';

export const TargetDetailPage: React.FC = () => {
  const { id } = useParams<{ id: string }>();
  const targetId = parseInt(id || '', 10);
  const navigate = useNavigate();
  const { isAdmin } = useAuth();

  const [target, setTarget] = useState<Target | null>(null);
  const [accounts, setAccounts] = useState<TargetAccount[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [verifyMessage, setVerifyMessage] = useState<string | null>(null);

  // New Account Form State
  const [roleLabel, setRoleLabel] = useState('');
  const [privilegeLevel, setPrivilegeLevel] = useState<number>(10);
  const [loginUrl, setLoginUrl] = useState('');
  const [username, setUsername] = useState('');
  const [password, setPassword] = useState('');
  const [userSel, setUserSel] = useState('input[name=username]');
  const [passSel, setPassSel] = useState('input[name=password]');
  const [submitSel, setSubmitSel] = useState('button[type=submit]');
  const [dismissSels, setDismissSels] = useState('');
  const [successUrlContains, setSuccessUrlContains] = useState('');
  const [identifiers, setIdentifiers] = useState('');
  const [accountFormError, setAccountFormError] = useState<string | null>(null);
  const [addingAccount, setAddingAccount] = useState(false);

  const loadData = async () => {
    if (isNaN(targetId)) return;
    try {
      setLoading(true);
      const [tData, accData] = await Promise.all([
        getTarget(targetId),
        listAccounts(targetId),
      ]);
      setTarget(tData);
      setAccounts(accData);
      if (!loginUrl && tData.base_url) {
        setLoginUrl(`${tData.base_url.replace(/\/+$/, '')}/login`);
      }
    } catch (err: any) {
      setError(err.detail || err.message || 'Failed to load target details.');
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    loadData();
  }, [targetId]);

  const handleVerify = async () => {
    setVerifyMessage(null);
    try {
      const res = await verifyTarget(targetId);
      if (res.verified) {
        setVerifyMessage('Domain ownership successfully verified!');
        await loadData();
      } else {
        setVerifyMessage(
          `Verification failed: Could not read token. ${res.instructions}`
        );
      }
    } catch (err: any) {
      setVerifyMessage(`Verification error: ${err.detail || err.message}`);
    }
  };

  const handleMarkLab = async () => {
    try {
      await markTargetLab(targetId);
      await loadData();
    } catch (err: any) {
      setError(err.detail || err.message || 'Failed to mark target as lab instance.');
    }
  };

  const handleDeleteTarget = async () => {
    if (!window.confirm('Are you sure you want to delete this target?')) return;
    try {
      await deleteTarget(targetId);
      navigate('/targets');
    } catch (err: any) {
      setError(err.detail || err.message || 'Failed to delete target.');
    }
  };

  const handleAddAccount = async (e: React.FormEvent) => {
    e.preventDefault();
    setAccountFormError(null);
    setAddingAccount(true);

    try {
      const payload: AccountCreate = {
        role_label: roleLabel.trim().toLowerCase(),
        privilege_level: privilegeLevel,
        login_url: loginUrl.trim(),
        username: username.trim(),
        password: password,
        username_selector: userSel.trim(),
        password_selector: passSel.trim(),
        submit_selector: submitSel.trim(),
        dismiss_selectors: dismissSels
          .split('\n')
          .map((s) => s.trim())
          .filter(Boolean),
        success_url_contains: successUrlContains.trim() || null,
        identifiers: identifiers
          .split('\n')
          .map((s) => s.trim())
          .filter(Boolean),
      };

      await createAccount(targetId, payload);
      // Reset sensitive password and input fields
      setPassword('');
      setRoleLabel('');
      setUsername('');
      setIdentifiers('');
      await loadData();
    } catch (err: any) {
      setAccountFormError(err.detail || err.message || 'Failed to add account.');
    } finally {
      setAddingAccount(false);
    }
  };

  const handleDeleteAccount = async (accId: number) => {
    if (!window.confirm('Delete this account profile?')) return;
    try {
      await deleteAccount(targetId, accId);
      await loadData();
    } catch (err: any) {
      setError(err.detail || err.message || 'Failed to remove account.');
    }
  };

  if (loading) return <div className="loading-state">Loading target profile...</div>;
  if (!target) return <div className="error-state">Target not found.</div>;

  const isScanReady =
    (target.ownership_status === 'verified' || target.ownership_status === 'lab') &&
    accounts.length >= 2;

  return (
    <div className="page-container">
      <div className="target-detail-header">
        <div>
          <div className="breadcrumb">
            <Link to="/targets">&larr; Targets</Link>
          </div>
          <h2>{target.name}</h2>
          <span className="target-url-sub">{target.base_url}</span>
        </div>

        <div className="target-header-actions">
          {isScanReady ? (
            <Link to={`/targets/${target.id}/scan/new`} className="btn btn-primary">
              ⚡ Start New Scan
            </Link>
          ) : (
            <button className="btn btn-disabled" disabled title="Requires verified/lab status and ≥ 2 accounts">
              ⚡ Start Scan (Requires 2 Accounts)
            </button>
          )}
          <button onClick={handleDeleteTarget} className="btn btn-danger-outline">
            Delete Target
          </button>
        </div>
      </div>

      {error && <div className="alert alert-error">{error}</div>}

      {/* Target Status & Verification */}
      <div className="card target-status-card">
        <div className="status-indicator-bar">
          <div>
            <strong>Ownership Status: </strong>
            <span className={`status-badge status-${target.ownership_status}`}>
              {target.ownership_status.toUpperCase()}
            </span>
          </div>
          <div className="status-actions">
            {target.ownership_status === 'unverified' && (
              <button onClick={handleVerify} className="btn btn-secondary btn-small">
                Verify Domain Ownership
              </button>
            )}
            {isAdmin && target.ownership_status !== 'lab' && (
              <button onClick={handleMarkLab} className="btn btn-outline btn-small">
                Mark as Lab Instance (Admin)
              </button>
            )}
          </div>
        </div>

        {target.ownership_status === 'unverified' && (
          <div className="verification-box">
            <h4>Ownership Verification Instructions</h4>
            <p>
              To scan this target, verify domain ownership by creating a plain text file at:
            </p>
            <code>
              {target.base_url.replace(/\/+$/, '')}/.well-known/aegis-verification.txt
            </code>
            <p>Containing your unique verification token:</p>
            <div className="token-display">
              <code>{target.ownership_token}</code>
            </div>
            {verifyMessage && <div className="alert alert-info">{verifyMessage}</div>}
          </div>
        )}
      </div>

      {/* Accounts Section */}
      <div className="grid-2-columns">
        <div className="card">
          <h3>Test Accounts ({accounts.length})</h3>
          <p className="card-subtitle">
            At least two accounts with different roles or privileges are needed to test access control boundaries.
          </p>

          {accounts.length === 0 ? (
            <p className="empty-message">No test accounts configured for this target.</p>
          ) : (
            <div className="accounts-list">
              {accounts.map((acc) => (
                <div key={acc.id} className="account-card-item">
                  <div className="account-card-info">
                    <div className="account-role-row">
                      <strong>Role: <code>{acc.role_label}</code></strong>
                      <span className="privilege-tag">Privilege Level: {acc.privilege_level}</span>
                    </div>
                    <div>User: <code>{acc.username}</code> &bull; Password: <em>(Encrypted in DB)</em></div>
                    {acc.identifiers && acc.identifiers.length > 0 && (
                      <small className="ident-tags">
                        Identifiers: {acc.identifiers.join(', ')}
                      </small>
                    )}
                  </div>
                  <button
                    onClick={() => handleDeleteAccount(acc.id)}
                    className="btn btn-text-danger"
                  >
                    Delete
                  </button>
                </div>
              ))}
            </div>
          )}
        </div>

        {/* Add Account Form */}
        <div className="card">
          <h3>Add Test Role / Account</h3>
          {accountFormError && <div className="alert alert-error">{accountFormError}</div>}

          <form onSubmit={handleAddAccount} className="standard-form">
            <div className="form-row">
              <div className="form-group flex-1">
                <label htmlFor="role-label">Role Label *</label>
                <input
                  id="role-label"
                  type="text"
                  required
                  value={roleLabel}
                  onChange={(e) => setRoleLabel(e.target.value)}
                  placeholder="e.g. admin, user_a, user_b"
                />
              </div>

              <div className="form-group flex-1">
                <label htmlFor="priv-level">Privilege Level (1-100) *</label>
                <input
                  id="priv-level"
                  type="number"
                  min={1}
                  max={100}
                  required
                  value={privilegeLevel}
                  onChange={(e) => setPrivilegeLevel(parseInt(e.target.value, 10))}
                />
              </div>
            </div>

            <div className="form-group">
              <label htmlFor="login-url">Login URL *</label>
              <input
                id="login-url"
                type="url"
                required
                value={loginUrl}
                onChange={(e) => setLoginUrl(e.target.value)}
              />
            </div>

            <div className="form-row">
              <div className="form-group flex-1">
                <label htmlFor="acc-user">Username *</label>
                <input
                  id="acc-user"
                  type="text"
                  required
                  value={username}
                  onChange={(e) => setUsername(e.target.value)}
                />
              </div>

              <div className="form-group flex-1">
                <label htmlFor="acc-pass">Password (Write-Only) *</label>
                <input
                  id="acc-pass"
                  type="password"
                  required
                  value={password}
                  onChange={(e) => setPassword(e.target.value)}
                  placeholder="Encrypted immediately"
                />
              </div>
            </div>

            <div className="form-row">
              <div className="form-group flex-1">
                <label htmlFor="u-sel">User Selector</label>
                <input
                  id="u-sel"
                  type="text"
                  value={userSel}
                  onChange={(e) => setUserSel(e.target.value)}
                />
              </div>
              <div className="form-group flex-1">
                <label htmlFor="p-sel">Pass Selector</label>
                <input
                  id="p-sel"
                  type="text"
                  value={passSel}
                  onChange={(e) => setPassSel(e.target.value)}
                />
              </div>
              <div className="form-group flex-1">
                <label htmlFor="s-sel">Submit Selector</label>
                <input
                  id="s-sel"
                  type="text"
                  value={submitSel}
                  onChange={(e) => setSubmitSel(e.target.value)}
                />
              </div>
            </div>

            <div className="form-group">
              <label htmlFor="idents">Account Identifiers (one per line, e.g. user ID, email)</label>
              <textarea
                id="idents"
                rows={2}
                value={identifiers}
                onChange={(e) => setIdentifiers(e.target.value)}
                placeholder="alice&#10;alice@example.com&#10;101"
              />
            </div>

            <button type="submit" className="btn btn-primary" disabled={addingAccount}>
              {addingAccount ? 'Saving Account...' : 'Add Account'}
            </button>
          </form>
        </div>
      </div>
    </div>
  );
};
