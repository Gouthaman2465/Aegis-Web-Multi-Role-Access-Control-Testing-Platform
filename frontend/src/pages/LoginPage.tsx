import React, { useState } from 'react';
import { useNavigate, useLocation } from 'react-router-dom';
import { useAuth } from '../auth/AuthContext';
import { ApiError } from '../api/client';

export const LoginPage: React.FC = () => {
  const { login, register } = useAuth();
  const navigate = useNavigate();
  const location = useLocation();

  const [isRegister, setIsRegister] = useState(false);
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(false);

  const from = (location.state as any)?.from?.pathname || '/targets';

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setError(null);
    setLoading(true);

    try {
      if (isRegister) {
        await register(email, password);
      } else {
        await login(email, password);
      }
      navigate(from, { replace: true });
    } catch (err: any) {
      if (err instanceof ApiError) {
        setError(err.detail);
      } else {
        setError('Authentication request failed. Please verify credentials.');
      }
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="auth-page-container">
      <div className="auth-card">
        <div className="auth-header">
          <div className="auth-logo">🛡️</div>
          <h2>{isRegister ? 'Create an Account' : 'Sign in to Aegis-Web'}</h2>
          <p className="auth-subtitle">
            {isRegister
              ? 'Register to perform authorized access-control evaluations'
              : 'Enter your credentials to access testing dashboard'}
          </p>
        </div>

        {error && <div className="alert alert-error">{error}</div>}

        <form onSubmit={handleSubmit} className="auth-form">
          <div className="form-group">
            <label htmlFor="email">Email Address</label>
            <input
              id="email"
              type="email"
              required
              value={email}
              onChange={(e) => setEmail(e.target.value)}
              placeholder="analyst@example.com"
            />
          </div>

          <div className="form-group">
            <label htmlFor="password">Password</label>
            <input
              id="password"
              type="password"
              required
              value={password}
              onChange={(e) => setPassword(e.target.value)}
              placeholder="••••••••••••"
            />
            {isRegister && (
              <small className="form-hint">
                Must be at least 10 characters with upper, lower, and digit.
              </small>
            )}
          </div>

          <button type="submit" className="btn btn-primary btn-block" disabled={loading}>
            {loading ? 'Processing...' : isRegister ? 'Register' : 'Sign In'}
          </button>
        </form>

        <div className="auth-toggle">
          {isRegister ? (
            <p>
              Already have an account?{' '}
              <button
                type="button"
                className="link-button"
                onClick={() => {
                  setIsRegister(false);
                  setError(null);
                }}
              >
                Sign in
              </button>
            </p>
          ) : (
            <p>
              Need an account?{' '}
              <button
                type="button"
                className="link-button"
                onClick={() => {
                  setIsRegister(true);
                  setError(null);
                }}
              >
                Register
              </button>
            </p>
          )}
        </div>
      </div>
    </div>
  );
};
