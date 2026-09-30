import { describe, it, expect, vi, beforeEach } from 'vitest';
import {
  getToken,
  listTargets,
  setOnUnauthorized,
  setToken,
  ApiError,
} from './client';

describe('API Client', () => {
  beforeEach(() => {
    setToken(null);
    sessionStorage.clear();
    vi.restoreAllMocks();
  });

  it('attaches Authorization: Bearer <token> header when token is set', async () => {
    const fakeToken = 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.test.jwt';
    setToken(fakeToken);

    const mockFetch = vi.fn().mockResolvedValue({
      ok: true,
      status: 200,
      headers: new Headers({ 'content-type': 'application/json' }),
      json: async () => [{ id: 1, name: 'Target 1' }],
    });
    vi.stubGlobal('fetch', mockFetch);

    const result = await listTargets();
    expect(result).toEqual([{ id: 1, name: 'Target 1' }]);

    expect(mockFetch).toHaveBeenCalledTimes(1);
    const calledHeaders = mockFetch.mock.calls[0][1]?.headers as Record<string, string>;
    expect(calledHeaders['Authorization']).toBe(`Bearer ${fakeToken}`);
  });

  it('clears token, sessionStorage, and calls unauthorized callback on 401 response', async () => {
    const fakeToken = 'expired-or-revoked-token';
    setToken(fakeToken);
    sessionStorage.setItem('aegis_token', fakeToken);

    const unauthorizedCallback = vi.fn();
    setOnUnauthorized(unauthorizedCallback);

    const mockFetch = vi.fn().mockResolvedValue({
      ok: false,
      status: 401,
      headers: new Headers({ 'content-type': 'application/json' }),
      json: async () => ({ detail: 'Token has expired' }),
    });
    vi.stubGlobal('fetch', mockFetch);

    await expect(listTargets()).rejects.toThrow(ApiError);

    // Assert token state cleared
    expect(getToken()).toBeNull();
    expect(sessionStorage.getItem('aegis_token')).toBeNull();
    expect(unauthorizedCallback).toHaveBeenCalledTimes(1);
  });
});
