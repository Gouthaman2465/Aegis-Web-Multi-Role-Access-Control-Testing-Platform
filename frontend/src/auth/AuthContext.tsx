/**
 * Authentication context managing JWT token in React state mirrored to sessionStorage.
 */

import React, { createContext, useContext, useEffect, useState } from 'react';
import { getMe, login as apiLogin, register as apiRegister, setOnUnauthorized, setToken } from '../api/client';
import { User } from '../api/types';

interface AuthContextType {
  token: string | null;
  user: User | null;
  isAuthenticated: boolean;
  isAdmin: boolean;
  loading: boolean;
  login: (email: string, pass: string) => Promise<void>;
  register: (email: string, pass: string) => Promise<void>;
  logout: () => void;
}

const AuthContext = createContext<AuthContextType | undefined>(undefined);

export const AuthProvider: React.FC<{ children: React.ReactNode }> = ({ children }) => {
  const [token, setTokenState] = useState<string | null>(() => {
    return sessionStorage.getItem('aegis_token');
  });
  const [user, setUser] = useState<User | null>(null);
  const [loading, setLoading] = useState<boolean>(true);

  const updateToken = (newToken: string | null) => {
    setTokenState(newToken);
    setToken(newToken);
    if (newToken) {
      sessionStorage.setItem('aegis_token', newToken);
    } else {
      sessionStorage.removeItem('aegis_token');
      setUser(null);
    }
  };

  const logout = () => {
    updateToken(null);
  };

  useEffect(() => {
    setOnUnauthorized(() => {
      logout();
    });
  }, []);

  useEffect(() => {
    const initAuth = async () => {
      if (token) {
        setToken(token);
        try {
          const me = await getMe();
          setUser(me);
        } catch {
          logout();
        }
      }
      setLoading(false);
    };
    initAuth();
  }, [token]);

  const login = async (email: string, pass: string) => {
    const res = await apiLogin(email, pass);
    updateToken(res.access_token);
    setUser(res.user);
  };

  const register = async (email: string, pass: string) => {
    await apiRegister(email, pass);
    await login(email, pass);
  };

  const value: AuthContextType = {
    token,
    user,
    isAuthenticated: !!token && !!user,
    isAdmin: user?.role === 'admin',
    loading,
    login,
    register,
    logout,
  };

  return <AuthContext.Provider value={value}>{children}</AuthContext.Provider>;
};

export function useAuth(): AuthContextType {
  const ctx = useContext(AuthContext);
  if (!ctx) {
    throw new Error('useAuth must be used within an AuthProvider');
  }
  return ctx;
}
