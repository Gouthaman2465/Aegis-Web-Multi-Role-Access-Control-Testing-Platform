import React from 'react';
import { BrowserRouter, Routes, Route, Navigate } from 'react-router-dom';
import { AuthProvider } from './auth/AuthContext';
import { ProtectedRoute } from './auth/ProtectedRoute';
import { Layout } from './components/Layout';

import { LoginPage } from './pages/LoginPage';
import { TargetsPage } from './pages/TargetsPage';
import { TargetDetailPage } from './pages/TargetDetailPage';
import { NewScanPage } from './pages/NewScanPage';
import { ScanDetailPage } from './pages/ScanDetailPage';
import { FindingDetailPage } from './pages/FindingDetailPage';
import { ComparePage } from './pages/ComparePage';
import { AuditLogPage } from './pages/AuditLogPage';

export const App: React.FC = () => {
  return (
    <AuthProvider>
      <BrowserRouter>
        <Routes>
          <Route path="/login" element={<LoginPage />} />

          <Route
            path="/*"
            element={
              <ProtectedRoute>
                <Layout>
                  <Routes>
                    <Route path="/" element={<Navigate to="/targets" replace />} />
                    <Route path="/targets" element={<TargetsPage />} />
                    <Route path="/targets/:id" element={<TargetDetailPage />} />
                    <Route path="/targets/:id/scan/new" element={<NewScanPage />} />
                    <Route path="/scans/:id" element={<ScanDetailPage />} />
                    <Route path="/scans/:id/compare/:otherId" element={<ComparePage />} />
                    <Route path="/findings/:id" element={<FindingDetailPage />} />
                    <Route
                      path="/admin/audit-log"
                      element={
                        <ProtectedRoute adminOnly>
                          <AuditLogPage />
                        </ProtectedRoute>
                      }
                    />
                    <Route path="*" element={<Navigate to="/targets" replace />} />
                  </Routes>
                </Layout>
              </ProtectedRoute>
            }
          />
        </Routes>
      </BrowserRouter>
    </AuthProvider>
  );
};

export default App;
