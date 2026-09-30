import React from 'react';

interface SeverityBadgeProps {
  severity: 'Critical' | 'High' | 'Medium' | 'Low' | 'Info' | string;
}

export const SeverityBadge: React.FC<SeverityBadgeProps> = ({ severity }) => {
  const norm = (severity || 'info').toLowerCase();
  const badgeClass = `severity-badge badge-${norm}`;

  return <span className={badgeClass}>{severity}</span>;
};
