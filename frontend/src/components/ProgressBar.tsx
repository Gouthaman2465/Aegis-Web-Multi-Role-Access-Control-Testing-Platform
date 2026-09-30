import React from 'react';

interface ProgressBarProps {
  percent: number;
  stage: string;
  status: string;
}

export const ProgressBar: React.FC<ProgressBarProps> = ({ percent, stage, status }) => {
  const clamped = Math.max(0, Math.min(100, percent));

  let statusClass = 'progress-normal';
  if (status === 'completed') statusClass = 'progress-completed';
  if (status === 'failed') statusClass = 'progress-failed';
  if (status === 'cancelled') statusClass = 'progress-cancelled';

  return (
    <div className={`scan-progress-container ${statusClass}`}>
      <div className="progress-header">
        <span className="progress-stage-label">Stage: <strong>{stage}</strong></span>
        <span className="progress-percent-label">{clamped}%</span>
      </div>
      <div className="progress-track">
        <div className="progress-fill" style={{ width: `${clamped}%` }} />
      </div>
    </div>
  );
};
