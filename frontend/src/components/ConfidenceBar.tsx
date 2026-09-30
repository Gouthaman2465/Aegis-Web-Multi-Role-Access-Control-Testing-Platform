import React from 'react';

interface ConfidenceBarProps {
  confidence: number;
}

export const ConfidenceBar: React.FC<ConfidenceBarProps> = ({ confidence }) => {
  const clamped = Math.max(0, Math.min(100, confidence));
  let color = '#22c55e'; // green
  if (clamped < 60) color = '#ef4444'; // red
  else if (clamped < 80) color = '#f59e0b'; // amber

  return (
    <div className="confidence-wrapper" title={`Confidence: ${clamped}%`}>
      <div className="confidence-bar-bg">
        <div
          className="confidence-bar-fill"
          style={{ width: `${clamped}%`, backgroundColor: color }}
        />
      </div>
      <span className="confidence-label">{clamped}%</span>
    </div>
  );
};
