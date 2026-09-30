import React from 'react';
import { diffLines, Change } from 'diff';
import { FindingEvidence } from '../api/types';

interface DiffViewerProps {
  evidence?: FindingEvidence;
}

export const DiffViewer: React.FC<DiffViewerProps> = ({ evidence }) => {
  if (!evidence) {
    return <div className="diff-empty">No replay evidence available for this finding.</div>;
  }

  const original = evidence.original;
  const replay = evidence.replay;

  const origStatus = original ? `HTTP ${original.status}` : 'N/A';
  const replayStatus = replay ? `HTTP ${replay.status}` : 'N/A';

  const origHeadersStr = original?.headers
    ? Object.entries(original.headers)
        .map(([k, v]) => `${k}: ${v}`)
        .join('\n')
    : '';

  const replayHeadersStr = replay?.headers
    ? Object.entries(replay.headers)
        .map(([k, v]) => `${k}: ${v}`)
        .join('\n')
    : '';

  const origBody = original?.body_preview || '';
  const replayBody = replay?.body_preview || '';

  const changes: Change[] = diffLines(origBody, replayBody);

  return (
    <div className="diff-viewer-container" data-testid="diff-viewer">
      <div className="diff-meta-bar">
        <span>Similarity Score: <strong>{evidence.similarity ?? 'N/A'}</strong></span>
        {evidence.stability !== undefined && (
          <span>Control Stability: <strong>{evidence.stability}</strong></span>
        )}
      </div>

      <div className="diff-columns">
        {/* Original Column */}
        <div className="diff-column original-column">
          <div className="column-header">
            <h4>Original Request ({original?.role || 'source'})</h4>
            <span className="status-code">{origStatus}</span>
          </div>

          <div className="section-block">
            <h5>Headers</h5>
            <pre className="headers-pre" data-testid="orig-headers">
              {origHeadersStr || '(No headers)'}
            </pre>
          </div>

          <div className="section-block">
            <h5>Body Preview</h5>
            <pre className="body-pre" data-testid="orig-body">
              {origBody || '(Empty body)'}
            </pre>
          </div>
        </div>

        {/* Replay Column */}
        <div className="diff-column replay-column">
          <div className="column-header">
            <h4>Replay Response ({replay?.role || 'tested'})</h4>
            <span className="status-code">{replayStatus}</span>
          </div>

          <div className="section-block">
            <h5>Headers</h5>
            <pre className="headers-pre" data-testid="replay-headers">
              {replayHeadersStr || '(No headers)'}
            </pre>
          </div>

          <div className="section-block">
            <h5>Body Preview</h5>
            <pre className="body-pre" data-testid="replay-body">
              {replayBody || '(Empty body)'}
            </pre>
          </div>
        </div>
      </div>

      {/* Unified Line Diff */}
      <div className="diff-unified-section">
        <h4>Normalized Line Diff (Original vs Replay)</h4>
        <pre className="unified-diff-pre" data-testid="diff-lines">
          {changes.map((part, index) => {
            const lineClass = part.added
              ? 'diff-added'
              : part.removed
              ? 'diff-removed'
              : 'diff-unchanged';
            const prefix = part.added ? '+ ' : part.removed ? '- ' : '  ';
            return (
              <span key={index} className={lineClass}>
                {prefix}
                {part.value}
              </span>
            );
          })}
        </pre>
      </div>
    </div>
  );
};
