import '@testing-library/jest-dom/vitest';
import { render, screen } from '@testing-library/react';
import { describe, it, expect } from 'vitest';
import { DiffViewer } from './DiffViewer';
import { FindingEvidence } from '../api/types';

describe('DiffViewer', () => {
  it('renders hostile payload as text node and creates no img element in DOM', () => {
    const maliciousPayload = '<img src=x onerror=alert(1)>';
    const evidence: FindingEvidence = {
      original: {
        role: 'alice',
        status: 200,
        headers: { 'X-Injected': maliciousPayload },
        body_preview: maliciousPayload,
      },
      replay: {
        role: 'bob',
        status: 200,
        headers: { 'X-Injected': maliciousPayload },
        body_preview: maliciousPayload,
      },
      similarity: 1.0,
    };

    const { container } = render(<DiffViewer evidence={evidence} />);

    // Assert that NO <img> element was inserted into the DOM
    const imgElements = container.querySelectorAll('img');
    expect(imgElements.length).toBe(0);

    // Assert that the exact string appears as visible text content
    const allMatches = screen.getAllByText(new RegExp('<img src=x onerror=alert\\(1\\)>', 'i'));
    expect(allMatches.length).toBeGreaterThan(0);
  });
});
