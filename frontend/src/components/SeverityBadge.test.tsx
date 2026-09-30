import '@testing-library/jest-dom/vitest';
import { render, screen } from '@testing-library/react';
import { describe, it, expect } from 'vitest';
import { SeverityBadge } from './SeverityBadge';

describe('SeverityBadge', () => {
  const severities = [
    { name: 'Critical', expectedClass: 'badge-critical' },
    { name: 'High', expectedClass: 'badge-high' },
    { name: 'Medium', expectedClass: 'badge-medium' },
    { name: 'Low', expectedClass: 'badge-low' },
    { name: 'Info', expectedClass: 'badge-info' },
  ];

  severities.forEach(({ name, expectedClass }) => {
    it(`renders ${name} with class ${expectedClass}`, () => {
      const { container } = render(<SeverityBadge severity={name} />);
      const badge = container.querySelector('.severity-badge');
      expect(badge).toHaveClass(expectedClass);
      expect(screen.getByText(name)).toBeInTheDocument();
    });
  });
});
