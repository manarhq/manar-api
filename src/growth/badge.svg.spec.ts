import { describe, expect, it } from 'vitest';
import { renderBadge } from './badge.svg';

describe('badge', () => {
  const stats = { devices: 2, actions: 1204, blocked: 3, secretsKeptSafe: 1 };
  it('shows aggregate numbers and nothing named', () => {
    const svg = renderBadge(stats);
    expect(svg).toContain('Protected by Manar');
    expect(svg).toContain('1,204');
    expect(svg.startsWith('<svg')).toBe(true);
  });
  it('has an Arabic version', () => {
    expect(renderBadge(stats, 'ar')).toContain('محمي بواسطة منار');
  });
});
