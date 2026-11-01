export interface BadgeStats {
  devices: number;
  actions: number;
  blocked: number;
  secretsKeptSafe: number;
}

const COPY = {
  en: {
    label: 'Protected by Manar',
    value: (n: number) =>
      `${n.toLocaleString('en')} AI actions checked this week`,
  },
  ar: {
    label: 'محمي بواسطة منار',
    value: (n: number) =>
      `${n.toLocaleString('ar-EG')} إجراء ذكاء اصطناعي تم فحصه هذا الأسبوع`,
  },
} as const;

const esc = (s: string) =>
  s.replace(/[&<>"']/g, (c) => `&#${c.charCodeAt(0)};`);

/** ~6.4px per character at 11px: close enough for a README badge without a font library. */
const width = (s: string) => Math.ceil(s.length * 6.4) + 20;

/**
 * The README badge. Aggregate numbers only (never a device or workspace name). The colours are
 * fixed because an SVG embedded on GitHub cannot use the console's CSS variables: Midnight and the
 * brand blue, as in the Midnight design system.
 */
export function renderBadge(
  stats: BadgeStats,
  lang: 'en' | 'ar' = 'en',
): string {
  const c = COPY[lang];
  const label = c.label;
  const value = c.value(stats.actions);
  const lw = width(label);
  const vw = width(value);
  const w = lw + vw;
  const font =
    'font-family="Readex Pro, Verdana, DejaVu Sans, sans-serif" font-size="11"';
  return `<svg xmlns="http://www.w3.org/2000/svg" width="${w}" height="22" viewBox="0 0 ${w} 22" role="img" aria-label="${esc(`${label}: ${value}`)}">
<title>${esc(`${label}: ${value}`)}</title>
<rect width="${w}" height="22" rx="4" fill="#02070A"/>
<rect x="${lw}" width="${vw}" height="22" rx="4" fill="#0297DE"/>
<rect x="${lw}" width="6" height="22" fill="#0297DE"/>
<g ${font} fill="#fff" text-anchor="middle"${lang === 'ar' ? ' direction="rtl"' : ''}>
<text x="${lw / 2}" y="15">${esc(label)}</text>
<text x="${lw + vw / 2}" y="15" fill="#02070A">${esc(value)}</text>
</g></svg>`;
}
