import type { Config } from 'tailwindcss'

// The range's own identity: emerald on near-black. Chosen to read as a
// hunting/defensive-ops tool and to sit apart from the sibling Sherlog app
// (violet) so the two are never confused when both are open.
//
// `mal` and `benign` are semantic, not decorative: `mal` marks confirmed
// attack activity in results and the answer key, `benign`/`decoy` mark the
// lookalikes. They must stay distinguishable from the emerald accent, which
// only ever means "selected/interactive".
export default {
  content: ['./index.html', './src/**/*.{ts,tsx}'],
  theme: {
    extend: {
      colors: {
        bg: '#080a0c',
        surface: '#0e1114',
        surface2: '#13171b',
        surface3: '#1a2026',
        line: '#1e252c',
        line2: '#2b3540',
        accent: {
          DEFAULT: '#10b981',
          dark: '#059669',
          light: '#34d399',
        },
        txt: {
          DEFAULT: '#e5edf2',
          2: '#8a9aa8',
          3: '#4d5b68',
        },
        // Ground-truth semantics. Amber for decoy is deliberate: a decoy is a
        // trap, not a threat, and must never read as "malicious".
        mal: '#f43f5e',       // confirmed attack
        decoy: '#f59e0b',     // benign lookalike
        noise: '#64748b',     // ambient benign anomaly
        good: '#10b981',      // a correct find
        // Confidence ramp for resolver candidates.
        conf: {
          high: '#34d399',
          medium: '#fbbf24',
          low: '#94a3b8',
        },
      },
      fontFamily: {
        mono: ['ui-monospace', 'SFMono-Regular', 'Menlo', 'Consolas', 'monospace'],
        sans: ['Inter', 'system-ui', '-apple-system', 'sans-serif'],
      },
      // A real type ramp — hierarchy comes from weight + tracking, not just size.
      fontSize: {
        display: ['1.75rem', { lineHeight: '2.1rem', letterSpacing: '-0.02em', fontWeight: '650' }],
        h1: ['1.35rem', { lineHeight: '1.75rem', letterSpacing: '-0.015em', fontWeight: '600' }],
        h2: ['1.05rem', { lineHeight: '1.5rem', letterSpacing: '-0.01em', fontWeight: '600' }],
      },
      // Elevation. Depth through light and shadow rather than borders everywhere.
      boxShadow: {
        card: '0 1px 2px rgba(0,0,0,0.4), 0 1px 1px rgba(0,0,0,0.3)',
        raised: '0 4px 16px -4px rgba(0,0,0,0.5), 0 2px 6px -2px rgba(0,0,0,0.4)',
        overlay: '0 16px 48px -12px rgba(0,0,0,0.7)',
        // A subtle emerald glow for the single primary action on hover.
        glow: '0 2px 14px -2px rgba(16,185,129,0.45)',
      },
      keyframes: {
        shimmer: { '100%': { transform: 'translateX(100%)' } },
        toastIn: {
          '0%': { opacity: '0', transform: 'translateY(8px) scale(0.98)' },
          '100%': { opacity: '1', transform: 'translateY(0) scale(1)' },
        },
      },
      animation: {
        shimmer: 'shimmer 1.6s infinite',
      },
    },
  },
  plugins: [],
} satisfies Config
