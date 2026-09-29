/** @type {import('tailwindcss').Config} */
export default {
  content: ['./index.html', './src/**/*.{ts,tsx}'],
  theme: {
    extend: {
      colors: {
        navy: { 950: 'var(--navy-950)', 800: 'var(--navy-800)' },
        canvas: 'var(--bg)',
        surface: 'var(--surface)',
        line: 'var(--border)',
        saffron: 'var(--saffron)',
        success: 'var(--success)',
        warning: 'var(--warning)',
        critical: 'var(--critical)',
        muted: 'var(--muted-text)',
      },
      fontFamily: { sans: ['Inter', 'IBM Plex Sans', 'ui-sans-serif', 'system-ui', 'sans-serif'] },
    },
  },
  plugins: [],
}
