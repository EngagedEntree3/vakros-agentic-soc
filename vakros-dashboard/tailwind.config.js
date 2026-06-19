/** @type {import('tailwindcss').Config} */
module.exports = {
  content: [
    './pages/**/*.{js,ts,jsx,tsx,mdx}',
    './components/**/*.{js,ts,jsx,tsx,mdx}',
    './app/**/*.{js,ts,jsx,tsx,mdx}',
  ],
  theme: {
    extend: {
      colors: {
        'soc-bg': '#0a0e1a',
        'soc-panel': '#111827',
        'soc-border': '#1f2937',
        'soc-accent': '#3b82f6',
      }
    },
  },
  plugins: [],
}
