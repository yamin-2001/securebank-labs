/** @type {import('tailwindcss').Config} */
export default {
  content: ['./index.html', './src/**/*.{js,ts,jsx,tsx}'],
  theme: {
    extend: {
      colors: {
        bank: {
          50: '#eef4ff',
          100: '#d9e6ff',
          500: '#2f5fd0',
          600: '#2450b4',
          700: '#1c3f8e',
          900: '#14264f',
        },
        ink: {
          900: '#0d1526',
          700: '#25324a',
          500: '#4a5872',
          300: '#8b96ab',
        },
      },
      fontFamily: {
        sans: ['Inter', 'system-ui', 'sans-serif'],
        mono: ['ui-monospace', 'SFMono-Regular', 'Menlo', 'monospace'],
      },
    },
  },
  plugins: [],
}
