/** @type {import('tailwindcss').Config} */
export default {
  content: [
    "./index.html",
    "./src/**/*.{js,ts,jsx,tsx}",
  ],
  theme: {
    extend: {
      colors: {
        cyber: {
          darker: "#07090e",
          dark: "#0d1117",
          card: "#161b22",
          border: "#30363d",
          green: "#00ff88",
          purple: "#a855f7",
          cyan: "#00f0ff",
          red: "#ff3366",
          yellow: "#ffcc00"
        }
      },
      fontFamily: {
        mono: ['"JetBrains Mono"', 'monospace', 'ui-monospace'],
      }
    },
  },
  plugins: [],
}
