/** Tailwind build config for the bundled UI (no CDN at runtime).
 *  Rebuild: npx tailwindcss@3.4.17 -c tailwind.config.js -i tailwind.input.css -o static/app.css --minify
 */
module.exports = {
  darkMode: 'class',
  content: ['./templates/**/*.html'],
  theme: {
    extend: {
      colors: {
        ink: { 950: '#07080c', 900: '#0b0d13', 800: '#12151f', 700: '#1b1f2c' },
        brand: { 400: '#a78bfa', 500: '#8b5cf6', 600: '#7c3aed' },
        aqua: { 400: '#22d3ee', 500: '#06b6d4' },
      },
      keyframes: {
        float: {
          '0%,100%': { transform: 'translate3d(0,0,0)' },
          '50%': { transform: 'translate3d(0,-12px,0)' },
        },
        shimmer: {
          '0%': { backgroundPosition: '0% 50%' },
          '100%': { backgroundPosition: '200% 50%' },
        },
        rise: {
          '0%': { opacity: '0', transform: 'translateY(10px)' },
          '100%': { opacity: '1', transform: 'translateY(0)' },
        },
      },
      animation: {
        float: 'float 9s ease-in-out infinite',
        shimmer: 'shimmer 6s linear infinite',
        rise: 'rise .4s cubic-bezier(.22,1,.36,1) both',
      },
    },
  },
  plugins: [],
};
