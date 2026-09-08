import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'

// Range backend binds 8780 (8770 is sherlog, 8765 skill-cti). Use the explicit
// IPv4 loopback, not `localhost` — on Windows `localhost` can resolve to ::1
// first and miss a backend bound only to 127.0.0.1.
const BE = 'http://127.0.0.1:8780'

export default defineConfig({
  plugins: [react()],
  server: {
    port: 5175,
    proxy: { '/api': BE },
  },
  build: {
    rollupOptions: {
      output: {
        manualChunks: {
          'vendor-react': ['react', 'react-dom', 'react-router-dom'],
          'vendor-query': ['@tanstack/react-query'],
        },
      },
    },
  },
})
