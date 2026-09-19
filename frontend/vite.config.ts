import react from '@vitejs/plugin-react'
import { defineConfig } from 'vite'

// The dev server proxies API calls to the FastAPI backend, so the browser only
// ever talks to ONE origin (http://<host>:5173). This removes CORS/cookie
// problems in development and lets phones/other laptops on your network use
// `npm run dev -- --host` without any "localhost" URL pointing at the wrong machine.
const BACKEND = process.env.VITE_DEV_BACKEND_URL || 'http://127.0.0.1:8000'

export default defineConfig({
  plugins: [react()],
  server: {
    proxy: {
      '/api': { target: BACKEND, changeOrigin: false },
      '/auth/google': { target: BACKEND, changeOrigin: false },
      '/health': { target: BACKEND, changeOrigin: false },
    },
  },
})
