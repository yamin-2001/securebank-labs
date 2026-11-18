import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'

// The React app runs on its own dev server (:5173) and proxies every API
// call to the Spring Boot backend (:8080). The browser therefore stays
// same-origin — there is no CORS configuration anywhere.
//
// Note: labs.json is NOT proxied. The Labs panel imports it as a bundled
// module (`import labs from '../labs.json'`), so Vite serves it from
// src/ — it never makes an HTTP request for it. The backend does not have
// a labs.json either, so proxying it would only produce a 500.
export default defineConfig({
  plugins: [react()],
  server: {
    port: 5173,
    strictPort: true,
    proxy: {
      '/api': {
        target: 'http://localhost:8080',
        changeOrigin: true,
      },
      '/admin-panel': {
        target: 'http://localhost:8080',
        changeOrigin: true,
      },
      '/uploads': {
        target: 'http://localhost:8080',
        changeOrigin: true,
      },
    },
  },
})
