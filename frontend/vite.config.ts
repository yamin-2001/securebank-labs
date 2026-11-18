import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'

// The React app runs on its own dev server (:5173) and proxies every API
// call to the Spring Boot backend (:8080). The browser therefore stays
// same-origin — there is no CORS configuration anywhere.
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
      '/labs.json': {
        target: 'http://localhost:8080',
        changeOrigin: true,
      },
    },
  },
})
