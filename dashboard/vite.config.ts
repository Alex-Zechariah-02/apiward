import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'

// EAT_PORT_OFFSET shifts every demonstration address, as in the browser
// tests; E2E_DEV_PORT moves this development server.
function offsetPort(base: number): number {
  const value = process.env.EAT_PORT_OFFSET ?? ''
  if (value && !/^\d+$/.test(value)) throw new Error('EAT_PORT_OFFSET must be a nonnegative decimal integer')
  const port = base + Number(value)
  if (!Number.isSafeInteger(port) || port > 65535) throw new Error('EAT_PORT_OFFSET exceeds the available port range')
  return port
}

function developmentPort(defaultPort: number): number {
  const value = process.env.E2E_DEV_PORT
  if (value === undefined) return defaultPort
  const port = Number(value)
  if (!/^\d+$/.test(value) || !Number.isInteger(port) || port < 1 || port > 65535) throw new Error('E2E_DEV_PORT must be a valid port')
  return port
}

// The Admin API of a running demonstration.
const adminURL = `http://127.0.0.1:${offsetPort(9440)}`

// The dashboard is served by the gateway's admin listener at /, which serves
// only index.html and flat files under /assets/.
export default defineConfig({
  base: '/',
  plugins: [react()],
  server: {
    host: 'localhost',
    port: developmentPort(5173),
    strictPort: true,
    proxy: {
      '/admin': {
        target: adminURL,
        changeOrigin: true,
        configure: (proxy) => {
          proxy.on('proxyReq', (proxyRequest) => {
            if (proxyRequest.getHeader('origin')) proxyRequest.setHeader('origin', adminURL)
          })
        },
      },
    },
  },
  build: {
    outDir: 'dist',
    emptyOutDir: true,
    // The page's content policy allows only its own script and style files,
    // so nothing may be inlined.
    assetsInlineLimit: 0,
    modulePreload: { polyfill: false },
    sourcemap: false,
  },
})
