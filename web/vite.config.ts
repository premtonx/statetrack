import { readFile } from 'node:fs/promises'
import { resolve, normalize } from 'node:path'
import { defineConfig, type Plugin } from 'vite'
import react from '@vitejs/plugin-react'
import tailwindcss from '@tailwindcss/vite'

// Provisioned integration assets (Grafana dashboard, Prometheus rules, Checkmk
// plugin, Zabbix template) live in integrations/ at the repo root, beside the
// documentation that describes them. The console serves them for copy/download.
//
// They are served under /integration-assets/ rather than /integrations/ because
// `/integrations` is the hub's own SPA route, and an asset prefix that shadows a
// route is a bug waiting for a trailing slash.
//
// Serving them straight out of integrations/ in dev means there is exactly one
// copy on disk and no generated file to keep in sync while iterating. A
// production build has no repo root to read from, so `dev.ps1 web-build` copies
// them into web/public first and Vite bundles them normally.
const ASSET_PREFIX = '/integration-assets/'
const ASSET_ROOT = resolve(__dirname, '..', 'integrations')

function integrationAssets(): Plugin {
  return {
    name: 'statetrack-integration-assets',
    apply: 'serve',
    configureServer(server) {
      server.middlewares.use((req, res, next) => {
        const path = (req.url ?? '').split('?')[0]
        if (!path.startsWith(ASSET_PREFIX)) return next()

        // Resolve, then confirm the result is still inside ASSET_ROOT: a
        // request for /integration-assets/../../etc/passwd must not escape.
        const rel = normalize(decodeURIComponent(path.slice(ASSET_PREFIX.length)))
        const file = resolve(ASSET_ROOT, rel)
        if (!file.startsWith(ASSET_ROOT)) {
          res.statusCode = 403
          res.end('forbidden')
          return
        }

        readFile(file)
          .then((body) => {
            res.statusCode = 200
            res.setHeader('Content-Type', contentType(file))
            res.end(body)
          })
          .catch(() => next())
      })
    },
  }
}

function contentType(file: string): string {
  if (file.endsWith('.json')) return 'application/json; charset=utf-8'
  if (file.endsWith('.yaml') || file.endsWith('.yml')) return 'text/yaml; charset=utf-8'
  if (file.endsWith('.py')) return 'text/x-python; charset=utf-8'
  if (file.endsWith('.md')) return 'text/markdown; charset=utf-8'
  return 'text/plain; charset=utf-8'
}

// The Go backend serves REST + WebSocket APIs on localhost:8080. During
// development the Vite dev server proxies /api (including the WS upgrade for
// /api/v1/stream) to it, so the console never deals with CORS or origin
// mismatches.
export default defineConfig({
  plugins: [react(), tailwindcss(), integrationAssets()],
  server: {
    port: 5173,
    proxy: {
      '/api': {
        target: process.env.STATETRACK_API_URL ?? 'http://localhost:8080',
        changeOrigin: true,
        ws: true,
      },
      // The hub shows the live /metrics exposition (counter names, scrape
      // status), so the dev server forwards it to the Go backend too.
      '/metrics': {
        target: process.env.STATETRACK_API_URL ?? 'http://localhost:8080',
        changeOrigin: true,
      },
    },
  },
})
