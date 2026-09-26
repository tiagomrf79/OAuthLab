import { resolve } from 'node:path'
import { defineConfig } from 'vite'

// Multi-page app: each flow is its own page, so each gets its own redirect URI (/implicit/,
// /code-pkce/) registered on the authorization server. The dev server serves these directories'
// index.html automatically; the build needs them listed as inputs.
export default defineConfig({
  server: {
    open: true,
  },
  build: {
    rollupOptions: {
      input: {
        main: resolve(import.meta.dirname, 'index.html'),
        implicit: resolve(import.meta.dirname, 'implicit/index.html'),
        codePkce: resolve(import.meta.dirname, 'code-pkce/index.html'),
      },
    },
  },
})
