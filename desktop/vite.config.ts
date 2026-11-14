import { defineConfig } from 'vite';
import solid from 'vite-plugin-solid';

export default defineConfig({
  plugins: [solid()],
  server: {
    host: '127.0.0.1',
    port: 1420,
    strictPort: true,
    // The Wails window proxies the page, so point HMR at Vite directly.
    hmr: { host: '127.0.0.1', port: 1420 },
    watch: { ignored: ['**/build/**'] },
  },
  clearScreen: false,
  // zxcvbn's dictionaries (about 1.2 MB) load lazily when a master password
  // is typed; they ship inside the app, so the size is not a download cost.
  build: { chunkSizeWarningLimit: 1500 },
});
