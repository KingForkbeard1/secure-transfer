import { defineConfig } from 'vitest/config';
import react from '@vitejs/plugin-react';

export default defineConfig({
  plugins: [react()],
  server: { port: 5173, proxy: { '/api': 'http://localhost:3000' } },
  build: { outDir: 'dist', sourcemap: false },
  test: { environment: 'node', env: { VITE_CHAT_BACKEND: 'mock' }, include: ['test/**/*.test.{ts,tsx}'], testTimeout: 20000 },
});
