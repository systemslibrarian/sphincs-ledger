import { defineConfig } from 'vite';

// GitHub Pages deploys to https://<user>.github.io/<repo>/
// Base path must match the repo name for asset resolution.
export default defineConfig({
  base: '/crypto-lab-sphincs-ledger/',
  build: {
    outDir: 'dist',
  },
});
