import { defineConfig } from 'vite';
import { viteSingleFile } from 'vite-plugin-singlefile';
import { fileURLToPath } from 'node:url';

// Build spike.html into ONE self-contained file with the crsqlite wasm inlined
// as a data: URI (assetsInlineLimit=MAX). fetch() of a data: URI works on
// file://, so this proves the cr-sqlite engine on the real target.
export default defineConfig({
  plugins: [viteSingleFile()],
  build: {
    target: 'es2022',
    assetsInlineLimit: Number.MAX_SAFE_INTEGER,
    cssCodeSplit: false,
    outDir: 'dist-spike',
    rollupOptions: { input: fileURLToPath(new URL('./' + (process.env.SPIKE_ENTRY ?? 'spike.html'), import.meta.url)) },
  },
});
