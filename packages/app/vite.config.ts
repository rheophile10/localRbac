import { defineConfig, type Plugin } from 'vite';
import { viteSingleFile } from 'vite-plugin-singlefile';
import { readFileSync } from 'node:fs';
import { createRequire } from 'node:module';
import { fileURLToPath } from 'node:url';

// The headless engine lives in the sibling datalayer package; import its source
// directly so Vite bundles it into the single file (TS transpiled, tree-shaken).
const datalayerSrc = fileURLToPath(new URL('../datalayer/src/index.ts', import.meta.url));
const repoRoot = fileURLToPath(new URL('../..', import.meta.url));


// Inline the cr-sqlite WASM as a base64 string via a virtual module, so it is
// embedded in the single-file bundle and handed to wa-sqlite as `wasmBinary`
// (no network fetch → runs on file://).
const crsqliteWasmInline = (): Plugin => {
  const id = 'virtual:crsqlite-wasm-b64';
  const resolved = '\0' + id;
  const require = createRequire(import.meta.url);
  return {
    name: 'crsqlite-wasm-inline',
    resolveId: (source) => (source === id ? resolved : null),
    load(thisId) {
      if (thisId !== resolved) return null;
      const wasmPath = require.resolve('@vlcn.io/wa-sqlite/dist/crsqlite.wasm');
      const b64 = readFileSync(wasmPath).toString('base64');
      return `export default ${JSON.stringify(b64)};`;
    },
  };
};

export default defineConfig({
  plugins: [crsqliteWasmInline(), viteSingleFile()],
  resolve: {
    alias: { '@localrbac/datalayer': datalayerSrc },
  },
  server: {
    // allow the dev server to serve the sibling datalayer package source
    fs: { allow: [repoRoot] },
  },
  build: {
    target: 'es2022',
    // one self-contained file, no split chunks
    assetsInlineLimit: Number.MAX_SAFE_INTEGER,
    cssCodeSplit: false,
  },
  // demo.html lives in public/ (static shell that iframes the built app 3x)
});
