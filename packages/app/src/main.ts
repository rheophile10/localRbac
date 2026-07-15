import wasmB64 from 'virtual:crsqlite-wasm-b64';
import { createCrDevice, bootBrowserEngine } from '@localrbac/datalayer';
import { startApp } from './ui';
import './style.css';

// One app instance = one user's machine. demo.html iframes this N times.
// URL params prefill the login + label so the demo shell can label each frame.
const params = new URLSearchParams(location.search);
const prefill = {
  label: params.get('label') ?? 'Device',
  user: params.get('user') ?? '',
  pass: params.get('pass') ?? '',
};

// cr-sqlite wasm, inlined as base64 → ArrayBuffer (no network fetch on file://).
const wasmBinary = Uint8Array.from(atob(wasmB64), (c) => c.charCodeAt(0)).buffer;

const boot = async (): Promise<void> => {
  // Each frame persists to its own encrypted IndexedDB (named by the label).
  const idbName = 'localrbac-' + (prefill.label || 'device').toLowerCase().replace(/\W+/g, '');
  const engine = await bootBrowserEngine({ wasmBinary, idbName });
  const device = createCrDevice(engine, prefill.label);
  (window as unknown as { __app: typeof device }).__app = device; // test / cross-frame hook
  startApp(device, prefill);
};

void boot();
