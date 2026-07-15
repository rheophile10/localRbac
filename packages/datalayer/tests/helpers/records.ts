// Test conveniences over the GENERIC record API (putRecord/listRecords). Column
// names like title/body are just arbitrary strings here — the core is
// resource/column-agnostic; "notes" conventions live in the demo layer.
import type { CrDevice } from '../../src/engine/crengine';

export const addRecord = (dev: CrDevice, title: string, body: string, resource?: string): Promise<string> =>
  dev.putRecord({ title, body }, resource);

export const bodies = async (dev: CrDevice, resource?: string): Promise<(string | null)[]> =>
  (await dev.listRecords(resource)).map((r) => r.cols.body ?? null);

export const bodyOf = async (dev: CrDevice, id: string, resource?: string): Promise<string | null | undefined> =>
  (await dev.listRecords(resource)).find((r) => r.id === id)?.cols.body;

export const countRecords = async (dev: CrDevice, resource?: string): Promise<number> =>
  (await dev.listRecords(resource)).length;
