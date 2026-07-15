/* Demo layer: the "notes" convention on top of the generic record engine.
 * A note is a record under the 'notes' resource with `title` + `body` columns.
 * The datalayer core knows nothing about notes — this file (and the UI + seeds)
 * is the demo-specific implementation. */
import type { CrDevice } from '@localrbac/datalayer';

export const NOTES_RESOURCE = 'notes';

export interface NoteView { id: string; title: string | null; body: string | null; }

export const addNote = (dev: CrDevice, title: string, body: string): Promise<string> =>
  dev.putRecord({ title, body }, NOTES_RESOURCE);

export const listNotes = async (dev: CrDevice): Promise<NoteView[]> =>
  (await dev.listRecords(NOTES_RESOURCE)).map((r) => ({
    id: r.id,
    title: r.cols.title ?? null, // null = locked (no readable title cell)
    body: r.cols.body ?? null,
  }));

/** Seed a couple of demo notes (called after genesis in the demo). */
export const seedNotes = async (dev: CrDevice): Promise<void> => {
  await addNote(dev, 'Welcome', 'A demo note. Edit it, export a changeset, and share it with another device.');
};
