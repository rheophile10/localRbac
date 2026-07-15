import { test, expect, type Frame, type Page } from '@playwright/test';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const here = path.dirname(fileURLToPath(import.meta.url));
const DEMO = 'file://' + path.resolve(here, '..', 'dist', 'demo.html');
const id = (s: string): string => `[data-testid="${s}"]`;

const frameFor = async (page: Page, sel: string): Promise<Frame> => {
  const handle = await page.waitForSelector(sel);
  const frame = await handle.contentFrame();
  if (!frame) throw new Error('no frame for ' + sel);
  await frame.waitForFunction(() => !!(window as unknown as { __app?: unknown }).__app, null, { timeout: 20000 });
  return frame;
};
const stateRoot = (f: Frame): Promise<string> => f.locator(id('state-root')).textContent().then((t) => t ?? '');

// export an identity card from a user's frame and return its JSON text
const exportCard = async (f: Frame): Promise<string> => {
  await f.click(id('export-card'));
  await expect.poll(async () => (await f.locator(id('card-out')).inputValue()).length).toBeGreaterThan(50);
  return f.locator(id('card-out')).inputValue();
};
// admin imports a card and grants the named user a role
const provision = async (admin: Frame, card: string, name: string, role: 'reader' | 'writer'): Promise<void> => {
  await admin.fill(id('card-in'), card);
  await admin.click(id('import-card-btn'));
  await expect(admin.locator(id(`urole-${name}`))).toBeVisible();
  await admin.click(id(`grant-${name}-${role}`));
  await expect(admin.locator(id(`urole-${name}`))).toContainText(role);
};

test.setTimeout(180000);

test('cr-sqlite + WebCrypto: card-exchange provisioning, changeset sync, RBAC-locked reads', async ({ page }) => {
  await page.goto(DEMO);
  const admin = await frameFor(page, '#f-admin');
  const alice = await frameFor(page, '#f-alice');
  const bob = await frameFor(page, '#f-bob');

  await test.step('admin genesis; users generate identities and share cards; admin grants', async () => {
    await admin.click(id('signin'));
    await admin.click(id('genesis'));
    await expect(admin.locator(id('role'))).toContainText('admin');

    await alice.click(id('signin'));
    await bob.click(id('signin'));
    await provision(admin, await exportCard(alice), 'alice', 'writer');
    await provision(admin, await exportCard(bob), 'bob', 'reader');
  });

  await test.step('admin writes a record, exports a changeset', async () => {
    await admin.fill(id('note-title'), 'Launch');
    await admin.fill(id('note-body'), 'the eagle lands at dawn');
    await admin.click(id('note-add'));
    await expect(admin.locator(id('note-text')).first()).toContainText('the eagle lands at dawn');
  });

  let changeset = '';
  await test.step('export changeset from admin', async () => {
    await admin.click(id('export-diff'));
    await expect.poll(async () => (await admin.locator(id('difflog-out')).inputValue()).length).toBeGreaterThan(100);
    changeset = await admin.locator(id('difflog-out')).inputValue();
  });

  await test.step('writer imports → reads + writes; reader imports → reads only', async () => {
    await alice.fill(id('difflog-in'), changeset);
    await alice.click(id('import-diff'));
    await expect(alice.locator(id('role'))).toContainText('writer');
    await expect(alice.locator(id('note-text')).first()).toContainText('the eagle lands at dawn');

    await bob.fill(id('difflog-in'), changeset);
    await bob.click(id('import-diff'));
    await expect(bob.locator(id('role'))).toContainText('reader');
    await expect(bob.locator(id('note-text')).first()).toContainText('the eagle lands at dawn');
    await expect(bob.locator(id('note-add'))).toHaveCount(0); // reader: no write UI
  });

  await test.step('writer adds a note; it converges back to admin', async () => {
    await alice.fill(id('note-title'), 'Reply');
    await alice.fill(id('note-body'), 'wilco');
    await alice.click(id('note-add'));
    await alice.click(id('export-diff'));
    await expect.poll(async () => (await alice.locator(id('difflog-out')).inputValue()).length).toBeGreaterThan(100);
    const fromAlice = await alice.locator(id('difflog-out')).inputValue();

    await admin.fill(id('difflog-in'), fromAlice);
    await admin.click(id('import-diff'));
    await expect(admin.locator(id('note-list'))).toContainText('wilco');
  });

  await test.step('converged: admin and writer show the same state root', async () => {
    const [ra, rb] = await Promise.all([stateRoot(admin), stateRoot(alice)]);
    expect(ra).toBe(rb);
  });
});
