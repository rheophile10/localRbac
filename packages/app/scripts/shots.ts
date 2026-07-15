// Capture screenshots of the three-user demo (dist/demo.html) on file://.
import { chromium, type Frame, type Page } from '@playwright/test';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const here = path.dirname(fileURLToPath(import.meta.url));
const DEMO = 'file://' + path.resolve(here, '..', 'dist', 'demo.html');
const OUT = path.resolve(here, '..', 'shots');
const id = (s: string): string => `[data-testid="${s}"]`;

const frameFor = async (page: Page, sel: string): Promise<Frame> => {
  const h = await page.waitForSelector(sel);
  const f = await h.contentFrame();
  if (!f) throw new Error('no frame ' + sel);
  await f.waitForFunction(() => !!(window as any).__app);
  return f;
};

const run = async (): Promise<void> => {
  const browser = await chromium.launch();
  const page = await browser.newPage({ viewport: { width: 1500, height: 1260 } });
  const shot = (name: string) => page.screenshot({ path: path.join(OUT, name), fullPage: true });

  await page.goto(DEMO);
  const admin = await frameFor(page, '#f-admin');
  const alice = await frameFor(page, '#f-alice');
  const bob = await frameFor(page, '#f-bob');
  await shot('01-login.png');

  await admin.click(id('signin'));
  await admin.click(id('genesis'));
  for (const [n, p, r] of [['alice', 'alice-pw', 'writer'], ['bob', 'bob-pw', 'reader']] as const) {
    await admin.fill(id('create-user-name'), n);
    await admin.fill(id('create-user-pass'), p);
    await admin.selectOption(id('create-user-role'), r);
    await admin.click(id('create-user-btn'));
    await admin.locator(id(`urole-${n}`)).waitFor();
  }
  await admin.click(id('export-diff'));
  const diff = await admin.locator(id('difflog-out')).inputValue();
  await shot('02-provisioned.png');

  await alice.click(id('signin')); await alice.fill(id('difflog-in'), diff); await alice.click(id('import-diff'));
  await bob.click(id('signin')); await bob.fill(id('difflog-in'), diff); await bob.click(id('import-diff'));
  [admin, alice, bob].forEach(() => {});
  await admin.click(id('mark-baseline')); await alice.click(id('mark-baseline')); await bob.click(id('mark-baseline'));

  await admin.fill(id('note-title'), 'Admin-1'); await admin.fill(id('note-body'), 'a1'); await admin.click(id('note-add'));
  await alice.fill(id('note-title'), 'Alice-1'); await alice.fill(id('note-body'), 'w1'); await alice.click(id('note-add'));
  await admin.fill(id('note-title'), 'Admin-2'); await admin.fill(id('note-body'), 'a2'); await admin.click(id('note-add'));
  await alice.fill(id('note-title'), 'Alice-2'); await alice.fill(id('note-body'), 'w2'); await alice.click(id('note-add'));

  await admin.click(id('export-diff')); const adminDiff = await admin.locator(id('difflog-out')).inputValue();
  await alice.click(id('export-diff')); const aliceDiff = await alice.locator(id('difflog-out')).inputValue();
  await admin.fill(id('difflog-in'), aliceDiff); await admin.click(id('import-diff'));
  await alice.fill(id('difflog-in'), adminDiff); await alice.click(id('import-diff'));
  await bob.fill(id('difflog-in'), adminDiff); await bob.click(id('import-diff'));
  await bob.fill(id('difflog-in'), aliceDiff); await bob.click(id('import-diff'));
  await shot('03-interleaved.png');

  await browser.close();
  console.log('wrote screenshots to', OUT);
};

void run();
