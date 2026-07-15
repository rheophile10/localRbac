// Record a slow-motion, captioned Playwright video of three users exchanging
// difflogs, against the built dist/demo.html (file://).
// Output: videos/rbac-difflog-demo.webm
import { chromium, type Frame, type Page } from '@playwright/test';
import path from 'node:path';
import fs from 'node:fs';
import { fileURLToPath } from 'node:url';

const here = path.dirname(fileURLToPath(import.meta.url));
const DEMO = 'file://' + path.resolve(here, '..', 'dist', 'demo.html');
const VIDEODIR = path.resolve(here, '..', 'videos');
const id = (s: string): string => `[data-testid="${s}"]`;
const VIEWPORT = { width: 1500, height: 1260 };

const frameFor = async (page: Page, sel: string): Promise<Frame> => {
  const handle = await page.waitForSelector(sel);
  const frame = await handle.contentFrame();
  if (!frame) throw new Error('no frame ' + sel);
  await frame.waitForFunction(() => !!(window as any).__app);
  return frame;
};

const run = async (): Promise<void> => {
  fs.mkdirSync(VIDEODIR, { recursive: true });
  const browser = await chromium.launch({ slowMo: 500 });
  const context = await browser.newContext({ viewport: VIEWPORT, recordVideo: { dir: VIDEODIR, size: VIEWPORT } });
  const page = await context.newPage();

  const caption = async (text: string, holdMs = 1500): Promise<void> => {
    await page.evaluate((t) => {
      let c = document.getElementById('caption');
      if (!c) {
        c = document.createElement('div');
        c.id = 'caption';
        c.setAttribute('style',
          'position:fixed;top:0;left:0;right:0;z-index:9999;padding:9px 16px;' +
          'font:600 15px/1.4 ui-sans-serif,system-ui,sans-serif;color:#fff;' +
          'background:linear-gradient(90deg,#2b6fe0,#6ea8fe);box-shadow:0 2px 12px rgba(0,0,0,.3);text-align:center');
        document.body.prepend(c);
      }
      c.textContent = t;
    }, text);
    await page.waitForTimeout(holdMs);
  };

  await page.goto(DEMO);
  const admin = await frameFor(page, '#f-admin');
  const alice = await frameFor(page, '#f-alice');
  const bob = await frameFor(page, '#f-bob');
  await caption('Three separate app instances (iframes). They collaborate only by exchanging difflog files.', 2400);

  await caption('USER CREATION — admin signs in, creates the genesis DB, provisions two users');
  await admin.click(id('signin'));
  await admin.click(id('genesis'));
  await admin.fill(id('create-user-name'), 'alice');
  await admin.fill(id('create-user-pass'), 'alice-pw');
  await admin.selectOption(id('create-user-role'), 'writer');
  await admin.click(id('create-user-btn'));
  await admin.locator(id('urole-alice')).waitFor();
  await admin.fill(id('create-user-name'), 'bob');
  await admin.fill(id('create-user-pass'), 'bob-pw');
  await admin.selectOption(id('create-user-role'), 'reader');
  await admin.click(id('create-user-btn'));
  await admin.locator(id('urole-bob')).waitFor();
  await caption('PERMISSION ASSIGNMENT — alice = writer, bob = reader (admin-signed grants)', 1800);

  await caption('DIFF THE DB — admin exports a difflog (a delta of signed ops + a hash of the base state)');
  await admin.click(id('export-diff'));
  const genesisDiff = await admin.locator(id('difflog-out')).inputValue();

  await caption('LOAD + LOGIN — the two users import that difflog and log in as themselves');
  await alice.click(id('signin'));
  await alice.fill(id('difflog-in'), genesisDiff);
  await alice.click(id('import-diff'));
  await bob.click(id('signin'));
  await bob.fill(id('difflog-in'), genesisDiff);
  await bob.click(id('import-diff'));
  await caption('Alice is a WRITER, Bob is a READER — established purely from the imported ops', 2000);

  await caption('BASELINE — all three mark the shared starting state (matching content hashes)');
  await admin.click(id('mark-baseline'));
  await alice.click(id('mark-baseline'));
  await bob.click(id('mark-baseline'));

  await caption('CONCURRENT WRITES — admin and the writer add notes alternately; the reader cannot write');
  await admin.fill(id('note-title'), 'Admin-1'); await admin.fill(id('note-body'), 'a1'); await admin.click(id('note-add'));
  await alice.fill(id('note-title'), 'Alice-1'); await alice.fill(id('note-body'), 'w1'); await alice.click(id('note-add'));
  await admin.fill(id('note-title'), 'Admin-2'); await admin.fill(id('note-body'), 'a2'); await admin.click(id('note-add'));
  await alice.fill(id('note-title'), 'Alice-2'); await alice.fill(id('note-body'), 'w2'); await alice.click(id('note-add'));

  await caption('EXPORT DIFFS — each writer exports a delta since the shared baseline');
  await admin.click(id('export-diff'));
  const adminDiff = await admin.locator(id('difflog-out')).inputValue();
  await alice.click(id('export-diff'));
  const aliceDiff = await alice.locator(id('difflog-out')).inputValue();

  await caption('CROSS-IMPORT — everyone merges the other two difflogs');
  await admin.fill(id('difflog-in'), aliceDiff); await admin.click(id('import-diff'));
  await alice.fill(id('difflog-in'), adminDiff); await alice.click(id('import-diff'));
  await bob.fill(id('difflog-in'), adminDiff); await bob.click(id('import-diff'));
  await bob.fill(id('difflog-in'), aliceDiff); await bob.click(id('import-diff'));

  await caption('CONVERGED — notes INTERLEAVE by time on all three replicas; the reader decrypted them all', 3200);

  const video = page.video();
  await context.close();
  await browser.close();
  if (video) {
    const src = await video.path();
    const dest = path.join(VIDEODIR, 'rbac-difflog-demo.webm');
    fs.renameSync(src, dest);
    console.log(`wrote ${dest} (${(fs.statSync(dest).size / 1024).toFixed(0)} KB)`);
  }
};

void run();
