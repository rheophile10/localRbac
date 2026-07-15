/* Vanilla-DOM UI for ONE device on the cr-sqlite engine (async). Iframe the app
 * N times for N users. RBAC is enforced by the datalayer; this file renders
 * state and awaits device calls. Tagged data-testid for the Playwright e2e. */
import type { CrDevice } from '@localrbac/datalayer';
import { short } from '@localrbac/datalayer';
import { addNote, listNotes, seedNotes } from './notes';

type ElProps = Record<string, string | EventListener>;
type ElChild = Node | string;

const el = (tag: string, props: ElProps = {}, kids: ElChild | ElChild[] = []): HTMLElement => {
  const e = document.createElement(tag);
  for (const k in props) {
    const v = props[k];
    if (k.startsWith('on') && typeof v === 'function') e.addEventListener(k.slice(2), v);
    else if (k === 'class') e.className = v as string;
    else e.setAttribute(k, v as string);
  }
  for (const c of ([] as ElChild[]).concat(kids)) e.append(c);
  return e;
};
const tid = (name: string): ElProps => ({ 'data-testid': name });

export const startApp = (dev: CrDevice, prefill: { label: string; user: string; pass: string }): void => {
  const root = document.querySelector('#app') as HTMLElement;
  document.querySelector('#dev-label')!.textContent = prefill.label;
  let lastSync = '';
  let hasDb = false; // whether genesis/import has created the local DB

  const toast = (msg: string, bad = false): void => {
    const t = document.querySelector('#toast') as HTMLElement;
    t.textContent = msg;
    t.className = 'show' + (bad ? ' bad' : '');
    setTimeout(() => (t.className = ''), 2600);
  };
  const download = (text: string, name: string): void => {
    const a = document.createElement('a');
    a.href = URL.createObjectURL(new Blob([text], { type: 'application/json' }));
    a.download = name; a.click(); URL.revokeObjectURL(a.href);
  };
  const copy = async (text: string): Promise<boolean> => {
    try { await navigator.clipboard.writeText(text); return true; } catch { return false; }
  };

  /* ---- login: new identity (→ download keystore) OR load a keystore file --*/
  const downloadKeystore = (blob: unknown, name: string): void =>
    download(JSON.stringify(blob, null, 2), `${name}.keystore`);

  const loginForm = (): HTMLElement => {
    const wrap = el('div', { class: 'login', ...tid('login') });

    // (1) NEW identity: generate keys, then download a keystore file to keep.
    const f = el('form', { class: 'login' }) as HTMLFormElement;
    const user = el('input', { class: 'u', ...tid('user'), placeholder: 'user name' }) as HTMLInputElement;
    const pass = el('input', { type: 'password', ...tid('pass'), placeholder: 'passphrase (wraps your keystore file)' }) as HTMLInputElement;
    user.value = prefill.user; pass.value = prefill.pass;
    f.addEventListener('submit', async (e) => {
      e.preventDefault();
      const name = user.value.trim(); const pw = pass.value;
      if (!name || !pw) return;
      await dev.login(name); // generate a fresh identity
      const blob = await dev.exportKeystore(pw); // wrap it under the passphrase
      downloadKeystore(blob, name);
      toast(`new identity — keystore downloaded as ${name}.keystore. Keep it safe!`);
      await render();
    });
    f.append(user, pass,
      el('button', { class: 'primary', type: 'submit', ...tid('signin') }, 'New identity + download keystore'),
      el('div', { class: 'hint' }, 'A random keypair (Ed25519 + X25519) generated in-browser and saved as a keystore FILE (wrapped with your passphrase — Argon2id + AES-GCM). Nothing is stored in the browser; keep the file.'));
    wrap.append(f);

    // (2) LOAD an existing keystore file + passphrase.
    const lf = el('form', { class: 'login' }) as HTMLFormElement;
    const ksInput = el('input', { type: 'file', accept: '.keystore,.json', ...tid('keystore-file') }) as HTMLInputElement;
    const ksPass = el('input', { type: 'password', ...tid('keystore-pass'), placeholder: 'keystore passphrase' }) as HTMLInputElement;
    lf.addEventListener('submit', async (e) => {
      e.preventDefault();
      const file = ksInput.files?.[0]; const pw = ksPass.value;
      if (!file || !pw) { toast('choose a keystore file + passphrase', true); return; }
      try {
        const blob = JSON.parse(await file.text());
        await dev.unlock(blob, pw);
        toast('keystore unlocked');
        await render();
      } catch { toast('wrong passphrase or bad keystore', true); }
    });
    lf.append(el('div', { class: 'hint' }, 'Already have a keystore? Load it:'), ksInput, ksPass,
      el('button', { type: 'submit', ...tid('unlock-btn') }, 'Unlock keystore file'));
    wrap.append(lf);
    return wrap;
  };

  /* ---- admin -------------------------------------------------------------*/
  const adminPanel = async (): Promise<HTMLElement> => {
    const p = el('div', { class: 'panel', ...tid('admin') }, [el('h3', {}, '🔑 Admin')]);
    // Import a user's identity card (they exported it on their own device), which
    // records their public key so we can grant them a role. No passwords here.
    const cardIn = el('textarea', { class: 'diff', ...tid('card-in'), placeholder: 'paste a user\'s identity card, then Import' }) as HTMLTextAreaElement;
    p.append(el('div', { class: 'hint' }, 'Import a user\'s identity card (their public key), then grant a role.'), cardIn,
      el('button', {
        class: 'primary', ...tid('import-card-btn'),
        onclick: async () => {
          const raw = cardIn.value.trim();
          if (!raw) return;
          try { await dev.importIdentityCard(JSON.parse(raw)); cardIn.value = ''; toast('identity card imported'); await render(); }
          catch (err) { toast('bad card: ' + (err as Error).message, true); }
        },
      }, 'Import identity card'));

    const adminPub = await dev.adminPub();
    const users = (await dev.knownUsers()).filter((u) => u.pub !== adminPub);
    users.forEach((u) => {
      const row = el('div', { class: 'urow', ...tid(`user-row-${u.name}`) });
      row.append(el('span', { class: 'uname' }, u.name), el('span', { class: 'urole r-' + u.role, ...tid(`urole-${u.name}`) }, u.role));
      (['reader', 'writer'] as const).forEach((r) => row.append(el('button', {
        class: 'mini', ...tid(`grant-${u.name}-${r}`),
        onclick: async () => { try { await dev.grant(u.pub, r); toast(`${u.name} → ${r}`); await render(); } catch (err) { toast((err as Error).message, true); } },
      }, r)));
      row.append(el('button', {
        class: 'mini danger', ...tid(`revoke-${u.name}`),
        onclick: async () => { try { await dev.revoke(u.pub); toast(`${u.name} revoked`, true); await render(); } catch (err) { toast((err as Error).message, true); } },
      }, 'revoke'));
      p.append(row);
    });
    return p;
  };

  /* ---- notes -------------------------------------------------------------*/
  const notesPanel = async (): Promise<HTMLElement> => {
    const role = await dev.myRole();
    const canWrite = role === 'admin' || role === 'writer';
    const p = el('div', { class: 'panel', ...tid('notes') }, [el('h3', {}, '📝 Records')]);
    if (canWrite) {
      const add = el('div', { class: 'add' });
      const t = el('input', { ...tid('note-title'), placeholder: 'title' }) as HTMLInputElement;
      const b = el('input', { ...tid('note-body'), placeholder: 'body' }) as HTMLInputElement;
      add.append(t, b, el('button', {
        class: 'primary', ...tid('note-add'),
        onclick: async () => {
          if (!t.value.trim()) return;
          try { await addNote(dev, t.value.trim(), b.value.trim()); t.value = ''; b.value = ''; await render(); }
          catch (err) { toast((err as Error).message, true); }
        },
      }, 'Add'));
      p.append(add);
    } else {
      p.append(el('div', { class: 'hint' }, role === 'none' ? 'read-only view — writing is denied' : 'you may read but not write'));
    }
    const list = el('div', tid('note-list'));
    const notes = await listNotes(dev);
    if (!notes.length) list.append(el('div', { class: 'empty' }, 'no records'));
    notes.forEach((n) => {
      const locked = n.title === null && n.body === null;
      const rowEl = el('div', { class: 'note' + (locked ? ' locked' : '') });
      if (locked) rowEl.append(el('span', { class: 'lock', ...tid('locked') }, '🔒 encrypted — you lack the key'));
      else rowEl.append(
        el('span', { class: 'ntitle' }, n.title === null ? '🔒' : n.title || '(untitled)'),
        el('span', { class: 'nbody', ...tid('note-text') }, n.body === null ? '🔒' : n.body),
      );
      list.append(rowEl);
    });
    p.append(list);
    return p;
  };

  /* ---- sync (changesets) -------------------------------------------------*/
  const syncPanel = async (): Promise<HTMLElement> => {
    const p = el('div', { class: 'panel', ...tid('sync') }, [el('h3', {}, '🔁 Sync — changesets')]);
    p.append(el('div', { class: 'root' }, ['state root ', el('code', tid('state-root'), short(await dev.stateRoot()))]));

    const mergeText = async (raw: string): Promise<void> => {
      const t = raw.trim();
      if (!t) { toast('nothing to merge', true); return; }
      try {
        const r = await dev.importChangeset(t);
        lastSync = r.applied ? '✓ merged changeset' : `⚠ REJECTED: ${r.rejected[0] ?? 'unauthorized'}`;
        toast(r.applied ? 'merged' : 'rejected', !r.applied);
        await render();
      } catch (err) { lastSync = '⚠ bad changeset'; toast((err as Error).message, true); await render(); }
    };

    const out = el('textarea', { class: 'diff', readonly: 'true', ...tid('difflog-out'), placeholder: 'exported changeset appears here', onfocus: (e) => (e.target as HTMLTextAreaElement).select() }) as HTMLTextAreaElement;
    p.append(el('button', {
      class: 'primary', ...tid('export-diff'),
      onclick: async () => {
        const sql = await dev.exportChangeset(-1);
        out.value = sql;
        const name = `${dev.session?.name ?? 'device'}-changeset.sql`;
        download(sql, name); void copy(sql);
        lastSync = `⤓ exported changeset → ${name} (also copied)`;
        (document.querySelector('[data-testid="sync-status"]') as HTMLElement).textContent = lastSync;
        toast(`saved ${name}`);
      },
    }, 'Export changeset ⤓ (save file + copy)'), out);

    const inp = el('textarea', { class: 'diff', ...tid('difflog-in'), placeholder: 'paste a changeset (or open a file) then merge' }) as HTMLTextAreaElement;
    const fileIn = el('input', { type: 'file', accept: '.sql,.txt', style: 'display:none', ...tid('merge-file') }) as HTMLInputElement;
    fileIn.addEventListener('change', (e) => {
      const f = (e.target as HTMLInputElement).files?.[0]; if (!f) return;
      const rd = new FileReader(); rd.onload = () => void mergeText(String(rd.result)); rd.readAsText(f);
      (e.target as HTMLInputElement).value = '';
    });
    const bar = el('div', { class: 'bar' });
    bar.append(
      el('label', { class: 'btn primary' }, ['⤒ Open changeset file & merge', fileIn]),
      el('button', { ...tid('import-diff'), onclick: () => void mergeText(inp.value) }, 'Merge pasted text'),
    );
    p.append(inp, bar, el('div', { class: 'synced', ...tid('sync-status') }, lastSync));
    return p;
  };

  /* ---- render ------------------------------------------------------------*/
  const render = async (): Promise<void> => {
    root.innerHTML = '';
    const role = await dev.myRole();
    const badge = document.querySelector('#role-badge') as HTMLElement;
    badge.textContent = dev.session ? `${dev.session.name} — ${role ?? 'no db'}` : 'logged out';
    badge.className = 'role ' + (role ? 'r-' + role : 'r-none');
    badge.setAttribute('data-testid', 'role');

    if (!dev.session) { root.append(loginForm()); return; }
    hasDb = role !== null;

    const bar = el('div', { class: 'bar' });
    bar.append(el('button', { ...tid('logout'), onclick: async () => { dev.logout(); await render(); } }, 'Log out'));
    // Any user can export their identity card (public key) to hand to an admin.
    const cardOut = el('textarea', { class: 'diff', readonly: 'true', ...tid('card-out'), style: 'display:none' }) as HTMLTextAreaElement;
    bar.append(el('button', {
      ...tid('export-card'),
      onclick: async () => {
        const card = JSON.stringify(await dev.exportIdentityCard());
        cardOut.value = card; cardOut.style.display = ''; cardOut.focus(); cardOut.select();
        try { await navigator.clipboard.writeText(card); } catch { /* clipboard blocked in iframe */ }
        toast('identity card exported (copied)');
      },
    }, 'Export my identity card'));
    // Re-key: migrate the keystore to a new file under a new passphrase (same
    // identity, so all grants/data still apply).
    const newPass = el('input', { type: 'password', ...tid('rekey-pass'), placeholder: 'new passphrase', style: 'width:120px' }) as HTMLInputElement;
    bar.append(newPass, el('button', {
      ...tid('rekey-btn'),
      onclick: async () => {
        if (!newPass.value) { toast('enter a new passphrase', true); return; }
        const blob = await dev.exportKeystore(newPass.value); // fresh salt/iv, same identity
        downloadKeystore(blob, dev.session!.name);
        newPass.value = '';
        toast('re-keyed — new keystore downloaded');
      },
    }, 'Re-key keystore'));
    if (!hasDb) bar.append(el('button', {
      class: 'primary', ...tid('genesis'),
      onclick: async () => { await dev.genesis(); await seedNotes(dev); toast('genesis db created (you are admin)'); await render(); },
    }, 'Create genesis DB'));
    root.append(bar, cardOut);

    if (!hasDb) {
      root.append(el('div', { class: 'hint' }, 'No database yet — create a genesis DB, share your identity card with an admin, or import a changeset to join.'));
      root.append(await syncPanel());
      return;
    }
    if (await dev.isAdmin()) root.append(await adminPanel());
    root.append(await notesPanel());
    root.append(await syncPanel());
  };

  void render();
};
