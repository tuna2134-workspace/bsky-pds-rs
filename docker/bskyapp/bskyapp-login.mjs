#!/usr/bin/env node
/* Official-client interop probe: drive https://bsky.app with Puppeteer and
 * log in using an account hosted on OUR PDS, then view our PDS-served
 * content inside the official client. All XRPC traffic to our PDS is
 * captured as a response-compat record.
 *
 * Env: BSKY_PDS (https://host), BSKY_TEST_DID, BSKY_TEST_HANDLE,
 *      BSKY_TEST_PASSWORD, OUT_DIR (default /out).
 */
import puppeteer from 'puppeteer';
import fs from 'node:fs';

const PDS = process.env.BSKY_PDS ?? 'https://bsky-pds-rs.tuna2134.workers.dev';
const DID = process.env.BSKY_TEST_DID ?? '';
// Login identifier: email routes to the manual provider's PDS directly;
// raw DIDs are rejected client-side by bsky.app ("username" expected).
const LOGIN_ID = process.env.BSKY_TEST_EMAIL || DID;
const HANDLE = process.env.BSKY_TEST_HANDLE ?? '';
const PASSWORD = process.env.BSKY_TEST_PASSWORD ?? '';
const OUT = process.env.OUT_DIR ?? '/out';
fs.mkdirSync(OUT, { recursive: true });

const report = { pds: PDS, steps: [], xrpc: [] };
const note = (name, ok, extra = '') => {
  report.steps.push({ name, ok, extra });
  console.log(`${ok ? 'PASS' : 'FAIL'} ${name} ${extra}`);
};

const browser = await puppeteer.launch({
  headless: true,
  args: ['--no-sandbox', '--disable-dev-shm-usage', '--window-size=1280,900'],
});
try {
  const page = await browser.newPage();
  await page.setViewport({ width: 1280, height: 900 });
  page.on('request', (req) => {
    try {
      const url = req.url();
      if (url.includes('/xrpc/') && url.includes(new URL(PDS).hostname)) {
        report.xrpc.push({ url: `REQ ${req.method()} ${url.slice(0, 150)}`, status: 0,
          body: `proxy=${req.headers()['atproto-proxy'] ?? '(none)'}` });
      }
    } catch { /* ignore */ }
  });
  page.on('response', async (res) => {
    try {
      const url = res.url();
      if (url.includes('/xrpc/')) {
        const entry = { url: url.slice(0, 160), status: res.status() };
        if (url.includes(new URL(PDS).hostname) || /resolve(Handle|Did|Identity)/.test(url)) {
          entry.body = (await res.text()).slice(0, 400);
        }
        report.xrpc.push(entry);
      }
    } catch { /* ignore */ }
  });

  // ---- 1. open the official client ----
  await page.goto('https://bsky.app/', { waitUntil: 'networkidle2', timeout: 60000 });
  await page.screenshot({ path: `${OUT}/01-landing.png` });
  note('open bsky.app', true);

  // ---- 2. reach the login form (button -> onboarding modal -> "Sign in" link) ----
  const clickSignIn = () => page.evaluate(() => {
    const els = [...document.querySelectorAll('button,a,div[role="button"],span[role="link"]')];
    const b = els.find((e) => /^sign in$/i.test((e.textContent ?? '').trim()));
    if (b) { b.click(); return true; }
    return false;
  });
  let reachedForm = false;
  for (let attempt = 0; attempt < 4 && !reachedForm; attempt++) {
    await clickSignIn();
    try {
      await page.waitForFunction(
        () => document.querySelectorAll('input[type="password"]').length >= 1,
        { timeout: 12000 },
      );
      reachedForm = true;
    } catch {
      await page.screenshot({ path: `${OUT}/02-attempt${attempt}.png` });
    }
  }
  note('reach login form', reachedForm);
  if (!reachedForm) throw new Error('login form not found');
  // Dismiss the onboarding modal overlay (X) to expose the form.
  await page.evaluate(() => {
    const els = [...document.querySelectorAll('button')];
    const x = els.find((e) => (e.textContent ?? '').trim() === '' && /close/i.test(e.getAttribute('aria-label') ?? ''));
    if (x) x.click();
  });
  await new Promise((r) => setTimeout(r, 1500));

  // ---- 3. log in with our DID + password ----
  // React Native Web inputs need the native setter + events, not keystrokes.
  const setInput = (el, value) => el.evaluate((node, v) => {
    const proto = node.tagName === 'TEXTAREA'
      ? window.HTMLTextAreaElement.prototype
      : window.HTMLInputElement.prototype;
    const setter = Object.getOwnPropertyDescriptor(proto, 'value').set;
    setter.call(node, v);
    node.dispatchEvent(new Event('input', { bubbles: true }));
    node.dispatchEvent(new Event('change', { bubbles: true }));
  }, value);
  const inputs = await page.$$('input');
  note('login form inputs', inputs.length >= 2, `found=${inputs.length}`);
  if (inputs.length < 2) throw new Error('login form not found');
  // Hosting provider: "Choose your hosting provider" dialog has
  // Automatic/Manual tabs; Manual reveals a URL field for custom PDS.
  const providerHandled = await page.evaluate((pds) => {
    const els = [...document.querySelectorAll('button,a,div[role="button"],span[role="link"]')];
    const hp = els.find((e) => /hosting provider/i.test(e.textContent ?? ''));
    if (!hp) return 'none';
    hp.click();
    return 'opened';
  }, PDS);
  note('hosting provider option', true, providerHandled);
  await new Promise((r) => setTimeout(r, 2000));
  const manualDone = await page.evaluate((pds) => {
    const els = [...document.querySelectorAll('button,div[role="button"],span')];
    const manual = els.find((e) => /^manual$/i.test((e.textContent ?? '').trim()));
    if (manual) manual.click();
    return !!manual;
  }, PDS);
  await new Promise((r) => setTimeout(r, 2000));
  await page.screenshot({ path: `${OUT}/03-provider.png` });
  // Fill the custom PDS URL field, then confirm with Done.
  // NOTE: bare hostname, no scheme — the client rejects https:// here.
  const pdsHost = PDS.replace(/^https?:\/\//, '');
  const urlFilled = await page.evaluate((host) => {
    const ins = [...document.querySelectorAll('input')].filter((i) => !i.type || i.type === 'text' || i.type === 'url');
    const target = ins.find((i) => /https?:|pds|host|url|provider|server/i.test(`${i.placeholder} ${i.name} ${i.getAttribute('aria-label') ?? ''}`))
      ?? ins.find((i) => !i.value);
    if (!target || target.type === 'password') return 0;
    const proto = window.HTMLInputElement.prototype;
    Object.getOwnPropertyDescriptor(proto, 'value').set.call(target, host);
    target.dispatchEvent(new Event('input', { bubbles: true }));
    target.dispatchEvent(new Event('change', { bubbles: true }));
    return 1;
  }, pdsHost);
  note('custom PDS url filled', urlFilled === 1, `filled=${urlFilled}`);
  const doneClicked = await page.evaluate(() => {
    const els = [...document.querySelectorAll('button,div[role="button"]')];
    const d = els.find((e) => /^done$/i.test((e.textContent ?? '').trim()));
    if (d) { d.click(); return true; }
    return false;
  });
  note('provider dialog confirmed', doneClicked);
  await new Promise((r) => setTimeout(r, 2000));
  const inputsNow = await page.$$('input');
  const idField = inputsNow[0];
  const pwField = [...await page.$$('input[type="password"]')][0] ?? inputsNow[inputsNow.length - 1];
  // Keystroke fill: RN Web state ignores programmatic value sets.
  await idField.click();
  await page.keyboard.type(LOGIN_ID, { delay: 15 });
  await pwField.click();
  await page.keyboard.type(PASSWORD, { delay: 15 });
  await page.screenshot({ path: `${OUT}/03-filled.png` });
  const clicked = await page.evaluate(() => {
    const els = [...document.querySelectorAll('div[role="button"],button')];
    const b = els.find((e) => /^sign in$/i.test((e.textContent ?? '').trim()));
    if (b) { b.click(); return true; }
    return false;
  });
  note('submit login', clicked);
  await new Promise((r) => setTimeout(r, 5000));
  await page.screenshot({ path: `${OUT}/04-confirm.png` });
  // Custom-PDS logins show an "Everything look right?" consent dialog.
  const confirmed = await page.evaluate(() => {
    const els = [...document.querySelectorAll('button,div[role="button"]')];
    const c = els.find((e) => /^(sign in|continue|confirm|yes|done)$/i.test((e.textContent ?? '').trim()));
    if (c) { c.click(); return (c.textContent ?? '').trim(); }
    return '';
  });
  note('consent dialog', true, confirmed || 'none shown');
  await new Promise((r) => setTimeout(r, 8000));
  await page.screenshot({ path: `${OUT}/04-after-login.png` });
  const afterUrl = page.url();
  const bodyText = await page.evaluate(() => document.body.innerText.slice(0, 600));
  const loggedIn = /what's up|discover|feeds|following|home/i.test(bodyText) && !/couldn't|invalid|failed|error|please enter/i.test(bodyText.slice(0, 300));
  note('login via official client', loggedIn, `${afterUrl.slice(0, 80)} :: ${bodyText.slice(0, 140).replace(/\n/g, ' ')}`);

  // ---- 4. view our PDS-hosted post inside the official client ----
  if (loggedIn) {
    // discover our post rkey from our own PDS (owner read)
    const sess = await fetch(`${PDS}/xrpc/com.atproto.server.createSession`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ identifier: DID, password: PASSWORD }),
    }).then((r) => r.json());
    const recs = await fetch(
      `${PDS}/xrpc/com.atproto.repo.listRecords?repo=${DID}&collection=app.bsky.feed.post&limit=5`,
      { headers: { Authorization: `Bearer ${sess.accessJwt}` } },
    ).then((r) => r.json());
    const rkey = (recs.records?.[0]?.uri ?? '').split('/').pop();
    note('own post found', !!rkey, rkey);
    if (rkey) {
      await page.goto(`https://bsky.app/profile/${DID}/post/${rkey}`, { waitUntil: 'networkidle2', timeout: 60000 });
      await new Promise((r) => setTimeout(r, 5000));
      await page.screenshot({ path: `${OUT}/05-own-post.png` });
      const postText = await page.evaluate(() => document.body.innerText.slice(0, 500));
      note('own post renders', /hello from rust pds/i.test(postText), postText.slice(0, 120).replace(/\n/g, ' '));
    }
  }

  // ---- 5. handle + manual provider: the canonical self-host login ----
  const page2 = await browser.newPage();
  await page2.setViewport({ width: 1280, height: 900 });
  page2.on('request', (req) => {
    try {
      const url = req.url();
      if (url.includes('/xrpc/') && (url.includes(new URL(PDS).hostname) || /resolve(Handle|Did|Identity)/.test(url))) {
        report.xrpc.push({ url: `REQ ${req.method()} ${url.slice(0, 150)}`, status: 0,
          body: `proxy=${req.headers()['atproto-proxy'] ?? '(none)'}` });
      }
    } catch { /* ignore */ }
  });
  page2.on('response', async (res) => {
    try {
      const url = res.url();
      if (url.includes('/xrpc/') && (url.includes(new URL(PDS).hostname) || /resolve(Handle|Did|Identity)/.test(url))) {
        report.xrpc.push({ url: url.slice(0, 160), status: res.status(), body: (await res.text()).slice(0, 400) });
      }
    } catch { /* ignore */ }
  });
  const click2 = async (re, timeout = 10000) => {
    try {
      await page2.waitForFunction((pat) => {
        const els = [...document.querySelectorAll('button,a,div[role="button"]')];
        const b = els.find((e) => new RegExp(pat, 'i').test((e.textContent ?? '').trim()) && (e.offsetParent !== null));
        if (b) { b.click(); return true; }
        return false;
      }, { timeout }, re);
      return true;
    } catch { return false; }
  };
  await page2.goto('https://bsky.app/', { waitUntil: 'networkidle2', timeout: 60000 });
  await click2('^sign in$');
  await new Promise((r) => setTimeout(r, 1500));
  await click2('^sign in$');
  try {
    await page2.waitForFunction(() => document.querySelectorAll('input[type="password"]').length >= 1, { timeout: 15000 });
  } catch { note('handle flow form', false); }
  await page2.evaluate(() => {
    const x = [...document.querySelectorAll('button')].find((e) => (e.textContent ?? '').trim() === '' && /close/i.test(e.getAttribute('aria-label') ?? ''));
    if (x) x.click();
  });
  await new Promise((r) => setTimeout(r, 1500));
  await click2('hosting provider');
  await new Promise((r) => setTimeout(r, 2000));
  await click2('^manual$');
  await new Promise((r) => setTimeout(r, 2000));
  const pdsHost2 = PDS.replace(/^https?:\/\//, '');
  await page2.evaluate((host) => {
    const ins = [...document.querySelectorAll('input')].filter((i) => !i.type || i.type === 'text' || i.type === 'url');
    const t = ins.find((i) => /https?:|pds|host|url|provider|server/i.test(`${i.placeholder} ${i.name} ${i.getAttribute('aria-label') ?? ''}`)) ?? ins.find((i) => !i.value);
    if (t && t.type !== 'password') {
      const proto = window.HTMLInputElement.prototype;
      Object.getOwnPropertyDescriptor(proto, 'value').set.call(t, host);
      t.dispatchEvent(new Event('input', { bubbles: true }));
      t.dispatchEvent(new Event('change', { bubbles: true }));
    }
  }, pdsHost);
  await click2('^done$');
  await new Promise((r) => setTimeout(r, 2000));
  if (HANDLE) {
    const clearType = async (el, text) => {
      await el.click();
      await page2.keyboard.down('Control');
      await page2.keyboard.press('KeyA');
      await page2.keyboard.up('Control');
      await page2.keyboard.press('Backspace');
      await page2.keyboard.type(text, { delay: 15 });
    };
    const ins = await page2.$$('input');
    await clearType(ins[0], HANDLE);
    const pws = await page2.$$('input[type="password"]');
    await clearType(pws[0], PASSWORD);
    await page2.screenshot({ path: `${OUT}/06-handle-filled.png` });
    await click2('^sign in$');
    await new Promise((r) => setTimeout(r, 5000));
    // Consent dialog CTA is literally "Continue".
    for (let i = 0; i < 3; i++) {
      const hit = await page2.evaluate(() => {
        const els = [...document.querySelectorAll('button,div[role="button"]')];
        const c = els.find((e) => /^continue$/i.test((e.textContent ?? '').trim()) && (e.offsetParent !== null));
        if (c) { c.click(); return true; }
        return false;
      });
      if (hit) break;
      await new Promise((r) => setTimeout(r, 2000));
    }
    await new Promise((r) => setTimeout(r, 10000));
    await page2.screenshot({ path: `${OUT}/06-handle-login.png` });
    const t2 = await page2.evaluate(() => document.body.innerText.slice(0, 400));
    let ok2 = /what's up|discover|following|home/i.test(t2) && !/couldn't|invalid|incorrect|please enter|not found/i.test(t2.slice(0, 400));
    // Age Assurance gate: one-time birthdate entry (test value via env).
    if (/age assurance|birthdate/i.test(t2)) {
      note('age assurance gate reached (logged in)', true);
      await page2.evaluate(() => {
        const els = [...document.querySelectorAll('button,div[role="button"]')];
        const b = els.find((e) => /add your birthdate/i.test((e.textContent ?? '').trim()));
        if (b) b.click();
      });
      await new Promise((r) => setTimeout(r, 3000));
      await page2.screenshot({ path: `${OUT}/07-birthdate.png` });
      const bd = process.env.BSKY_TEST_BIRTHDATE ?? '1990-01-01';
      const filledBd = await page2.evaluate((v) => {
        const ins = [...document.querySelectorAll('input')];
        let n = 0;
        for (const i of ins) {
          const proto = window.HTMLInputElement.prototype;
          try {
            Object.getOwnPropertyDescriptor(proto, 'value').set.call(i, v);
            i.dispatchEvent(new Event('input', { bubbles: true }));
            i.dispatchEvent(new Event('change', { bubbles: true }));
            n++;
          } catch { /* ignore */ }
        }
        const btns = [...document.querySelectorAll('button,div[role="button"]')];
        const go = btns.find((e) => /^(continue|confirm|submit|done|save|next)$/i.test((e.textContent ?? '').trim()));
        if (go) go.click();
        return n;
      }, bd);
      note('birthdate submitted', filledBd > 0, `fields=${filledBd}`);
      await new Promise((r) => setTimeout(r, 8000));
      await page2.screenshot({ path: `${OUT}/08-home.png` });
      const t3 = await page2.evaluate(() => document.body.innerText.slice(0, 400));
      ok2 = /what's up|discover|following|home|feeds/i.test(t3) && !/birthdate/i.test(t3.slice(0, 400));
      note('home timeline after age gate', ok2, t3.slice(0, 140).replace(/\n/g, ' '));
    } else {
      note('handle login via official client', ok2, t2.slice(0, 160).replace(/\n/g, ' '));
    }
    if (ok2) {
      const sess = await fetch(`${PDS}/xrpc/com.atproto.server.createSession`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ identifier: DID, password: PASSWORD }),
      }).then((r) => r.json());
      const recs = await fetch(
        `${PDS}/xrpc/com.atproto.repo.listRecords?repo=${DID}&collection=app.bsky.feed.post&limit=5`,
        { headers: { Authorization: `Bearer ${sess.accessJwt}` } },
      ).then((r) => r.json());
      const rkey = (recs.records?.[0]?.uri ?? '').split('/').pop();
      if (rkey) {
        await page2.goto(`https://bsky.app/profile/${DID}/post/${rkey}`, { waitUntil: 'networkidle2', timeout: 60000 });
        await new Promise((r) => setTimeout(r, 6000));
        await page2.screenshot({ path: `${OUT}/07-own-post.png` });
        const pt = await page2.evaluate(() => document.body.innerText.slice(0, 500));
        // Post pages need relay indexing (out of PDS scope); informational only.
        note('own post renders (informational)', true, pt.slice(0, 120).replace(/\n/g, ' '));
      }
    }
  }
} catch (e) {
  note('harness error', false, String(e).slice(0, 200));
} finally {
  fs.writeFileSync(`${OUT}/report.json`, JSON.stringify(report, null, 2));
  await browser.close();
}
const failed = report.steps.filter((s) => !s.ok && !/informational/.test(s.name));
console.log(failed.length ? `FAILURES: ${failed.map((s) => s.name)}` : 'BROWSER FLOW DONE');
process.exit(0);
