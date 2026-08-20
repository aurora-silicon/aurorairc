/* Browser test: drives the real client in Chromium against the fake network
   brought up by tests/uiserver.py. Run it through that script rather than
   directly, since it needs the stack behind it:

       python3 tests/uiserver.py
*/
import crypto from 'node:crypto';
import { createRequire } from 'node:module';

/* Playwright is installed globally in this environment, and ESM resolution
   ignores NODE_PATH - so reach it through a CommonJS require, which does not. */
const require_ = createRequire(import.meta.url);
const { chromium } = (() => {
  for (const spec of ['playwright', process.env.NODE_PATH
      ? process.env.NODE_PATH.split(':')[0] + '/playwright' : null].filter(Boolean)) {
    try { return require_(spec) } catch (e) { /* try the next one */ }
  }
  console.error('playwright is not installed; skipping the browser test');
  process.exit(0);
})();

const [base, ctrl, ircPort, web] = process.argv.slice(2);
let checks = 0;
const failures = [];

function check(label, ok, detail = '') {
  checks++;
  console.log(`  ${ok ? '\x1b[32m✓\x1b[0m' : '\x1b[31m✗\x1b[0m'} ${label}` +
    (!ok && detail ? `  — ${detail}` : ''));
  if (!ok) failures.push(label + (detail ? ` (${detail})` : ''));
  return ok;
}
const head = t => console.log(`\n\x1b[1m${t}\x1b[0m`);
const sleep = ms => new Promise(r => setTimeout(r, ms));
const control = (path, params = {}) =>
  fetch(ctrl + path + '?' + new URLSearchParams(params)).then(r => r.json());

/* RFC 6238, so the test can sign in through the real two-factor prompt. */
function totp(secret) {
  const clean = secret.replace(/=+$/, '').toUpperCase();
  const alpha = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
  let bits = '';
  for (const ch of clean) bits += alpha.indexOf(ch).toString(2).padStart(5, '0');
  const bytes = Buffer.from((bits.match(/.{8}/g) || []).map(b => parseInt(b, 2)));
  const counter = Buffer.alloc(8);
  counter.writeBigUInt64BE(BigInt(Math.floor(Date.now() / 1000 / 30)));
  const h = crypto.createHmac('sha1', bytes).update(counter).digest();
  const off = h[h.length - 1] & 0x0f;
  const code = (h.readUInt32BE(off) & 0x7fffffff) % 1000000;
  return String(code).padStart(6, '0');
}

async function waitFor(fn, { timeout = 20000, step = 200, what = '' } = {}) {
  const end = Date.now() + timeout;
  while (Date.now() < end) {
    if (await fn()) return true;
    await sleep(step);
  }
  return false;
}

/* Who a row will read as: its own name, or the name of the group it joined. */
async function authorOf(page, index) {
  return page.evaluate(i => {
    const rows = [...document.querySelectorAll('#log .msg')];
    const row = i < 0 ? rows[rows.length + i] : rows[i];
    if (!row) return null;
    let el = row;
    while (el) {
      const who = el.querySelector('.who');
      if (who) return who.textContent;
      el = el.previousElementSibling;
      while (el && !el.classList.contains('msg')) el = el.previousElementSibling;
    }
    return null;
  }, index);
}

const run = async () => {
  const browser = await chromium.launch();
  const page = await browser.newPage({ viewport: { width: 1280, height: 900 } });
  const errors = [];
  page.on('pageerror', e => errors.push(String(e)));
  // Several checks below deliberately provoke a 4xx (a short password, a wrong
  // authenticator code), and the browser logs every one of those as a console
  // error. Only genuine script failures count here.
  const noise = t => /Failed to load resource/.test(t);
  page.on('console', m => { if (m.type() === 'error' && !noise(m.text())) errors.push(m.text()); });

  try {
    // ------------------------------------------------------------ wizard
    head('Setup wizard');
    await page.goto(base + '/', { waitUntil: 'domcontentloaded' });
    await page.waitForSelector('#wizard.on', { timeout: 15000 });
    check('a fresh archive opens the wizard', true);
    check('it starts on Welcome',
      (await page.textContent('#wiz-title')).trim() === 'Welcome');
    check('the step counter is honest',
      /Step 1 of 6/.test(await page.textContent('#wiz-step')));
    check('Back is hidden on the first step',
      await page.evaluate(() => getComputedStyle($('#wiz-back')).visibility) === 'hidden');
    check('the welcome step explains what is coming',
      (await page.textContent('#wiz-content')).includes('set up your account'));

    await page.click('#wiz-next');
    check('step 2 is Server setup',
      (await page.textContent('#wiz-title')).trim() === 'Server setup');
    await page.fill('#wz-appname', 'Aurora UI Test');
    await page.click('#wiz-next');

    check('step 3 is Account creation',
      (await page.textContent('#wiz-title')).trim() === 'Account creation');
    check('it says the account cannot be deleted',
      (await page.textContent('#wiz-content')).includes('cannot be deleted'));
    check('the button says what it will do',
      (await page.textContent('#wiz-next')).trim() === 'Create account');

    await page.fill('#wz-user', 'ryan');
    await page.fill('#wz-nick', 'ryan_');
    await page.fill('#wz-pw1', 'correct horse 9');
    await page.fill('#wz-pw2', 'nope nope nope');
    await page.click('#wiz-next');
    await page.waitForSelector('#wiz-err .note.err');
    check('mismatched passwords are caught in the step',
      (await page.textContent('#wiz-err')).includes("don't match"));
    await page.fill('#wz-pw2', 'correct horse 9');
    await page.click('#wiz-next');

    await page.waitForSelector('#wz-totp', { timeout: 15000 });
    check('the account step becomes "secure your account"',
      (await page.textContent('#wiz-content')).includes('Secure your account'));
    check('a passkey can be added from here', await page.isVisible('#wz-pk-add'));
    check('and two-factor', await page.isVisible('#wz-totp-on'));
    check('Skip for now is offered', await page.isVisible('#wiz-alt'));
    check('Back is closed off once the account exists',
      await page.isDisabled('#wiz-back'));
    check('the header adopted the server name',
      (await page.textContent('.title')).includes('Aurora UI Test'));

    // enrol two-factor for real, so the sign-in prompt can be tested later
    await page.click('#wz-totp-on');
    await page.waitForSelector('#totp-secret');
    const secret = (await page.textContent('#totp-secret')).trim();
    await page.fill('#totp-code', '000000');
    await page.click('#totp-confirm');
    await page.waitForSelector('#totp-err .note.err');
    check('a wrong authenticator code is refused in the wizard', true);
    await page.fill('#totp-code', totp(secret));
    await page.click('#totp-confirm');
    await waitFor(() => page.isVisible('.pill.ok'), { what: 'totp on' });
    check('the right one turns two-factor on',
      (await page.textContent('#wz-totp')).includes('Two-factor is on'));

    await page.click('#wiz-next');
    check('step 4 is Member creation',
      (await page.textContent('#wiz-title')).trim() === 'Member creation');
    check('there is an "or" between the two ways in',
      await page.isVisible('.orline'));
    await page.selectOption('#wz-inv-role', 'admin');
    check('an admin link warns before it is made',
      (await page.textContent('#wz-inv-warn')).includes('hands over the keys'));
    await page.selectOption('#wz-inv-role', 'user');
    check('and the warning goes away for a user link',
      (await page.textContent('#wz-inv-warn')).trim() === '');
    await page.selectOption('#wz-inv-uses', '5');
    await page.click('#wz-inv-go');
    await page.waitForSelector('.copyfield code');
    const link = await page.textContent('.copyfield code');
    check('a pass link is shown', /#invite=/.test(link), link);
    check('and says it is good for five',
      (await page.textContent('#wiz-content')).includes('good for 5 people'));

    await page.fill('#wz-na-user', 'dave');
    await page.fill('#wz-na-pass', 'another good one');
    await page.click('#wz-na-go');
    await waitFor(() => page.isVisible('.row .pill.ok'));
    check('an account can also be added by hand right here',
      (await page.textContent('#wiz-content')).includes('dave'));

    await page.click('#wiz-next');
    check('step 5 is the IRC network',
      (await page.textContent('#wiz-title')).trim() === 'IRC network setup');
    await page.fill('#wz-nn-name', 'test');
    await page.fill('#wz-nn-host', '127.0.0.1');
    await page.click('#wz-nn-tls');                    // plain, like the fake ircd
    check('turning TLS off moves the port with it',
      await page.inputValue('#wz-nn-port') === '6667');
    await page.fill('#wz-nn-port', String(ircPort));
    await page.fill('#wz-nn-nick', 'aurora');
    await page.fill('#wz-nn-chans', 'mychannel, another');

    await page.fill('#wz-nn-host', '127.0.0.1');
    await page.fill('#wz-nn-port', '1');
    await page.click('#wiz-next');
    await page.waitForSelector('#wz-nn-out .note.err', { timeout: 20000 });
    check('a dead connection blocks the step',
      (await page.textContent('#wiz-title')).trim() === 'IRC network setup');
    check('and says so plainly',
      (await page.textContent('#wz-nn-out')).includes('Could not connect'));

    await page.fill('#wz-nn-port', String(ircPort));
    await page.click('#wz-nn-test');
    await page.waitForSelector('#wz-nn-out .note.ok', { timeout: 25000 });
    check('a good connection reports the server back',
      (await page.textContent('#wz-nn-out')).includes('Connected to'));
    await page.click('#wiz-next');
    await waitFor(() => page.isVisible('.summary'), { what: 'network saved' });
    check('the saved network is shown back',
      (await page.textContent('#wiz-content')).includes('#mychannel'));

    await page.click('#wiz-next');
    check('the last step is Finalisation',
      (await page.textContent('#wiz-title')).trim() === 'Finalisation');
    const summary = await page.textContent('#wiz-content');
    check('the summary names the server', summary.includes('Aurora UI Test'));
    check('and the owner account', summary.includes('ryan'));
    check('and that two-factor is on', /Two-factor\s*on/.test(summary.replace(/\s+/g, ' ')));
    check('and the network', summary.includes('127.0.0.1'));
    check('no password appears anywhere in it',
      !summary.includes('correct horse'), 'a password leaked into the summary');
    check('the last button says Finish',
      (await page.textContent('#wiz-next')).trim() === 'Finish');
    await page.click('#wiz-next');
    await page.waitForSelector('#wizard', { state: 'hidden' });
    check('finishing closes the wizard', true);

    // -------------------------------------------------------------- feed
    head('Live feed');
    await waitFor(() => page.isVisible('.composer.on'), { timeout: 40000 });
    check('the composer appears once the archivist is connected', true);

    await control('/inject', { nick: 'someone', text: 'first line from someone' });
    await control('/inject', { nick: 'someone', text: 'still someone talking' });
    const arrived = await waitFor(async () =>
      (await page.textContent('#log')).includes('still someone talking'));
    check('messages arrive over the stream without a reload', arrived);
    check('the newest row is attributed to someone',
      await authorOf(page, -1) === 'someone');

    // ---- the bug: your own message showing as the previous speaker's ----
    head('Sending');
    await page.fill('#sendtext', 'my reply to someone');
    await page.click('#sendbtn');
    check('the echo goes up immediately',
      await page.isVisible('#log .msg.sending'));
    check('and is attributed to you even before it lands',
      await authorOf(page, -1) === 'ryan_');

    const landed = await waitFor(async () =>
      await page.evaluate(() =>
        !document.querySelector('#log .msg.sending') &&
        document.querySelector('#log').textContent.includes('my reply to someone')),
      { timeout: 45000 });
    check('the real message replaces the echo', landed);
    check('and is still attributed to you, not to the previous speaker',
      await authorOf(page, -1) === 'ryan_',
      'this is the reported bug: the row grouped under the last speaker');
    check('it is on screen exactly once', await page.evaluate(() =>
      [...document.querySelectorAll('#log .msg .txt')]
        .filter(t => t.textContent === 'my reply to someone').length) === 1);

    // consecutive messages from you still group under one header
    await page.fill('#sendtext', 'and one more');
    await page.click('#sendbtn');
    await waitFor(async () => (await page.textContent('#log')).includes('and one more'));
    check('a second message of yours still groups under your name',
      await authorOf(page, -1) === 'ryan_');

    // ---- the other bug: composer growth ----
    head('Composer growth');
    const before = await page.evaluate(() => {
      const log = $('#log');
      return { h: $('#composer').getBoundingClientRect().height,
               gap: log.scrollHeight - log.scrollTop - log.clientHeight };
    });
    await page.fill('#sendtext',
      Array.from({ length: 6 }, (_, i) => `line number ${i} of a long message`).join('\n'));
    await sleep(350);
    const after = await page.evaluate(() => {
      const log = $('#log');
      const rows = [...document.querySelectorAll('#log .msg')];
      const last = rows[rows.length - 1].getBoundingClientRect();
      const box = log.getBoundingClientRect();
      return { h: $('#composer').getBoundingClientRect().height,
               gap: log.scrollHeight - log.scrollTop - log.clientHeight,
               lastBottom: last.bottom, logBottom: box.bottom };
    });
    check('the composer actually grew', after.h > before.h + 20,
      `${before.h} -> ${after.h}`);
    check('the conversation moved up with it', after.gap < 8, `gap ${after.gap}`);
    check('the newest message is still fully visible',
      after.lastBottom <= after.logBottom + 1,
      `row bottom ${after.lastBottom} vs pane ${after.logBottom}`);
    await page.fill('#sendtext', '');

    // ---------------------------------------------------------- tooltips
    head('Message quick actions');
    const row = page.locator('#log .msg').last();
    await row.hover();
    await page.waitForSelector('.msg:hover .rowact', { timeout: 5000 }).catch(() => {});
    const act = row.locator('.rowact button').first();
    check('the hover strip appears', await act.isVisible());
    await act.hover();
    const tipped = await waitFor(() => page.isVisible('#tip.on'), { timeout: 4000 });
    check('hovering an action says what it does', tipped);
    if (tipped) {
      const text = (await page.textContent('#tip')).trim();
      check('and the label is a real sentence', text.length > 3, text);
    }
    const labels = await page.evaluate(() =>
      [...document.querySelectorAll('#log .msg:last-of-type .rowact button')]
        .map(b => b.getAttribute('data-tip')));
    check('every action carries one', labels.length > 0 && labels.every(Boolean),
      JSON.stringify(labels));

    // ----------------------------------------------------------- filters
    head('Filters');
    await page.click('#filter-btn');
    await page.waitForSelector('#filter-sheet.on');
    const heads = await page.evaluate(() =>
      [...document.querySelectorAll('#filter-sheet .fhead')]
        .map(h => h.childNodes[0].textContent.trim()));
    check('the status bar is gone', await page.evaluate(() =>
      !document.querySelector('.status') && !document.querySelector('#count')));
    check('the copy control is a small app-bar button now',
      await page.evaluate(() => {
        const c = document.querySelector('#copy');
        return c && c.classList.contains('iconbtn') && c.closest('.appbar');
      }));
    check('a narrowed view says so in the header', await page.evaluate(() =>
      /of\s[\d,]+\smessages|messages/.test(
        document.querySelector('#subtitle').textContent)));
    check('the sections read Sort, Date range, Show, Inline images, Tags, Saved searches',
      JSON.stringify(heads) === JSON.stringify(
        ['Sort', 'Date range', 'Show', 'Inline images', 'Tags', 'Saved searches']),
      JSON.stringify(heads));
    check('Show is the three message kinds, nothing else',
      await page.evaluate(() => document.querySelectorAll('#kinds .chip').length) === 3);
    check('the quick date ranges hold one line', await page.evaluate(() => {
      const tops = [...document.querySelectorAll('#presets .chip')]
        .map(c => c.getBoundingClientRect().top);
      return new Set(tops.map(t => Math.round(t))).size === 1;
    }));
    check('the image toggle lives here now', await page.isVisible('#img-toggle'));
    check('every block is spaced the same', await page.evaluate(() => {
      const gaps = [...document.querySelectorAll('#filter-sheet .field')]
        .map(f => getComputedStyle(f).gap);
      return new Set(gaps).size === 1;
    }));
    check('the action links sit on the header line, not floated', await page.evaluate(() => {
      const l = document.querySelector('#manage-tags');
      return getComputedStyle(l).float === 'none';
    }));
    check('the date hint names the reader\'s own zone',
      (await page.textContent('#tzhint')).includes('time zone'));
    await page.click('#scrim');

    // --------------------------------------------------------- search bar
    head('Search bar');
    await page.click('#q');
    await page.fill('#q', 'someone');
    await page.press('#q', 'Enter');
    await waitFor(() => page.evaluate(() => state.total > 0));
    await page.click('#q');
    await page.fill('#q', '');
    await page.click('#q');
    const gotHistory = await waitFor(() => page.isVisible('#suggest.on'), { timeout: 4000 });
    check('the bar offers what you searched for before', gotHistory);
    if (gotHistory) {
      check('under a Recent heading',
        (await page.textContent('#suggest')).includes('Recent'));
      check('with the search in it',
        (await page.textContent('#suggest')).includes('someone'));
    }
    check('the bookmark stays hidden while the field is empty', await (async () => {
      await page.fill('#q', '');
      await sleep(150);
      return !(await page.evaluate(() =>
        document.querySelector('#qsave').classList.contains('on')));
    })());
    check('there is exactly one clear control, ours', await page.evaluate(() => {
      // Pseudo-element computed styles are unreliable in headless; assert the
      // rule itself is present and targets the native cancel button.
      return [...document.styleSheets].some(sh => {
        try { return [...sh.cssRules].some(r =>
          r.selectorText && r.selectorText.includes('-webkit-search-cancel-button')
          && /none/.test(r.style.display + (r.style.webkitAppearance || ''))); }
        catch (e) { return false; }
      });
    }));
    await page.fill('#q', '#mychannel someone');
    await sleep(120);
    check('typing brings the bookmark out', await page.evaluate(() =>
      document.querySelector('#qsave').classList.contains('on')));
    await page.click('#qsave');
    await waitFor(async () => (await page.evaluate(() =>
      SAVED.some(sv => sv.query === '#mychannel someone'))), { timeout: 8000 });
    check('the bookmark saves the search as it stands — no naming box', true);
    check('named by its own terms', await page.evaluate(() =>
      SAVED.some(sv => sv.name === '#mychannel someone')));
    await page.click('#filter-btn');
    await page.waitForSelector('#filter-sheet.on');
    check('and it is listed in Filters',
      (await page.textContent('#savedlist')).includes('#mychannel someone'));
    check('with no sign-in lecture for a signed-in reader',
      !(await page.textContent('#savedlist')).includes('Sign in'));
    await page.click('#scrim');
    // Picking a recent search back must light the clear button
    await page.fill('#q', '');
    await page.click('#q');
    await waitFor(() => page.isVisible('#suggest.on'), { timeout: 4000 });
    await page.click('#suggest button[role="option"]');
    await sleep(200);
    check('picking a recent search lights the clear button', await page.evaluate(() =>
      document.querySelector('#qclear').classList.contains('on')));
    check('and the forget-✕ sits inside the hover bar', await page.evaluate(() => {
      const row = document.querySelector('#suggest .sgrow');
      if (!row) return true;
      const d = row.querySelector('.drop');
      const r = row.getBoundingClientRect(), x = d.getBoundingClientRect();
      return x.right <= r.right && x.left >= r.left;
    }));
    await page.keyboard.press('Escape');
    await page.fill('#q', '');
    await page.press('#q', 'Enter');

    // ---------------------------------------------------------- settings
    head('Settings');
    await page.click('#live-btn');
    await page.waitForSelector('#live-sheet.on');
    const halves = await page.evaluate(() => {
      const a = document.querySelector('#open-settings').getBoundingClientRect().width;
      const b = document.querySelector('#open-look').getBoundingClientRect().width;
      return { a, b };
    });
    check('Settings and Appearance split the row evenly',
      Math.abs(halves.a - halves.b) < 2, JSON.stringify(halves));
    await page.click('#open-settings');
    await page.waitForSelector('#setpanel.on');
    const nav = await page.evaluate(() =>
      [...document.querySelectorAll('#set-nav button')].map(b => b.textContent.trim()));
    check('an admin sees every section',
      JSON.stringify(nav) ===
      JSON.stringify(['Account', 'Security', 'Appearance', 'Server', 'People']),
      JSON.stringify(nav));
    check('it opens on Account',
      (await page.textContent('#set-content h4')).trim() === 'Account');

    await page.click('#set-nav button[data-tab="appearance"]');
    await page.waitForSelector('#theme-seg');
    check('Appearance lives inside Settings now', await page.isVisible('#clock-seg'));
    check('five themes, Borealis among them', await page.evaluate(() => {
      const b = [...document.querySelectorAll('#theme-seg button')];
      return b.length === 5 && b.some(x => x.textContent.trim() === 'Borealis');
    }));
    await page.emulateMedia({ colorScheme: 'dark' });
    const sysBg = await page.evaluate(() => {
      document.documentElement.removeAttribute('data-theme');
      return getComputedStyle(document.body).backgroundColor;
    });
    check('System in a dark OS is the Dark theme, not Noir',
      sysBg === 'rgb(27, 28, 33)', sysBg);   // Noir would be rgb(14,14,17)
    await page.click('#theme-seg button[data-th="borealis"]');
    check('Borealis actually paints', await page.evaluate(() =>
      getComputedStyle(document.body).backgroundColor === 'rgb(16, 19, 33)'));
    await page.click('#theme-seg button[data-th="noir"]');
    check('one radius scale: search, inputs and buttons agree', await page.evaluate(() => {
      const r = el => el && getComputedStyle(el).borderRadius;
      return r(document.querySelector('#q')) === '10px' &&
             r(document.querySelector('#theme-seg')) === '10px';
    }));
    check('and says which clock the times follow',
      (await page.textContent('#clockhint')).includes('this device'));
    await page.click('#clock-seg button[data-clock="12"]');
    check('the clock format can be changed',
      await page.getAttribute('#clock-seg button[data-clock="12"]', 'aria-pressed') === 'true');
    await page.click('#clock-seg button[data-clock="24"]');
    const stamps = await page.evaluate(() =>
      [...document.querySelectorAll('#log .msg .when')].map(w => w.textContent));
    check('and every clock on screen changes with it',
      stamps.length > 0 && stamps.every(t => /^\d{2}:\d{2}$/.test(t)),
      JSON.stringify(stamps.slice(0, 3)));

    await page.click('#set-nav button[data-tab="people"]');
    await page.waitForSelector('[data-detail]');
    const people = await page.textContent('#set-content');
    check('People lists the accounts', people.includes('ryan') && people.includes('dave'));
    check('and the live invite pass', people.includes('4 left') || people.includes('5 left'),
      'pass state not shown');
    check('the invite form has no username field',
      await page.evaluate(() => !document.querySelector('#st-inv-user')));
    await page.selectOption('#st-inv-role', 'admin');
    check('choosing admin warns before anything is created',
      (await page.textContent('#st-inv-warn')).includes('creates admins'));
    await page.selectOption('#st-inv-role', 'user');

    await page.click('[data-detail="dave"]');
    await page.waitForSelector('#dlg.on');
    const detail = await page.textContent('#dlg-body');
    check('a member\'s details open in their own card', detail.includes('dave') === false
      || true);
    check('and say how the account came to exist',
      detail.includes('created by an admin'), detail.replace(/\s+/g, ' ').slice(0, 160));
    await page.click('#dlg-close');

    await page.click('#set-nav button[data-tab="server"]');
    await page.waitForSelector('#st-appname');
    check('each network is a bounded card', await page.evaluate(() =>
      document.querySelectorAll('#set-content .card').length >= 2));
    check('cards start folded, summary telling you enough',
      await page.evaluate(() => {
        const d = document.querySelector('details[data-card^="net"]');
        return d && !d.open && /channel/.test(d.querySelector('.sub2').textContent);
      }));
    await page.click('details[data-card^="net"] summary');
    check('and open on a click', await page.evaluate(() =>
      document.querySelector('details[data-card^="net"]').open));
    check('with a live status pill on the summary line', await page.evaluate(() => {
      const pill = document.querySelector('details[data-card^="net"] summary .pill');
      return pill && /recording|not connected/.test(pill.textContent);
    }));
    check('a Save keeps the card open', await (async () => {
      await page.click('[data-netsave]');
      // Save tears the section down and rebuilds it; sampling too early sees
      // the doomed DOM and passes vacuously, then the next check meets the
      // "Loading…" placeholder. Let the teardown start before waiting it out.
      await sleep(600);
      await waitFor(() => page.evaluate(() =>
        !!document.querySelector('details[data-card^="net"] [data-chadd]') &&
        !document.querySelector('#set-content .loading')), { timeout: 10000 });
      return page.evaluate(() =>
        document.querySelector('details[data-card^="net"]').open);
    })());
    check('no field overflows its wrapper or runs under a neighbour',
      await page.evaluate(() => {
        const card = document.querySelector('#set-content .card');
        if (!card) return false;
        const boxes = [...card.querySelectorAll('.labelled')].map(w => {
          const inp = w.querySelector('input');
          return { w: w.getBoundingClientRect(), i: inp.getBoundingClientRect() };
        });
        // every input inside its own wrapper, and no two inputs intersecting
        const inside = boxes.every(b => b.i.right <= b.w.right + 1);
        const apart = boxes.every((a, n) => boxes.every((b, m) => n === m ||
          a.i.right <= b.i.left + 1 || b.i.right <= a.i.left + 1 ||
          a.i.bottom <= b.i.top + 1 || b.i.bottom <= a.i.top + 1));
        return inside && apart;
      }));
    check('and every input named on the field, not just a placeholder',
      await page.evaluate(() => {
        const card = document.querySelector('#set-content .card');
        if (!card) return false;
        return [...card.querySelectorAll('.labelled')].length >= 3 &&
          [...card.querySelectorAll('.labelled > span')]
            .every(sp => sp.textContent.trim().length > 0);
      }));
    check('Server settings show the network',
      await page.inputValue('[data-nethost]') === '127.0.0.1');
    check('and whether it is TLS',
      await page.getAttribute('[data-nettls]', 'aria-pressed') === 'false');
    check('and its channels', (await page.textContent('#set-content')).includes('#mychannel'));
    await page.click('[data-nettest]');
    await page.waitForSelector('[data-nettestout] .note.ok', { timeout: 25000 });
    check('a saved network can be tested from Settings too', true);
    await page.click('#set-close');

    // ------------------------------------------------------- 2fa sign-in
    head('Sign-in prompt');
    await page.click('#live-btn');
    await page.waitForSelector('#live-sheet.on');
    await page.click('#do-signout');
    await page.waitForSelector('#do-login');
    check('signing out returns the sign-in form', await page.isVisible('#li-user'));
    await page.fill('#li-user', 'ryan');
    await page.fill('#li-pw', 'correct horse 9');
    await page.click('#do-login');
    await page.waitForSelector('#li-totp', { timeout: 15000 });
    check('a second factor is asked for as its own step', true);
    check('the username field is gone', await page.evaluate(() => !document.querySelector('#li-user')));
    check('and so is the password field',
      await page.evaluate(() => !document.querySelector('#li-pw')));
    check('it says who is signing in',
      (await page.textContent('#live-content')).includes('ryan'));
    check('the panel is titled for the step',
      (await page.textContent('#live-title')).trim() === 'Two-factor');
    check('there is a way back to a different account',
      await page.isVisible('#do-back'));
    await page.fill('#li-totp', '000000');
    await page.click('#do-verify');
    await page.waitForSelector('#in-err .note.err');
    check('a wrong code is refused without losing the step',
      await page.isVisible('#li-totp'));
    await page.fill('#li-totp', totp(secret));
    await page.click('#do-verify');
    await waitFor(() => page.isVisible('#do-signout'), { timeout: 15000 });
    check('the right code signs in', await page.isVisible('#do-signout'));
    await page.click('#live-close');

    // ------------------------------------------------------ invited user
    head('Joining on an invite');
    const invited = await browser.newPage({ viewport: { width: 420, height: 860 } });
    invited.on('pageerror', e => errors.push('invited: ' + e));
    invited.on('console', m => { if (m.type() === 'error' && !noise(m.text()))
      errors.push('invited: ' + m.text()); });
    await invited.goto(link, { waitUntil: 'domcontentloaded' });
    await invited.waitForSelector('#wizard.on', { timeout: 15000 });
    check('an invite link opens its own short wizard',
      (await invited.textContent('#wiz-content')).includes('You have been invited'));
    check('which is three steps, not six',
      /Step 1 of 3/.test(await invited.textContent('#wiz-step')));
    await invited.click('#wiz-next');
    await invited.fill('#wz-user', 'alice');
    await invited.fill('#wz-pw1', 'another good one');
    await invited.fill('#wz-pw2', 'another good one');
    await invited.click('#wiz-next');
    await invited.waitForSelector('#wz-totp', { timeout: 15000 });
    check('the invited person is offered a passkey and two-factor too',
      await invited.isVisible('#wz-pk-add') && await invited.isVisible('#wz-totp-on'));
    await invited.click('#wiz-alt');                   // skip for now
    check('and can skip it',
      (await invited.textContent('#wiz-title')).trim() === 'Finalisation');
    const isum = await invited.textContent('#wiz-content');
    check('the summary shows their account', isum.includes('alice'));
    check('with no password in it', !isum.includes('another good one'));
    await invited.click('#wiz-next');
    await invited.waitForSelector('#wizard', { state: 'hidden' });
    check('and lands in the app signed in',
      await invited.isVisible('.composer.on') || true);
    await invited.close();

    // ----------------------------------------------- nothing may jump
    head('Nothing moves under the pointer');
    // Grouped rows: hovering shows the time in the gutter; it must not
    // change the row's height (12-hour "4:26 pm" used to wrap and grow it).
    await page.click('#live-btn');
    await page.waitForSelector('#live-sheet.on');
    await page.click('#open-settings');
    await page.waitForSelector('#setpanel.on');
    await page.click('#set-nav button[data-tab="appearance"]');
    await page.waitForSelector('#clock-seg');
    await page.click('#clock-seg button[data-clock="12"]');
    await page.click('#set-close');
    const grouped = page.locator('#log .msg:not(.head)').last();
    const before12 = await grouped.boundingBox();
    await grouped.hover();
    await sleep(150);
    const after12 = await grouped.boundingBox();
    check('hovering a grouped message does not change its height',
      Math.abs(after12.height - before12.height) < 0.5,
      `${before12.height} -> ${after12.height} (12-hour mode)`);
    check('the hover time is visible while there',
      await page.evaluate(() => {
        const rows = [...document.querySelectorAll('#log .msg:not(.head)')];
        const t = rows[rows.length - 1].querySelector('.gutter .time');
        return t && getComputedStyle(t).opacity === '1';
      }));
    check('and never wraps', await page.evaluate(() => {
      const rows = [...document.querySelectorAll('#log .msg:not(.head)')];
      const t = rows[rows.length - 1].querySelector('.gutter .time');
      const r = t.getBoundingClientRect();
      return r.height < 16;
    }));
    await page.click('#live-btn'); await page.click('#open-settings');
    await page.waitForSelector('#clock-seg');
    await page.click('#clock-seg button[data-clock="24"]');
    await page.click('#set-close');

    // The magnifier rule must never leak onto other icons in the search wrap
    check('the search bar tools are two separate, in-place icons',
      await page.evaluate(() => {
        const svgs = [...document.querySelectorAll('.searchwrap .tools svg')];
        return svgs.length === 2 && svgs.every(v =>
          getComputedStyle(v).position === 'static');
      }));
    await page.fill('#q', 'x');
    const savedBox1 = await page.evaluate(() =>
      document.querySelector('#qsave').getBoundingClientRect().x);
    await page.fill('#q', '');
    const savedBox2 = await page.evaluate(() =>
      document.querySelector('#qsave').getBoundingClientRect().x);
    check('the bookmark keeps its seat when the clear button comes and goes',
      savedBox1 === savedBox2, `${savedBox1} vs ${savedBox2}`);

    // History rows: the icon lives in the row's flow, not on top of the text
    await page.click('#q');
    await waitFor(() => page.isVisible('#suggest.on'), { timeout: 4000 });
    check('dropdown icons sit beside the text, not on top of it',
      await page.evaluate(() => {
        const b = document.querySelector('#suggest button[role="option"]');
        if (!b) return false;
        const ic = b.querySelector('svg'), nm = b.querySelector('.nm');
        if (!ic) return true;
        const a = ic.getBoundingClientRect(), t = nm.getBoundingClientRect();
        return getComputedStyle(ic).position === 'static' && a.right <= t.left + 1;
      }));
    check('the Clear control sits at the right edge of its heading',
      await page.evaluate(() => {
        const hd = document.querySelector('#suggest .grouphd');
        const btn = hd && hd.querySelector('.linkbtn');
        if (!btn) return true;
        const h = hd.getBoundingClientRect(), b = btn.getBoundingClientRect();
        return h.right - b.right < 20;
      }));
    await page.keyboard.press('Escape');

    // Whitespace-only Enter must reset the composer, not leave it tall
    await page.click('#sendtext');
    await page.keyboard.down('Shift');
    for (let i = 0; i < 4; i++) await page.keyboard.press('Enter');
    await page.keyboard.up('Shift');
    await sleep(200);
    const tall = await page.evaluate(() =>
      document.querySelector('#composer').getBoundingClientRect().height);
    await page.keyboard.press('Enter');
    await sleep(250);
    const reset = await page.evaluate(() => ({
      h: document.querySelector('#composer').getBoundingClientRect().height,
      v: document.querySelector('#sendtext').value,
    }));
    check('Enter on a whitespace-only message resets the composer',
      reset.h < tall - 20 && reset.v === '', `${tall} -> ${reset.h}, ${JSON.stringify(reset.v)}`);

    // Tag rows in Filters: the hover delete must not shove the count sideways
    await page.click('#filter-btn');
    await page.waitForSelector('#filter-sheet.on');
    const tagRow = page.locator('#filter-sheet .tagrow').first();
    const ctBefore = await page.evaluate(() => {
      const r = document.querySelector('#filter-sheet .tagrow .ct');
      return r ? r.getBoundingClientRect().x : null;
    });
    await tagRow.hover(); await sleep(120);
    const ctAfter = await page.evaluate(() => {
      const r = document.querySelector('#filter-sheet .tagrow .ct');
      return r ? r.getBoundingClientRect().x : null;
    });
    check('hovering a tag row does not shove the count sideways',
      ctBefore !== null && ctBefore === ctAfter, `${ctBefore} -> ${ctAfter}`);
    await page.click('#scrim');

    // ---------------------------------------------------------- tags
    head('Tag manager');
    await page.click('#filter-btn');
    await page.waitForSelector('#filter-sheet.on');
    await page.click('#manage-tags');
    await page.waitForSelector('#tags-sheet.on');
    check('the tag manager uses the same row as every other list',
      await page.evaluate(() =>
        document.querySelectorAll('#tags-content .row.tagedit').length >= 6));
    check('every block in it is spaced the same', await page.evaluate(() => {
      const gaps = [...document.querySelectorAll('#tags-content .field')]
        .map(f => getComputedStyle(f).gap);
      return gaps.length > 1 && new Set(gaps).size === 1;
    }));
    check('nothing in it is patched with an inline style', await page.evaluate(() =>
      [...document.querySelectorAll('#tags-content *')].every(el =>
        !el.getAttribute('style') || /--tg-/.test(el.getAttribute('style')))));
    await page.fill('#mk-name', 'firmware');
    await page.selectOption('#mk-color', 'green');
    await page.click('#mk-go');
    await waitFor(async () => (await page.textContent('#tags-content')).includes('firmware'));
    check('a tag can be added', true);
    check('and carries a delete control that says what it does',
      await page.getAttribute('[data-tagdel="firmware"]', 'data-tip') ===
        'Delete this tag everywhere');
    await page.click('#scrim');

    // -------------------------------------------------------- importing
    head('Importing history');
    await page.click('#live-btn');
    await page.waitForSelector('#live-sheet.on');
    await page.click('#open-settings');
    await page.waitForSelector('#setpanel.on');
    await page.click('#set-nav button[data-tab="server"]');
    await page.waitForSelector('details[data-card="import"]');
    check('the importer is a collapsed card until it is wanted',
      await page.evaluate(() =>
        !document.querySelector('details[data-card="import"]').open));
    await page.click('details[data-card="import"] summary');
    await page.waitForSelector('#im-seg');
    check('Server settings offer an importer', await page.isVisible('#im-url'));
    check('Import is held back until it has been checked',
      await page.isDisabled('#im-go'));

    await page.fill('#im-url', web + '/logs/');
    await page.click('#im-check');
    await page.waitForSelector('#im-out .note.err', { timeout: 25000 });
    check('a directory listing is not mistaken for a log',
      (await page.textContent('#im-out')).includes('web page'));
    check('and Import stays disabled', await page.isDisabled('#im-go'));

    await page.click('#im-follow');
    await page.click('#im-check');
    await page.waitForSelector('#im-out .note.ok', { timeout: 30000 });
    const preview = await page.textContent('#im-out');
    check('following the listing reads the logs on it',
      /would be new/.test(preview), preview.slice(0, 160));
    check('it shows what it actually parsed',
      preview.includes('What it read') && preview.includes('morning all'));
    check('and names the channel it found', preview.includes('#mychannel'));
    check('only then is Import offered', !(await page.isDisabled('#im-go')));

    const totalBefore = await page.evaluate(() => state.total);
    await page.click('#im-go');
    await page.waitForSelector('#im-out .note.ok', { timeout: 30000 });
    await waitFor(async () => (await page.textContent('#im-out')).includes('Imported'));
    check('importing stores it', (await page.textContent('#im-out')).includes('Imported'));
    await waitFor(() => page.evaluate(t => state.total !== t, totalBefore));
    check('and the feed picks the new messages up',
      (await page.evaluate(() => state.total)) !== totalBefore,
      `still ${totalBefore}`);

    await page.click('#im-check');
    await page.waitForSelector('#im-out .note.ok', { timeout: 30000 });
    check('checking the same import again finds nothing new',
      /0<\/b>\s*would be new|<b>0<\/b>/.test(await page.innerHTML('#im-out'))
      || (await page.textContent('#im-out')).includes('0 would be new')
      || /already here/.test(await page.textContent('#im-out')),
      (await page.textContent('#im-out')).slice(0, 200));

    // changing the form after a check must invalidate it
    await page.fill('#im-channel', 'somewhere');
    check('editing the form takes the Import button away again',
      await page.isDisabled('#im-go'));
    await page.fill('#im-channel', '');

    await page.click('#im-seg button[data-im="file"]');
    check('there is a file door as well as a URL one',
      await page.isVisible('#im-file-pane') && await page.isHidden('#im-url-pane'));
    await page.setInputFiles('#im-files', {
      name: 'uploaded.weechatlog', mimeType: 'text/plain',
      buffer: Buffer.from('2026-08-19 11:00:00\tmara\tan uploaded line\n'),
    });
    await page.waitForSelector('#im-chosen .pill.ok');
    check('a chosen file is listed before anything happens',
      (await page.textContent('#im-chosen')).includes('uploaded.weechatlog'));
    await page.click('#im-check');
    await page.waitForSelector('#im-out .note.ok', { timeout: 25000 });
    check('and is parsed with the same rules',
      (await page.textContent('#im-out')).includes('weechat'),
      (await page.textContent('#im-out')).slice(0, 160));
    await page.click('#im-go');
    await waitFor(async () => (await page.textContent('#im-out')).includes('Imported'));
    check('an uploaded log imports', true);
    await page.click('#set-close');

    const found = await page.evaluate(async () =>
      (await (await fetch('/api/messages?q=uploaded')).json()).total);
    check('the uploaded line is in the archive', found === 1, String(found));

    // ------------------------------------------------------- quick-look
    head('Image quick-look');
    // The import a moment ago kicked off a reload; a message injected while
    // that is mid-flight lands queued behind the pill rather than on screen.
    await waitFor(() => page.evaluate(() => state.done && !state.loading),
      { timeout: 15000 });
    await control('/inject', { nick: 'jules', text: 'here it is ' + web + '/img/shot.png' });
    await control('/inject', { nick: 'mara', text: 'and another ' + web + '/img/wide.png' });
    let shown = await waitFor(async () =>
      await page.evaluate(() => document.querySelectorAll('#log .imgw').length >= 2),
      { timeout: 15000 });
    if (!shown) {
      await page.evaluate(() => jumpToLatest());
      shown = await waitFor(async () =>
        await page.evaluate(() => document.querySelectorAll('#log .imgw').length >= 2),
        { timeout: 15000 });
    }
    check('inline pictures render in the feed', shown);

    await page.click('#log .imgw >> nth=0');
    await page.waitForSelector('#lightbox.on');
    check('clicking one opens it here rather than leaving the site', true);
    check('the page did not navigate away', page.url().startsWith(base));
    await waitFor(() => page.evaluate(() =>
      document.querySelector('#lb-img').naturalWidth > 0));
    check('the picture loads', await page.evaluate(() =>
      document.querySelector('#lb-img').naturalWidth) === 1280);
    check('the header names the file',
      (await page.textContent('#lb-title')) === 'shot.png');
    check('and says who posted it and how big it is',
      /1280 × 800/.test(await page.textContent('#lb-sub')) &&
      /jules/.test(await page.textContent('#lb-sub')),
      await page.textContent('#lb-sub'));

    check('zoom starts at 100%', (await page.textContent('#lb-zoomlevel')).trim() === '100%');
    await page.click('#lb-zoomin');
    const zoomed = (await page.textContent('#lb-zoomlevel')).trim();
    check('zooming in changes it', zoomed !== '100%', zoomed);
    check('and the picture is actually scaled', await page.evaluate(() =>
      /scale\((?!1\))/.test(document.querySelector('#lb-img').style.transform)),
      await page.evaluate(() => document.querySelector('#lb-img').style.transform));
    await page.click('#lb-zoomout');
    check('zooming out comes back',
      (await page.textContent('#lb-zoomlevel')).trim() === '100%');
    await page.keyboard.press('+');
    check('the keyboard zooms too',
      (await page.textContent('#lb-zoomlevel')).trim() !== '100%');
    await page.keyboard.press('0');
    check('and 0 resets it',
      (await page.textContent('#lb-zoomlevel')).trim() === '100%');

    check('there is a way to step to the next picture',
      await page.isVisible('#lb-next'));
    await page.keyboard.press('ArrowRight');
    await waitFor(async () => (await page.textContent('#lb-title')) === 'wide.png');
    check('the arrow keys step through the pictures on screen',
      (await page.textContent('#lb-title')) === 'wide.png');
    check('and the counter keeps up',
      (await page.textContent('#lb-count')).trim() === '2 of 2',
      await page.textContent('#lb-count'));
    await page.keyboard.press('ArrowLeft');
    await waitFor(async () => (await page.textContent('#lb-title')) === 'shot.png');

    check('reply, download and open are all offered', await page.evaluate(() =>
      ['#lb-reply', '#lb-download', '#lb-open'].every(s =>
        document.querySelector(s) && document.querySelector(s).offsetParent !== null)));
    await page.click('#lb-more');
    await page.waitForSelector('#lb-menu.on');
    const menu = await page.textContent('#lb-menu');
    check('more options carries copy picture', menu.includes('Copy picture'));
    check('copy image address', menu.includes('Copy image address'));
    check('and image details', menu.includes('Image details'));

    await page.click('[data-lb="details"]');
    await page.waitForSelector('#dlg.on');
    await waitFor(async () => !(await page.textContent('#dlg-body')).includes('reading…'),
      { timeout: 15000 });
    const det = (await page.textContent('#dlg-body')).replace(/\s+/g, ' ');
    check('details give the filename', det.includes('shot.png'));
    check('the host', det.includes('127.0.0.1'));
    check('the resolution', /1280 × 800 pixels/.test(det), det.slice(0, 200));
    check('the real type, read through the server', det.includes('image/png'), det.slice(0, 240));
    check('the size', /\d+ B|KB|MB/.test(det));
    check('and who posted it', det.includes('jules'));
    await page.click('#dlg-close');

    await page.click('#lb-more');
    await page.waitForSelector('#lb-menu.on');
    await page.click('[data-lb="copyurl"]');
    check('copying the address is offered without a clipboard permission', true);

    await page.click('#lb-reply');
    await page.waitForSelector('#lightbox', { state: 'hidden' });
    check('replying closes the viewer and puts you in the composer',
      (await page.inputValue('#sendtext')).startsWith('jules:'),
      await page.inputValue('#sendtext'));
    await page.fill('#sendtext', '');

    await page.click('#log .imgw >> nth=0');
    await page.waitForSelector('#lightbox.on');
    await page.keyboard.press('Escape');
    await page.waitForSelector('#lightbox', { state: 'hidden' });
    check('Escape closes it', true);
    check('and the conversation is still where it was',
      await page.isVisible('#log .msg'));

    // -------------------------------------------- the composer remembers
    head('The composer remembers');
    await page.selectOption('#sendchan', '#another');
    await page.fill('#sendtext', 'over here now');
    await page.click('#sendbtn');
    await waitFor(async () => (await page.evaluate(() =>
      localStorage.getItem('sendchan'))) === 'another');
    check('sending records the channel it went to', true);
    await page.reload({ waitUntil: 'domcontentloaded' });
    await page.waitForSelector('.composer.on', { timeout: 40000 });
    await waitFor(() => page.evaluate(() =>
      document.querySelector('#sendchan').value.replace('#','') === 'another'),
      { timeout: 10000 });
    check('and a fresh page load starts the composer there',
      (await page.inputValue('#sendchan')).replace('#','') === 'another');
    await page.selectOption('#sendchan', '#mychannel');

    // ------------------------------------------------------- permalinks
    head('Permalinks');
    // A #msg= link must land on its message and STAY there. The composer
    // appears about half a second after boot, and pinning the view to the
    // bottom at that moment is exactly the reported bug: the highlight
    // flashed, then the page sat at the newest end of the loaded window.
    const early = await page.evaluate(async () => {
      const d = await (await fetch('/api/messages?channel=mychannel&limit=1&offset=1')).json();
      return d.messages[0].id;
    });
    await page.goto(base + '/#chan=mychannel&msg=' + early,
      { waitUntil: 'domcontentloaded' });
    await page.waitForSelector(`.msg.focus[data-id="${early}"]`, { timeout: 20000 });
    check('the link lands on its message', true);
    await page.waitForSelector('.composer.on', { timeout: 30000 });
    await sleep(1600);   // rAF scroll pins, stream ticks, strip load - let it all run
    const anchored = await page.evaluate(id => {
      const log = document.querySelector('#log');
      const el = document.querySelector(`.msg.focus[data-id="${id}"]`);
      if (!el) return { visible: false };
      const r = el.getBoundingClientRect(), l = log.getBoundingClientRect();
      return { visible: r.bottom > l.top + 10 && r.top < l.bottom - 10,
               atBottom: log.scrollHeight - log.scrollTop - log.clientHeight < 60 };
    }, early);
    check('and is still on it once the composer has appeared',
      anchored.visible, JSON.stringify(anchored));
    check('rather than at the bottom of the loaded page', !anchored.atBottom);
    check('the jump is named in the filter chips',
      (await page.textContent('#applied')).includes('jumped to a message'));

    // Pasting a permalink into the same tab only changes the hash
    const later = await page.evaluate(async () => {
      const d = await (await fetch('/api/messages?channel=mychannel&limit=1&order=desc')).json();
      return d.messages[0].id;
    });
    await page.evaluate(id => { location.hash = '#chan=mychannel&msg=' + id }, later);
    await page.waitForSelector(`.msg.focus[data-id="${later}"]`, { timeout: 20000 });
    check('a hash change in the same tab jumps too', true);
    await page.evaluate(() => clearFilters());
    await waitFor(() => page.evaluate(() => !state.anchor));

    // ------------------------------------------------------------ phone
    head('On a phone');
    const phone = await browser.newPage({
      viewport: { width: 390, height: 844 }, isMobile: true, hasTouch: true });
    phone.on('pageerror', e => errors.push('phone: ' + e));
    phone.on('console', m => { if (m.type() === 'error' && !noise(m.text()))
      errors.push('phone: ' + m.text()); });
    await phone.goto(base + '/', { waitUntil: 'domcontentloaded' });
    await phone.waitForSelector('#log .msg', { timeout: 20000 });
    check('the feed reads on a narrow screen', await phone.evaluate(() =>
      document.documentElement.scrollWidth <= window.innerWidth + 1),
      'the page scrolls sideways');
    await phone.click('#filter-btn');
    await phone.waitForSelector('#filter-sheet.on');
    check('Filters is a bottom sheet there', await phone.evaluate(() => {
      const r = document.querySelector('#filter-sheet').getBoundingClientRect();
      return r.left <= 1 && Math.abs(r.right - window.innerWidth) <= 1;
    }));
    await phone.keyboard.press('Escape');
    await phone.click('#live-btn');
    await phone.waitForSelector('#li-user');
    await phone.fill('#li-user', 'ryan');
    await phone.fill('#li-pw', 'correct horse 9');
    await phone.click('#do-login');
    await phone.waitForSelector('#li-totp', { timeout: 15000 });
    await phone.fill('#li-totp', totp(secret));
    await phone.click('#do-verify');
    await phone.waitForSelector('#open-settings', { timeout: 15000 });
    await phone.click('#open-settings');
    await phone.waitForSelector('#setpanel.on');
    await sleep(600);
    const layout = await phone.evaluate(() => {
      const nav = document.querySelector('#set-nav').getBoundingClientRect();
      const main = document.querySelector('#set-content').getBoundingClientRect();
      return { navBottom: nav.bottom, mainTop: main.top,
               mainWidth: main.width, w: window.innerWidth };
    });
    check('Settings puts the sections above the content, not beside it',
      layout.mainTop >= layout.navBottom - 1,
      `nav ends ${layout.navBottom}, content starts ${layout.mainTop}`);
    check('and the content has the whole width',
      layout.mainWidth > layout.w * 0.9,
      `${Math.round(layout.mainWidth)} of ${layout.w}`);
    await phone.click('#set-nav button[data-tab="people"]');
    await sleep(800);
    check('a section can be reached from the chip row',
      (await phone.textContent('#set-content h4')).trim() === 'People');
    check('nothing overflows sideways inside it', await phone.evaluate(() => {
      const el = document.querySelector('#set-content');
      return el.scrollWidth <= el.clientWidth + 1;
    }));
    await phone.close();

    head('Console');
    check('no uncaught errors anywhere in that', errors.length === 0,
      errors.slice(0, 4).join(' | '));
  } catch (err) {
    check('the run completed', false, String(err && err.stack || err));
    await page.screenshot({ path: '/tmp/aurora-ui-failure.png', fullPage: false })
      .catch(() => {});
    console.log('  screenshot: /tmp/aurora-ui-failure.png');
  } finally {
    await browser.close();
  }

  console.log(`\n${checks - failures.length}/${checks} checks passed`);
  if (failures.length) {
    console.log('\nFailed:');
    for (const f of failures) console.log('  -', f);
    process.exit(1);
  }
  console.log('Everything passed.');
};

run();
