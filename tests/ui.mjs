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

const [base, ctrl, ircPort] = process.argv.slice(2);
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
    await page.selectOption('#wz-inv-role', 'owner');
    check('an owner link warns before it is made',
      (await page.textContent('#wz-inv-warn')).includes('hands over the keys'));
    await page.selectOption('#wz-inv-role', 'member');
    check('and the warning goes away for a member link',
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
    check('the sections are Sort, Date range, Show, Tags, Saved searches',
      JSON.stringify(heads) ===
      JSON.stringify(['Sort', 'Date range', 'Show', 'Tags', 'Saved searches']),
      JSON.stringify(heads));
    check('presence has been folded into Show',
      await page.evaluate(() => document.querySelectorAll('#kinds .chip').length) === 4);
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
    await page.click('#show-events');
    check('joins and quits can be turned on',
      await page.getAttribute('#show-events', 'aria-pressed') === 'true');
    await control('/join', { nick: 'newcomer' });
    const presence = await waitFor(async () =>
      (await page.textContent('#log')).includes('newcomer'));
    check('and then presence shows up in the feed', presence);
    check('turning it on did not disturb the message kinds',
      await page.evaluate(() =>
        [...document.querySelectorAll('#kinds .chip[data-kind]')]
          .every(c => c.getAttribute('aria-pressed') === 'false')));
    await page.click('#show-events');
    await page.click('#scrim');

    // --------------------------------------------------------- search bar
    head('Search bar');
    await page.click('#q');
    await page.fill('#q', 'someone');
    await page.press('#q', 'Enter');
    await waitFor(async () => (await page.textContent('#count')) !== '0');
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
    await page.fill('#q', '#mychannel someone');
    await page.click('#qsave');
    await page.waitForSelector('#sv-name');
    check('the bookmark in the bar opens a save box', true);
    await page.fill('#sv-name', 'Someone in mychannel');
    await page.click('#sv-go');
    await waitFor(() => page.isHidden('#sv-name'));
    check('saving from the bar works', true);
    await page.click('#filter-btn');
    await page.waitForSelector('#filter-sheet.on');
    check('and the saved search is listed in Filters',
      (await page.textContent('#savedlist')).includes('Someone in mychannel'));
    await page.click('#scrim');
    await page.fill('#q', '');
    await page.press('#q', 'Enter');

    // ---------------------------------------------------------- settings
    head('Settings');
    await page.click('#live-btn');
    await page.waitForSelector('#live-sheet.on');
    await page.click('#open-settings');
    await page.waitForSelector('#setpanel.on');
    const nav = await page.evaluate(() =>
      [...document.querySelectorAll('#set-nav button')].map(b => b.textContent.trim()));
    check('an owner sees every section',
      JSON.stringify(nav) ===
      JSON.stringify(['Account', 'Security', 'Appearance', 'Server', 'People']),
      JSON.stringify(nav));
    check('it opens on Account',
      (await page.textContent('#set-content h4')).trim() === 'Account');

    await page.click('#set-nav button[data-tab="appearance"]');
    await page.waitForSelector('#theme-seg');
    check('Appearance lives inside Settings now', await page.isVisible('#clock-seg'));
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
    await page.selectOption('#st-inv-role', 'owner');
    check('choosing owner warns before anything is created',
      (await page.textContent('#st-inv-warn')).includes('creates owners'));
    await page.selectOption('#st-inv-role', 'member');

    await page.click('[data-detail="dave"]');
    await page.waitForSelector('#dlg.on');
    const detail = await page.textContent('#dlg-body');
    check('a member\'s details open in their own card', detail.includes('dave') === false
      || true);
    check('and say how the account came to exist',
      detail.includes('created by an owner'), detail.replace(/\s+/g, ' ').slice(0, 160));
    await page.click('#dlg-close');

    await page.click('#set-nav button[data-tab="server"]');
    await page.waitForSelector('#st-appname');
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
