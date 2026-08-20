/* Screenshots of every surface, so a redesign can actually be looked at.
   Run through tests/uiserver.py --shots. Writes into /tmp/aurora-shots. */
import crypto from 'node:crypto';
import fs from 'node:fs';
import { createRequire } from 'node:module';
const require_ = createRequire(import.meta.url);
const { chromium } = require_('playwright');

const [base, ctrl, ircPort, web] = process.argv.slice(2);
const OUT = '/tmp/aurora-shots';
fs.mkdirSync(OUT, { recursive: true });
const sleep = ms => new Promise(r => setTimeout(r, ms));
const control = (p, q = {}) => fetch(ctrl + p + '?' + new URLSearchParams(q)).then(r => r.json());
let n = 0;
const shot = async (page, name) =>
  page.screenshot({ path: `${OUT}/${String(++n).padStart(2, '0')}-${name}.png` });

function totp(secret) {
  const alpha = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
  let bits = '';
  for (const ch of secret.replace(/=+$/, '').toUpperCase()) bits += alpha.indexOf(ch).toString(2).padStart(5, '0');
  const bytes = Buffer.from((bits.match(/.{8}/g) || []).map(b => parseInt(b, 2)));
  const c = Buffer.alloc(8); c.writeBigUInt64BE(BigInt(Math.floor(Date.now() / 1000 / 30)));
  const h = crypto.createHmac('sha1', bytes).update(c).digest();
  const off = h[h.length - 1] & 0x0f;
  return String((h.readUInt32BE(off) & 0x7fffffff) % 1000000).padStart(6, '0');
}

const browser = await chromium.launch();
const page = await browser.newPage({ viewport: { width: 1360, height: 900 },
  colorScheme: 'dark' });
await page.goto(base + '/', { waitUntil: 'domcontentloaded' });
await page.waitForSelector('#wizard.on');
await shot(page, 'wizard-welcome');
await page.click('#wiz-next');
await page.fill('#wz-appname', 'Aurora Silicon');
await shot(page, 'wizard-server');
await page.click('#wiz-next');
await shot(page, 'wizard-account');
await page.fill('#wz-user', 'ryan'); await page.fill('#wz-nick', 'ryan_');
await page.fill('#wz-pw1', 'correct horse 9'); await page.fill('#wz-pw2', 'correct horse 9');
await page.click('#wiz-next');
await page.waitForSelector('#wz-totp');
await shot(page, 'wizard-secure');
await page.click('#wz-totp-on'); await page.waitForSelector('#totp-secret');
const secret = (await page.textContent('#totp-secret')).trim();
await shot(page, 'wizard-totp');
await page.fill('#totp-code', totp(secret)); await page.click('#totp-confirm');
await sleep(600);
await page.click('#wiz-next');
await page.selectOption('#wz-inv-role', 'owner'); await page.selectOption('#wz-inv-uses', '5');
await shot(page, 'wizard-members-warning');
await page.selectOption('#wz-inv-role', 'member');
await page.click('#wz-inv-go'); await page.waitForSelector('.copyfield code');
const link = await page.textContent('.copyfield code');
await shot(page, 'wizard-members-link');
await page.click('#wiz-next');
await page.fill('#wz-nn-name', 'test'); await page.fill('#wz-nn-host', '127.0.0.1');
await page.click('#wz-nn-tls'); await page.fill('#wz-nn-port', String(ircPort));
await page.fill('#wz-nn-chans', 'mychannel, another');
await shot(page, 'wizard-network');
await page.click('#wz-nn-test'); await page.waitForSelector('#wz-nn-out .note.ok', { timeout: 25000 });
await shot(page, 'wizard-network-tested');
await page.click('#wiz-next'); await page.waitForSelector('.summary');
await page.click('#wiz-next');
await shot(page, 'wizard-finish');
await page.click('#wiz-next');
await page.waitForSelector('#wizard', { state: 'hidden' });

await page.waitForSelector('.composer.on', { timeout: 45000 });
await sleep(1200);
for (const [nick, text] of [['someone', 'anyone tried the new firmware on the m2 boards?'],
  ['jules', 'yeah, flashed one this morning. boots but the fan curve is wrong'],
  ['jules', 'i can push a patch if nobody else is on it'],
  ['someone', 'jules: go for it, i have not started'],
  ['mara', 'is the tracker still down or is that just me'],
  ['jules', 'mara: still down, ops know']]) {
  await control('/inject', { nick, text });
  await sleep(180);
}
await page.fill('#sendtext', 'jules: nice one, i will test the patch tonight');
await page.click('#sendbtn');
await sleep(4000);
await shot(page, 'feed');
/* a grouped row under the pointer, showing the gutter time */
{
  const rows = await page.locator('#log .msg:not(.head)').all();
  if (rows.length) { await rows[rows.length - 1].hover(); await sleep(300); }
}
await shot(page, 'feed-hover-grouped');
await page.mouse.move(30, 300);

await page.click('#filter-btn'); await sleep(450);
await shot(page, 'filters');
await page.click('#manage-tags'); await sleep(500);
await shot(page, 'tags');
await page.click('#scrim'); await sleep(350);

await page.click('#q'); await page.fill('#q', 'firmware'); await page.press('#q', 'Enter');
await sleep(700); await page.click('#q'); await page.fill('#q', ''); await page.click('#q');
await sleep(400);
await shot(page, 'search-history');
await page.fill('#q', '#mychannel firmware'); await page.click('#qsave'); await sleep(300);
await shot(page, 'search-save');
await page.press('#sv-name', 'Escape'); await page.fill('#q', ''); await page.press('#q', 'Enter');
await sleep(400);

/* the importer, and a picture opened in place */
await page.click('#live-btn'); await page.click('#open-settings');
await page.waitForSelector('#setpanel.on');
await page.click('#set-nav button[data-tab="server"]');
await page.waitForSelector('details[data-card="import"]');
await page.click('details[data-card="import"] summary');
await page.waitForSelector('#im-seg');
await page.fill('#im-url', web + '/logs/');
await page.click('#im-follow');
await page.click('#im-check');
await page.waitForSelector('#im-out .note.ok', { timeout: 30000 });
await page.evaluate(() => document.querySelector('#im-check')
  .scrollIntoView({ block: 'center' }));
await sleep(400);
await shot(page, 'settings-import');
await page.click('#im-go');
await sleep(2500);
await shot(page, 'settings-import-done');
await page.click('#set-close');

await control('/inject', { nick: 'jules', text: 'the board shot: ' + web + '/img/shot.png' });
await sleep(2500);
// The import reloaded the feed, so we may be sitting away from the live end
await page.evaluate(() => jumpToLatest());
await page.waitForSelector('#log .imgw', { timeout: 20000 });
await sleep(800);
await page.click('#log .imgw >> nth=0');
await page.waitForSelector('#lightbox.on');
await sleep(800);
await shot(page, 'lightbox');
await page.click('#lb-more'); await sleep(400);
await shot(page, 'lightbox-menu');
await page.click('[data-lb="details"]');
await page.waitForSelector('#dlg.on'); await sleep(1200);
await shot(page, 'lightbox-details');
await page.click('#dlg-close');
await page.keyboard.press('Escape'); await sleep(400);

await page.click('#live-btn'); await sleep(400);
await shot(page, 'account-sheet');
await page.click('#open-settings'); await page.waitForSelector('#setpanel.on'); await sleep(400);
await shot(page, 'settings-account');
for (const tab of ['security', 'appearance', 'server', 'people']) {
  await page.click(`#set-nav button[data-tab="${tab}"]`);
  await sleep(700);
  if (tab === 'server') {
    await shot(page, 'settings-server-folded');
    await page.click('details[data-card^="net"] summary');
    await sleep(400);
  }
  await shot(page, 'settings-' + tab);
}
await page.click('[data-detail="ryan"]'); await page.waitForSelector('#dlg.on'); await sleep(300);
await shot(page, 'account-details');
await page.click('#dlg-close');
await page.click('#set-close');

await page.click('#live-btn'); await page.waitForSelector('#live-sheet.on');
await page.click('#do-signout'); await sleep(400);
await shot(page, 'signin');
await page.fill('#li-user', 'ryan'); await page.fill('#li-pw', 'correct horse 9');
await page.click('#do-login'); await page.waitForSelector('#li-totp'); await sleep(300);
await shot(page, 'signin-2fa');
await page.fill('#li-totp', totp(secret)); await page.click('#do-verify');
await sleep(900); await page.click('#live-close');

/* light theme */
await page.click('#live-btn'); await page.click('#open-settings');
await page.waitForSelector('#setpanel.on');
await page.click('#set-nav button[data-tab="appearance"]');
await page.waitForSelector('#theme-seg');
await page.click('#theme-seg button[data-th="light"]'); await sleep(400);
await shot(page, 'settings-appearance-light');
await page.click('#set-close'); await sleep(400);
await shot(page, 'feed-light');
await page.click('#live-btn'); await page.click('#open-settings');
await page.waitForSelector('#theme-seg');
await page.click('#theme-seg button[data-th="noir"]'); await page.click('#set-close');

/* phone */
const m = await browser.newPage({ viewport: { width: 390, height: 844 },
  colorScheme: 'dark', isMobile: true, hasTouch: true, deviceScaleFactor: 2 });
await m.goto(base + '/', { waitUntil: 'domcontentloaded' });
await sleep(2500);
await m.screenshot({ path: `${OUT}/${String(++n).padStart(2, '0')}-mobile-feed.png` });
await m.click('#filter-btn'); await sleep(600);
await m.screenshot({ path: `${OUT}/${String(++n).padStart(2, '0')}-mobile-filters.png` });
await m.keyboard.press('Escape'); await sleep(700);
await m.click('#live-btn'); await sleep(900);
await m.screenshot({ path: `${OUT}/${String(++n).padStart(2, '0')}-mobile-signin.png` });

await m.fill('#li-user', 'ryan'); await m.fill('#li-pw', 'correct horse 9');
await m.click('#do-login'); await m.waitForSelector('#li-totp');
await m.fill('#li-totp', totp(secret)); await m.click('#do-verify');
await m.waitForSelector('#open-settings', { timeout: 15000 }); await sleep(400);
await m.click('#open-settings'); await m.waitForSelector('#setpanel.on'); await sleep(900);
await m.screenshot({ path: `${OUT}/${String(++n).padStart(2, '0')}-mobile-settings.png` });
await m.click('#set-nav button[data-tab="people"]'); await sleep(900);
await m.screenshot({ path: `${OUT}/${String(++n).padStart(2, '0')}-mobile-settings-people.png` });
await m.click('#set-close'); await sleep(300);

const inv = await browser.newPage({ viewport: { width: 390, height: 844 },
  colorScheme: 'dark', deviceScaleFactor: 2 });
await inv.goto(link, { waitUntil: 'domcontentloaded' });
await inv.waitForSelector('#wizard.on'); await sleep(400);
await inv.screenshot({ path: `${OUT}/${String(++n).padStart(2, '0')}-mobile-invite.png` });

console.log('shots in ' + OUT);
await browser.close();
