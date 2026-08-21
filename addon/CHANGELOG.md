# Changelog

## 1.2.3

- **Compact people cards in the conversation.** Clicking a name or picture
  now opens a Discord-style summary first, with status, archive activity,
  notes, favourites, saved connection icons and a route into the full profile.
- The full profile now matches the wide Settings and Help dialogs on desktop,
  starts in a clean read-only view and uses a pencil action when private links
  need editing. Long IRC and Matrix names stay contained in both views.
- People search and `@` autocomplete now query the complete archive directory,
  so infrequent speakers remain discoverable even when they are outside the
  busiest names included with the initial page metadata.

## 1.2.2

- **IRC commands in the composer.** Slash commands now autocomplete as you
  type and cover WHOIS, ISON, NAMES, WHO, USERHOST, WHOWAS, MOTD, VERSION,
  TIME and NickServ INFO/STATUS, with private, readable replies. Read-only
  raw queries are supported too; OFTC's missing MONITOR support is explained
  and presence checks use ISON instead.
- **People have profiles.** Click a name or picture for live status, recent
  archive activity and identity hints, plus filtering, favourites, private
  notes and profile links. Server-side pictures now appear on the public page
  by IRC nick without exposing account usernames.
- Account setup, invite redemption and manual account creation now ask for an
  IRC nick. Known account and live-roster conflicts are called out, while an
  explicit ownership claim can proceed when the nick really is yours.
- A new account starts with the System theme and no inherited background.
  Account-scoped appearance loading is also guarded against stale responses
  when switching between users.
- Promoting a user to admin clears any earlier optional-security dismissal and
  brings back a non-dismissible two-factor requirement. Optional two-factor
  and passkey choices are labelled consistently for regular users.
- Desktop Help now matches the Settings width and lays its sections out in
  three columns, so it no longer needs to scroll. Narrow screens keep the
  compact scrolling layout.

## 1.2.1

- **Events are back in Filters.** The Show row once again has a control for
  joins, leaves, quits, nick changes, kicks and modes, now named **Events**.
- Help cards no longer compress and cut off rows on shorter screens; the
  dialog keeps each row intact and scrolls normally.
- Mobile toolbar buttons stay beside the server name instead of wrapping
  below it. The duplicate message count yields on narrow phones while the
  same count remains in the search field.

## 1.2.0

- **Two-factor enforcement for admins.** An admin without two-factor
  authentication must enrol before using management controls. The founding
  owner remains exempt from the hard server gate so the instance cannot be
  locked out, while users receive a one-time, dismissible enrolment offer.
  Passkeys are named automatically from the device and browser.
- **Single-use password reset links.** Admins can mint 24-hour reset links
  from People; opening one sets a new password, signs the account in and
  revokes its other sessions. A newer link invalidates the old one, and only
  the owner can reset the owner account.
- **Profile pictures.** Accounts can upload a locally cropped JPEG, PNG or
  WebP avatar. Pictures appear beside matching IRC nicks in the feed, sidebar
  and People list for signed-in members; anonymous readers keep coloured
  initials. Uploads are type-checked and capped at 300 KB by the server.
- **Appearance follows the account.** Theme, accent, clock and background
  preferences sync across signed-in devices and update during the live
  session poll. A compact "This device only" switch keeps a local override.
- **Help is built in.** The new header button and `?` shortcut open a guide to
  keyboard controls and search syntax. Signed-out readers receive the public
  version without member-only tag syntax.
- **Member data stays private.** Anonymous API responses and the live stream
  no longer expose tags or saved searches, tag filters cannot leak counts,
  and signing out scrubs member-only data already rendered in the page.
- Change password is now first in Security, account rows show avatars instead
  of a two-factor badge, and anonymous readers no longer see tag controls.
- Dismissible setup flows no longer clear their own open state, and the
  `hidden` attribute once again wins over button styling on wizard footers.

## 1.1.2

- **Roles renamed.** The role once called "owner" is **admin**, a "member" is
  a **user**, and **owner** now names the founding account alone. Stored
  roles migrate in place on first start; nothing else about who can do what
  changes.
- **Search bar overhauled.** The bookmark saves the search as it stands,
  named by its own terms — the naming box is gone, and so is the second,
  native clear button. The bookmark only appears once there is something to
  save, picking a recent search lights the clear button, the forget-✕ sits
  inside the row's hover bar, and Clear in the heading is a proper little
  button rather than a full-width strip. The saved list no longer tells a
  signed-in reader to sign in.
- **Theming.** System now follows Light/Dark rather than Noir, and there is a
  fifth theme: **Borealis**, deep indigo with a soft blurple accent, the
  house theme. Every generated colour (nick, channel, tag) now agrees on
  which themes are dark.
- **One radius scale.** Buttons, inputs, selects and search all sit on 10px;
  small controls on 8px; cards and floating panels on 14px. Nothing is
  rounded by accident any more.
- The status bar is gone. The count lives in the header — narrowed views say
  "N of M messages" — and Copy is a small app-bar button.
- Inline images moved from Appearance into Filters, next to the other
  decisions about what the feed shows. The joins-and-quits toggle and a few
  paragraphs of lecture left the panels entirely.
- The quick date ranges hold one line instead of wrapping "All" onto its own.
- The composer remembers the channel you last sent to and starts there.
- Server settings cards got breathing room, and the "Settings | Appearance"
  buttons split their row evenly.
- A message permalink stays on its message. The jump landed and highlighted
  the right line, then the composer appeared - it shows up about half a
  second after boot, once the session is confirmed - and the resize handler
  pinned the view to the bottom of the loaded page, four hours of scrollback
  away. A jump owns the viewport now, and the bottom is only re-pinned for a
  reader who was already there.
- Pasting a permalink into the same tab's address bar works. That only
  changes the hash, the page never reloads, and nothing was listening for it.

## 1.1.1

Graphical fixes, from a sweep after watching it run on a real screen:

- Hovering a grouped message no longer makes the conversation jump. The
  timestamp that appears in the gutter took part in layout, and in 12-hour
  mode "4:26 pm" was wider than the gutter — it wrapped and grew the row
  under the pointer. It is out of the layout entirely now, and shown in a
  compact form that fits.
- The search bar's icons untangled. A rule meant for the magnifier matched
  every icon inside the search area, absolutely positioning the bookmark and
  clear buttons on top of each other and stacking each dropdown row's icon on
  its own text. The bookmark also keeps its seat now when the clear button
  appears, instead of hopping sideways.
- Enter on a whitespace-only message resets the composer. A few Shift+Enters
  followed by Enter used to leave an invisible stack of newlines holding the
  box tall.
- Hovering a tag row no longer shoves the count sideways; the delete control
  keeps its seat and fades in.
- Empty message slots (test results, errors) no longer spend layout space
  waiting for something to say.

And the Server settings flow is redesigned:

- Each network is a collapsible card. Folded, one line tells you what it is:
  address, TLS or plain, the archivist's nick, how many channels, and a live
  recording/not-connected pill. Open, every field is named on the field —
  Host, Port, Archivist nick — with TLS, Test and Save on one action row, and
  the channels beneath.
- "Add a network" and "Import history" are cards of the same shape, folded
  until wanted; the add card opens itself when no network exists yet. Which
  cards are open survives a save.

## 1.1.0

Bug fixes:

- A message you send is attributed to you the moment it lands. The grouping
  decision was made against a variable rather than the feed, so when the real
  message replaced its optimistic echo the row grouped itself under whoever
  spoke before it — your reply read as theirs until the page was reloaded.
- The conversation moves up as the composer grows. The reading pane shrank
  correctly but kept its scroll position, so a long message slid the newest
  lines in behind the box.
- Schema upgrades survive two processes opening the database at once. `serve`
  and `live` share one file and either can be first through the door after an
  upgrade; checking for a column and then adding it is a race the loser used
  to crash on.
- Times are the reader's own, and now say so. The clock was already local but
  its tooltip claimed UTC, and the date presets picked a UTC day — which is
  yesterday for most of an Australian one. Everything derived from a timestamp
  now goes through one place, and Appearance names the zone it is using.

New:

- **Pictures open in place.** Clicking one used to throw you out of the archive
  and onto whoever hosts it. It opens here now: zoom and pan, arrows through
  every picture on screen, and reply, save, open where it lives, copy the
  picture, copy its address, or read its real type, size and resolution.
- **Import history from the app.** Settings → Server takes a web address — a
  log file, or a directory listing it may follow — or files from your own
  machine. It runs through the same parsers the command line uses, and
  "Check it first" does the whole import inside a transaction and rolls it
  back, so you see the format, the channels, the dates and the first lines it
  read, and how many are already here, before anything is stored. Importing
  the same log twice adds nothing.
- **Setup is a walked path.** A fresh instance opens a wizard: welcome, server
  name, the owner account, a passkey or two-factor, invitations, then the IRC
  connection — which is tested against the real server before it can be saved,
  or deferred with "Set up later". It ends on a summary of everything that was
  configured, with no password anywhere in it. An invitation opens the same
  wizard, three steps long.
- **Invite passes.** One link several people can join on, revocable at any
  moment without touching the accounts already made on it. Owner-level links
  warn before they are minted.
- **Where an account came from.** View details on anyone in People: by whose
  link they joined, which link, and when.
- **Two-factor is its own step.** Once the password is accepted the fields that
  proved it are put away, and only the code is asked for.
- **The search bar remembers.** Recent searches come back in the bar, and the
  bookmark beside it saves the current one. Both are account features.
- The member step of setup says **Skip for now** out loud, rather than leaving
  people to work out that Next on an untouched form is allowed.
- **Filters and Settings redesigned.** One block rhythm, one row component and
  one set of controls throughout; presence folded into "Show", where it always
  belonged; Appearance moved into Settings, which is now a page with a section
  rail rather than a drawer.
- Message hover actions say what they do straight away, instead of relying on
  a native tooltip that arrives a second late, if at all.
- A network's TLS setting is editable, and "Test connection" tests what Save
  would actually write.
- Inline pictures work on a plain-http install again. The content policy
  allowed only https images, which over TLS is exactly right and over plain
  http on a LAN meant no inline pictures at all — a broken feature rather
  than a protection.
- The tag manager is built from the same row as every other list, so it no
  longer reads as the one screen that grew rather than being designed.

## 1.0.4

- A throttled address can present a valid agent token again. The backoff was
  checked before the token, so the code that clears it on a good token could
  never run - locking out legitimate agents for up to fifteen minutes, which
  is the exact case the backoff was written to tolerate.

## 1.0.3

- Normalise message text on the way in. Trailing whitespace survives in a web
  export but not in live capture, and the text is part of the dedupe key, so a
  line seen both ways was stored twice.

## 1.0.2

- Fix the two-factor code field being invisible. A rule meant to hide empty
  placeholder containers also matched every `<input>`, because a void element
  has no children and so is always `:empty`.

## 1.0.1

- Adopt an archive left at `/share/aurorairc-import.db` on start, after
  checking it really is one. Home Assistant OS has no shell, so this is how an
  existing archive gets in, and how one is restored.
- Any archive already in place is moved aside rather than overwritten.

## 1.0.0

First add-on release.

- Runs the web client and the archivist as two supervised services, each
  restarted independently.
- Archive stored at `/data/archive.db`, so it survives restarts and updates and
  is picked up by Home Assistant backups.
- `behind_proxy` / `proxy_hops` options for running behind a tunnel.
- Waits for a network to be configured rather than exiting, so a fresh install
  sits idle instead of respawning.
