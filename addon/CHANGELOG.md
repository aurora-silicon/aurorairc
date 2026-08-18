# Changelog

## 1.0.0

First add-on release.

- Runs the web client and the archivist as two supervised services, each
  restarted independently.
- Archive stored at `/data/archive.db`, so it survives restarts and updates and
  is picked up by Home Assistant backups.
- `behind_proxy` / `proxy_hops` options for running behind a tunnel.
- Waits for a network to be configured rather than exiting, so a fresh install
  sits idle instead of respawning.
