#!/bin/sh
# Extract the client's script block and run it past a syntax check.
set -e
cd "$(dirname "$0")/.."
python3 - <<'PY'
import pathlib
s = pathlib.Path('ircarchive/web/index.html').read_text()
pathlib.Path('/tmp/aurora-app.js').write_text(s[s.index('<script>')+8:s.rindex('</script>')])
PY
node --check /tmp/aurora-app.js && echo "client script: syntax ok"
