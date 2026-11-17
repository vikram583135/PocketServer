#!/data/data/com.termux/files/usr/bin/sh
# Uses the registered owner installation; runtime data is preserved by default.
set -eu
umask 077
app_source=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd -P)
if ! command -v python >/dev/null 2>&1; then
  echo 'The installed Python interpreter is required.' >&2
  exit 3
fi
exec python "$app_source/pocketctl.py" uninstall "$@"
