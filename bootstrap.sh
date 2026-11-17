#!/data/data/com.termux/files/usr/bin/sh
# Explicit offline setup. Missing Termux/Python tools are never installed here.
set -eu
umask 077
app_source=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd -P)
if ! command -v python >/dev/null 2>&1; then
  echo 'A qualified Termux Python interpreter is required.' >&2
  exit 3
fi
exec python "$app_source/pocketctl.py" install --source "$app_source" "$@"
