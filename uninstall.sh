#!/bin/sh

set -eu

usage() {
  cat <<'EOF'
Usage:
  ./uninstall.sh [--preview] [--purge-state] TARGET_PROJECT

Remove MEVA files created by install.sh from an existing local project.

Options:
  --preview       Show the planned changes without removing anything.
  --purge-state  Also remove MEVA-created .meva/state.json when unchanged;
                 pre-existing/adopted state is always preserved.
  -h, --help      Show this help.

Environment:
  PYTHON_BIN      Python executable to use (default: python3).
EOF
}

die() {
  printf '%s\n' "uninstall.sh: $*" >&2
  exit 1
}

SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd -P)
PYTHON_BIN=${PYTHON_BIN:-python3}
PREVIEW=0
PURGE_STATE=0
TARGET_PROJECT=

while [ "$#" -gt 0 ]; do
  case "$1" in
    --preview)
      PREVIEW=1
      shift
      ;;
    --purge-state)
      PURGE_STATE=1
      shift
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    --)
      shift
      ;;
    -*)
      die "unknown option: $1"
      ;;
    *)
      [ -z "$TARGET_PROJECT" ] || die "only one target project is allowed"
      TARGET_PROJECT=$1
      shift
      ;;
  esac
done

[ -n "$TARGET_PROJECT" ] || { usage >&2; exit 2; }
[ -f "$SCRIPT_DIR/tools/meva_install.py" ] || die "MEVA installer helper is missing"
[ -d "$TARGET_PROJECT" ] || die "target project does not exist: $TARGET_PROJECT"

command -v "$PYTHON_BIN" >/dev/null 2>&1 || die "Python executable not found: $PYTHON_BIN"
"$PYTHON_BIN" -c 'import sys; raise SystemExit(0 if sys.version_info >= (3, 9) else 1)' \
  || die "$PYTHON_BIN must be Python 3.9 or newer"

if [ "$PREVIEW" -eq 1 ] && [ "$PURGE_STATE" -eq 1 ]; then
  exec env PYTHONDONTWRITEBYTECODE=1 "$PYTHON_BIN" \
    "$SCRIPT_DIR/tools/meva_install.py" uninstall \
    --target "$TARGET_PROJECT" --preview --purge-state
elif [ "$PREVIEW" -eq 1 ]; then
  exec env PYTHONDONTWRITEBYTECODE=1 "$PYTHON_BIN" \
    "$SCRIPT_DIR/tools/meva_install.py" uninstall \
    --target "$TARGET_PROJECT" --preview
elif [ "$PURGE_STATE" -eq 1 ]; then
  exec env PYTHONDONTWRITEBYTECODE=1 "$PYTHON_BIN" \
    "$SCRIPT_DIR/tools/meva_install.py" uninstall \
    --target "$TARGET_PROJECT" --purge-state
fi

exec env PYTHONDONTWRITEBYTECODE=1 "$PYTHON_BIN" \
  "$SCRIPT_DIR/tools/meva_install.py" uninstall \
  --target "$TARGET_PROJECT"
