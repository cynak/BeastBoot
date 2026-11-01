# shellcheck shell=bash
# scripts/bootstrap-tools.sh on macOS: the Linux toolchain lives in the build
# container (scripts/container.sh); the Mac gets Homebrew tools and .venv.
# Defines functions only; needs ROOT, log, warn and lib/platform.sh.

BREW_FORMULAE=(bash colima docker docker-buildx shellcheck)
BUILDX_DIR=/opt/homebrew/lib/docker/cli-plugins

mac_brew() {
  command -v brew >/dev/null 2>&1 || {
    echo "bootstrap: error: Homebrew is needed on macOS: https://brew.sh" >&2; return 1; }
  local want=() f
  for f in "${BREW_FORMULAE[@]}"; do
    brew list --formula "$f" >/dev/null 2>&1 || want+=("$f")
  done
  bb_python >/dev/null 2>&1 || want+=(python@3.12)
  [ "${#want[@]}" -gt 0 ] || return 0
  if [ "${BB_NO_BREW:-0}" = 1 ]; then
    echo "bootstrap: error: missing: ${want[*]}; run: brew install ${want[*]}" >&2
    return 1
  fi
  log "brew install ${want[*]}"
  brew install "${want[@]}"
}

# Homebrew's docker-buildx is a CLI plugin docker only finds once its folder is listed.
mac_buildx() {
  docker buildx version >/dev/null 2>&1 && return 0
  [ -d "$BUILDX_DIR" ] || { warn "docker buildx not found (brew install docker-buildx)"; return 0; }
  log "registering $BUILDX_DIR in ~/.docker/config.json (cliPluginsExtraDirs)"
  mkdir -p "$HOME/.docker"
  "$(bb_python)" -I - "$HOME/.docker/config.json" "$BUILDX_DIR" <<'EOF'
import json, sys, pathlib
p, d = pathlib.Path(sys.argv[1]), sys.argv[2]
c = json.loads(p.read_text()) if p.exists() else {}
dirs = c.setdefault("cliPluginsExtraDirs", [])
if d not in dirs:
    dirs.append(d)
p.write_text(json.dumps(c, indent="\t") + "\n")
EOF
}

# A venv copied from Linux can still "run": bin/python links to /usr/bin/python3,
# which macOS has too. Its scripts' #! lines name the other machine's path.
mac_venv_usable() {
  local venv="$1"
  "$venv/bin/python" -c 'import sys; sys.exit(sys.version_info < (3, 10))' 2>/dev/null || return 1
  [ ! -e "$venv/bin/pytest" ] && return 0
  case "$(head -n1 "$venv/bin/pytest")" in "#!$venv/bin/python"*) return 0 ;; esac
  return 1
}

# .venv: pytest, ruff, coverage (requirements-dev.txt), same stamp as bin/bb-dev setup.
mac_venv() {
  local venv="$ROOT/.venv" req="$ROOT/requirements-dev.txt" stamp py want
  stamp="$venv/.bb-requirements.sha256"
  want="$(bb_sha256 "$req")"
  if mac_venv_usable "$venv"; then
    [ "$(cat "$stamp" 2>/dev/null)" = "$want" ] && return 0
  elif [ -e "$venv" ]; then
    log ".venv does not run on this Mac (made on another OS): recreating it"
    rm -rf "${venv:?}"
  fi
  py="$(bb_python)"
  log ".venv from $py with requirements-dev.txt"
  [ -x "$venv/bin/python" ] || "$py" -m venv "$venv"
  PIP_DISABLE_PIP_VERSION_CHECK=1 "$venv/bin/python" -m pip install -q --require-hashes \
    --only-binary :all: -r "$req"
  printf '%s\n' "$want" > "$stamp"
}

macos_bootstrap() {
  mac_brew
  mac_buildx
  mac_venv
  "$ROOT/scripts/container.sh" --image
  log "Linux toolchain inside the container (.tools volume)"
  # The image drops apt's lists; bootstrap-tools.sh resolves packages with apt.
  "$ROOT/scripts/container.sh" bash -c 'apt-get update -qq && exec scripts/bootstrap-tools.sh'
  log "done. make build / sbom / vulns / keys / image / e2e run in the container;"
  log "make test / lint / portable run on the Mac ('source scripts/dev-env.sh' for .venv on PATH)."
}
