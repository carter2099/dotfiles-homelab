# Login environment for gamingrig-linux development.
# Keep credentials and production-only environment out of the rig.

export XDG_RUNTIME_DIR="${XDG_RUNTIME_DIR:-/run/user/$(id -u)}"
export BUN_INSTALL="${BUN_INSTALL:-$HOME/.bun}"
export FNM_PATH="${FNM_PATH:-${XDG_DATA_HOME:-$HOME/.local/share}/fnm}"
export RBENV_ROOT="${RBENV_ROOT:-$HOME/.rbenv}"
export GOPATH="${GOPATH:-$HOME/go}"

export PATH="$HOME/.local/bin:$BUN_INSTALL/bin:$FNM_PATH:$RBENV_ROOT/bin:/usr/local/go/bin:$GOPATH/bin:$PATH"

export EDITOR="${EDITOR:-nvim}"
export VISUAL="${VISUAL:-$EDITOR}"
export GIT_EDITOR="${GIT_EDITOR:-$EDITOR}"
