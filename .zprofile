# Login shell init for systemd user services (non-interactive).
# .zshrc is only sourced by interactive shells, so fnm/PATH must
# be set up here for systemd-managed services.
export FNM_PATH="/home/carter/.local/share/fnm"
if [ -d "$FNM_PATH" ]; then
  export PATH="$FNM_PATH:$PATH"
  eval "$(fnm env)"
fi
export PATH="$HOME/.bun/bin:$HOME/.local/bin:$PATH"
