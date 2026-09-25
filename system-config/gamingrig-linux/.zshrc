# Interactive zsh configuration for gamingrig-linux.

# Herdr opens an interactive, non-login zsh, so it does not read .zprofile.
# Establish the full development PATH here as well as in login shells.
export XDG_RUNTIME_DIR="${XDG_RUNTIME_DIR:-/run/user/$(id -u)}"
export BUN_INSTALL="${BUN_INSTALL:-$HOME/.bun}"
export FNM_PATH="${FNM_PATH:-${XDG_DATA_HOME:-$HOME/.local/share}/fnm}"
export RBENV_ROOT="${RBENV_ROOT:-$HOME/.rbenv}"
export GOPATH="${GOPATH:-$HOME/go}"
typeset -U path
path=(
    "$HOME/.local/bin"
    "$BUN_INSTALL/bin"
    "$FNM_PATH"
    "$RBENV_ROOT/bin"
    /usr/local/go/bin
    "$GOPATH/bin"
    $path
)
export PATH

# History is local to this host; never point it at ThinkPad state.
HISTFILE="$HOME/.histfile"
HISTSIZE=10000
SAVEHIST=10000
setopt APPEND_HISTORY
setopt INC_APPEND_HISTORY_TIME
setopt HIST_EXPIRE_DUPS_FIRST
setopt HIST_IGNORE_DUPS
setopt HIST_IGNORE_SPACE
setopt HIST_REDUCE_BLANKS
unsetopt beep

bindkey -v

# Completion
autoload -Uz compinit
compinit

# Prompt and useful, non-production aliases.
PS1='%B%n%b @ %F{green}%B%/%b%f $ '
alias cdconfig='cd ~/.config'
alias cdnvim='cd ~/.config/nvim'
alias ls='ls --color=auto'
alias ll='ls -alF'
alias la='ls -A'
alias l='ls -CF'
alias zs='source ~/.zshrc'
alias ez='nvim ~/.zshrc'

# direnv is opt-in per directory and does not import ThinkPad credentials.
if command -v direnv >/dev/null 2>&1; then
    eval "$(direnv hook zsh)"
fi

# fnm manages the requested Node.js default.
if [[ -x "$FNM_PATH/fnm" ]]; then
    eval "$(fnm env --use-on-cd --shell zsh)"
fi

# rbenv manages the requested Ruby default.
if [[ -x "$RBENV_ROOT/bin/rbenv" || -x "$RBENV_ROOT/libexec/rbenv" || $(command -v rbenv 2>/dev/null) ]]; then
    eval "$(rbenv init - zsh)"
fi

# Bun completions and user-local binaries.
if [[ -s "$BUN_INSTALL/_bun" ]]; then
    source "$BUN_INSTALL/_bun"
elif [[ -s "$BUN_INSTALL/bin/_bun" ]]; then
    source "$BUN_INSTALL/bin/_bun"
fi

# Start an OMP agent from $HOME only with its explicit home opt-in. This does
# not copy or relocate session/history/auth state. Keep command and flag
# classification aligned with OMP's registered command table and
# `resolveCliArgv`/`flagConsumesValue` contract.
_omp_is_registered_command() {
    case "$1" in
        launch|acp|auth-broker|auth-gateway|agents|bench|browser-relay|cleanse|commit|completions|__complete|compress|config|dry-balance|gc|grep|gallery|git|grievances|images|img|if-bench|install|join|models|plugin|ps|say|share|setup|shell|read|render|ssh|stats|update|usage|tiny-models|token|ttsr|worktree|wt|search|q)
            return 0
            ;;
        *)
            return 1
            ;;
    esac
}

# Return success when OMP's launch parser consumes the next argv token as a
# value. Bare unknown long options are treated as extension string candidates,
# as in OMP's startup parser.
_omp_flag_consumes_value() {
    local flag="$1"
    local next="${2-}"

    [[ "$flag" == --*=* ]] && return 1
    case "$flag" in
        --cwd|--config|--add-dir|--mode|--fork|--provider|--model|--smol|--slow|--prewalk-into|--plan-yolo-into|--max-time|--service-tier|--api-key|--system-prompt|--append-system-prompt|--provider-session-id|--prompt-cache-key|--session-dir|--models|--tools|--thinking|--export|--hook|--extension|-e|--trusted-extension|--plugin-dir|--skills|--approval-mode)
            return 0
            ;;
        --plan)
            [[ "$next" != -* ]]
            return $?
            ;;
        --resume|-r|--session|--profile|--alias)
            [[ -n "$next" && "$next" != -* ]]
            return $?
            ;;
        --help|--version|--allow-home|--continue|--from-claude|--from-codex|--no-session|--no-tools|--no-lsp|--no-pty|--hide-thinking|--advisor|--external-thinking|--prewalk|--no-prewalk|--plan-yolo|--print|--print-thoughts|--no-extensions|--no-skills|--no-rules|--no-title|--auto-approve|--yolo|-h|-v|-c|-p)
            return 1
            ;;
        --*)
            [[ "$next" != -* ]]
            return $?
            ;;
        *)
            return 1
            ;;
    esac
}

_omp_reserved_top_level_word() {
    local first="$1"
    local second="${2-}"
    case "$first" in
        extensions|list|remove|uninstall|marketplace|discover|upgrade|enable|disable)
            ;;
        *)
            return 1
            ;;
    esac

    if (( $# < 2 )); then
        return 0
    fi
    if [[ "$first" == marketplace && "$second" == (add|remove|rm|update|list) ]]; then
        return 0
    fi
    local arg
    shift
    for arg in "$@"; do
        if [[ "$arg" != -* && "$arg" == *@* ]]; then
            return 0
        fi
    done
    return 1
}

_omp_launch_invocation() {
    local -a args
    args=("$@")
    local first="${args[1]-}"
    case "$first" in
        --help|-h|--version|-v|help|--license|--smoke-test)
            return 1
            ;;
    esac
    if _omp_reserved_top_level_word "${args[@]}"; then
        return 1
    fi
    if _omp_is_registered_command "$first"; then
        [[ "$first" == launch ]]
        return $?
    fi

    local index=1
    local arg next
    while (( index <= $#args )); do
        arg="${args[index]}"
        if [[ "$arg" == -- ]]; then
            return 0
        fi
        if [[ "$arg" != -* ]]; then
            if _omp_is_registered_command "$arg"; then
                [[ "$arg" == launch ]]
                return $?
            fi
            return 0
        fi
        next="${args[index+1]-}"
        if _omp_flag_consumes_value "$arg" "$next"; then
            (( index += 2 ))
        else
            (( index += 1 ))
        fi
    done
    return 0
}

_omp_has_allow_home() {
    local -a args
    args=("$@")
    local index=1
    local arg next
    while (( index <= $#args )); do
        arg="${args[index]}"
        [[ "$arg" == --allow-home || "$arg" == --allow-home=* ]] && return 0
        [[ "$arg" == -- ]] && return 1
        next="${args[index+1]-}"
        if _omp_flag_consumes_value "$arg" "$next"; then
            (( index += 2 ))
        else
            (( index += 1 ))
        fi
    done
    return 1
}

omp() {
    if [[ "$PWD" == "$HOME" ]] && _omp_launch_invocation "$@"; then
        if _omp_has_allow_home "$@"; then
            command omp "$@"
        else
            command omp --allow-home "$@"
        fi
    else
        command omp "$@"
    fi
}
