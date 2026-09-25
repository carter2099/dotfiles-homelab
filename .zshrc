# Lines configured by zsh-newuser-install
# EDIT: added appendhistory
HISTFILE=~/.histfile
HISTSIZE=1000
SAVEHIST=10000
setopt INC_APPEND_HISTORY_TIME
unsetopt beep
bindkey -v
# End of lines configured by zsh-newuser-install
# The following lines were added by compinstall
zstyle :compinstall filename '/home/carter/.zshrc'

autoload -Uz compinit
compinit
# End of lines added by compinstall

# User config

# XDG RUNTIME DIR
export XDG_RUNTIME_DIR=/run/user/$(id -u)

# prompt
# using starship instead
# not on homelab (yet)
PS1='%B%n%b @ %F{green}%B%/%b%f $ '

# add ~/.zfunc to fpath, then lazy autoload
# every file in there as a function
# ** no functions yet on homelab so this errors
#fpath=(~/.zfunc $fpath)
#autoload -U $fpath[1]/*(.:t)

# alias
alias cdconfig="cd ~/.config"
alias ls="ls --color=auto"
alias zs="source ~/.zshrc"
alias ez="nvim ~/.zshrc"
alias cmatrix="cmatrix -b -C blue -u 5"
alias cdnvim="cd ~/.config/nvim"
alias k="kubectl"
# dotfiles sync (command at ~/.local/bin/dotfiles — no alias needed)
alias carterhelp='nvim ~/README.md'

# omp: auto-add --allow-home when starting from ~
omp() {
    if [[ "$PWD" == "$HOME" ]]; then
        # --allow-home is only for agent sessions, not subcommands.
        # Subcommands are single-word first args that don't start with -.
        if [[ $# -eq 0 || "$1" == -* || "$1" == *\ * ]]; then
            command omp --allow-home "$@"
        else
            command omp "$@"
        fi
    else
        command omp "$@"
    fi
}


export KUBECONFIG=~/.kube/config


# fnm
FNM_PATH="/home/carter/.local/share/fnm"
if [ -d "$FNM_PATH" ]; then
  export PATH="$FNM_PATH:$PATH"
  eval "`fnm env`"
fi

eval "$(fnm env --use-on-cd --shell zsh)"
eval "$(rbenv init -)"
export PATH="$HOME/.local/bin:$PATH"

# Cloudflare API credentials
export CLOUDFLARE_API_TOKEN=$(cat ~/.config/cloudflare/api-token 2>/dev/null | tr -d '\n')
export CLOUDFLARE_ACCOUNT_ID=$(cat ~/.config/cloudflare/account-id 2>/dev/null | tr -d '\n')
export CLOUDFLARE_ZONE_ID=$(cat ~/.config/cloudflare/zone-id 2>/dev/null | tr -d '\n')
export CLOUDFLARE_HOMELAB_TUNNEL_ID=$(cat ~/.config/cloudflare/homelab-tunnel-id 2>/dev/null | tr -d '\n')


# bun completions
[ -s "/home/carter/.bun/_bun" ] && source "/home/carter/.bun/_bun"

# bun
export BUN_INSTALL="$HOME/.bun"
export PATH="$BUN_INSTALL/bin:$PATH"

# go
export PATH="$HOME/go/bin:$PATH"
