-- *****
--
-- language specific
--
-- *****

--*
----** ruby
--*
--

-- ruby-lsp
vim.lsp.config['ruby-lsp'] = {
    cmd = { 'ruby-lsp' },
    filetypes = { 'ruby', 'eruby' },
    root_markers = { 'Gemfile', '.git' },
    init_options = {
        enabledFeatures = {
            -- use rubocop
            diagnostics = false,
            formatting = false
        }
    }
}
-- better with just rubocop - disable completion
--vim.lsp.enable('ruby-lsp')

-- rubocop (linting and formatting)
vim.lsp.config['rubocop'] = {
    cmd = { 'rubocop', '--lsp' },
    filetypes = { 'ruby', 'eruby' },
    root_markers = { 'Gemfile', '.git' },
}
vim.lsp.enable('rubocop')

--*
----** go
--*
--

-- gopls
vim.lsp.config['gopls'] = {
    cmd = { 'gopls' },
    filetypes = { 'go', 'gomod' },
    root_markers = { '.git', 'go.mod' },
    -- disable completion
    on_init = function(client, _)
        client.server_capabilities.completionProvider = nil
    end,
}
vim.lsp.enable('gopls')

--*
----** lua
--*
--

-- Lua Language Server
vim.lsp.config['luals'] = {
    cmd = { 'lua-language-server' },
    filetypes = { 'lua' },
    root_markers = { '.luarc.json', '.luarc.jsonc', '.git' },
    settings = {
        Lua = {
            runtime = {
                version = 'LuaJIT',
            }
        }
    },
    -- this on_init funtion configures luals for nvim configuration
    -- (i.e. inside ~/.config/nvim/
    on_init = function(client)
        if client.workspace_folders then
            local path = client.workspace_folders[1].name
            if
                path ~= vim.fn.stdpath('config')
                and (vim.uv.fs_stat(path .. '/.luarc.json') or vim.uv.fs_stat(path .. '/.luarc.jsonc'))
            then
                return
            end
        end

        client.config.settings.Lua =
            vim.tbl_deep_extend('force', client.config.settings.Lua, {
                runtime = {
                    -- Tell the language server which version of Lua you're using (most
                    -- likely LuaJIT in the case of Neovim)
                    version = 'LuaJIT',
                    -- Tell the language server how to find Lua modules same way as Neovim
                    -- (see `:h lua-module-load`)
                    path = {
                        'lua/?.lua',
                        'lua/?/init.lua',
                    },
                },

                -- Make the server aware of Neovim runtime files
                workspace = {
                    checkThirdParty = false,
                    library = {
                        vim.env.VIMRUNTIME
                    }
                }
            })
    end,
}
vim.lsp.enable('luals')


-- *****
--
-- general config
--
-- *****

--*
----** LspAttach
--*
--
-- adapted from https://github.com/nvim-lua/kickstart.nvim/blob/master/init.lua
-- general configs for LspAttach
vim.api.nvim_create_autocmd('LspAttach', {
    group = vim.api.nvim_create_augroup('usr-lsp-attach', { clear = true }),
    callback = function(event)
        local map = function(keys, func, desc, mode)
            mode = mode or 'n'
            vim.keymap.set(mode, keys, func, { buffer = event.buf, desc = 'LSP: ' .. desc })
        end

        -- Rename the variable under your cursor.
        --  Most Language Servers support renaming across files, etc.
        map('gln', vim.lsp.buf.rename, '[R]e[n]ame')

        -- Execute a code action, usually your cursor needs to be on top of an error
        -- or a suggestion from your LSP for this to activate.
        map('gla', vim.lsp.buf.code_action, '[G]oto Code [A]ction', { 'n', 'x' })

        -- Find references for the word under your cursor.
        map('glr', require('telescope.builtin').lsp_references, '[G]oto [R]eferences')

        -- Jump to the implementation of the word under your cursor.
        --  Useful when your language has ways of declaring types without an actual implementation.
        map('gli', require('telescope.builtin').lsp_implementations, '[G]oto [I]mplementation')

        -- Jump to the definition of the word under your cursor.
        --  This is where a variable was first declared, or where a function is defined, etc.
        --  To jump back, press <C-t>.
        map('gld', require('telescope.builtin').lsp_definitions, '[G]oto [D]efinition')

        -- The following two autocommands are used to highlight references of the
        -- word under your cursor when your cursor rests there for a little while.
        --    See `:help CursorHold` for information about when this is executed
        -- When you move your cursor, the highlights will be cleared (the second autocommand).
        local client = vim.lsp.get_client_by_id(event.data.client_id)
        if client:supports_method(vim.lsp.protocol.Methods.textDocument_documentHighlight, event.buf) then
            local highlight_augroup = vim.api.nvim_create_augroup('usr-lsp-highlight', { clear = false })
            vim.api.nvim_create_autocmd({ 'CursorHold', 'CursorHoldI' }, {
                buffer = event.buf,
                group = highlight_augroup,
                callback = vim.lsp.buf.document_highlight,
            })

            vim.api.nvim_create_autocmd({ 'CursorMoved', 'CursorMovedI' }, {
                buffer = event.buf,
                group = highlight_augroup,
                callback = vim.lsp.buf.clear_references,
            })

            vim.api.nvim_create_autocmd('LspDetach', {
                group = vim.api.nvim_create_augroup('usr-lsp-detach', { clear = true }),
                callback = function(event2)
                    vim.lsp.buf.clear_references()
                    vim.api.nvim_clear_autocmds { group = 'usr-lsp-highlight', buffer = event2.buf }
                end,
            })
        end
    end,
})

--*
----** diagnostic config
--*
--
vim.opt.signcolumn = "yes"
vim.diagnostic.config {
    severity_sort = true,
    underline = { severity = vim.diagnostic.severity.ERROR },
    virtual_text = {
        source = "if_many",
        spacing = 2,
    },
}
