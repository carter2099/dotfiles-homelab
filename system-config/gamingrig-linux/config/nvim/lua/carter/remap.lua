-- Set <leader> to space
vim.g.mapleader = " "
map = vim.keymap

-- Go back to explorer
map.set("n", "<leader>pv", vim.cmd.Ex)

-- Allows paste over current highlighted text
-- Dumps highlighted text into void register
-- Keeps pasted value in register
-- Kind of finicky unfortunately
map.set("x", "<leader>p", '"_dP')

-- copy and paste to/from system register
map.set("n", "<leader>y", '"+y')
map.set("v", "<leader>y", '"+y')

-- Scroll up and down sticks to middle of window
map.set("n", "<C-d>", "<C-d>zz")
map.set("n", "<C-u>", "<C-u>zz")

-- Same thing as above but when searching
map.set("n", "n", "nzzzv")
map.set("n", "N", "Nzzzv")

-- Make <C-c> do the same thing as <Esc>
map.set("i", "<C-c>", "<Esc>")

-- Format according to lsp
map.set("n", "<leader>f", vim.lsp.buf.format)

-- Map :so to <leader><leader>
map.set("n", "<leader><leader>", function()
    vim.cmd("so")
end)

-- Open lazy with <leader>L
map.set("n", "<leader>l", function()
    vim.cmd("Lazy")
end)

-- telescope
local telescope_builtin = require('telescope.builtin')
vim.keymap.set('n', '<leader>pf', telescope_builtin.find_files, {})
vim.keymap.set('n', '<leader>ps', function()
    telescope_builtin.grep_string({ search = vim.fn.input("Grep > ") })
end)
