opt = vim.opt

-- Line numbers + rel line number
opt.nu = true
opt.relativenumber = true

-- tabs = 4 space
opt.tabstop = 4
opt.softtabstop = 4
-- the size of an indent
opt.shiftwidth = 4
-- expand tabs into 4 spaces
opt.expandtab = true
-- automatically indent with some extra smartness
opt.smartindent = true

opt.wrap = false

-- make searches better
opt.hlsearch = false
opt.incsearch = true
opt.ignorecase = true

-- better colors
opt.termguicolors = true

-- keep 8 lines at bottom of file when scrolling
opt.scrolloff = 14

-- makes that line at the right
opt.colorcolumn = "84"

-- If this many ms nothing is typed the swap file will be written to disk
opt.updatetime = 100

-- Highlight line at cursor
opt.cursorline = true

-- *** Netrw config
-- Set to 0 to hide banner
vim.g.netrw_banner = 1

-- 0 = default
-- 1 = show filesizes, time stamps etc
-- 2 = idk
-- 3 = tree/expansions
vim.g.netrw_liststyle = 1

-- Human readable file sizes
vim.g.netrw_sizestyle = "H"

-- Sort directories first
vim.g.netrw_sort_sequence = [[[\/]\s]]
