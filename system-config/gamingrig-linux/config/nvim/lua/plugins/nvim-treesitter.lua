return {
    "nvim-treesitter/nvim-treesitter",
    branch = "main",
    build = ":TSUpdate",
    config = function()
        require("nvim-treesitter").install({ "lua", "ruby", "go", "json", "yaml", "markdown" })

        vim.api.nvim_create_autocmd("FileType", {
            pattern = { "lua", "ruby", "go", "json", "yaml", "markdown" },
            callback = function() vim.treesitter.start() end,
        })
    end,
}
