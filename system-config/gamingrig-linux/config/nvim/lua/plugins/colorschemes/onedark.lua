return {
    "navarasu/onedark.nvim",
    name = "onedark",
    config = function()
        require("onedark").setup({
            style = "cool",
            transparent = true,
            toggle_style_key = "<leader>ts",
            toggle_style_list = { 'dark', 'darker', 'cool', 'deep', 'warm', 'warmer', 'light' }, -- List of styles to toggle between
        })
        vim.cmd("colorscheme onedark")
    end
}
