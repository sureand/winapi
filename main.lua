local winapi = require("winapi")

local function main()

    local className = "SampleWindowClass"
    local windowTitle = "lua windows"
    local width = 800
    local height = 600

    local hwnd = winapi.CreateMainWindow(className, windowTitle, width, height)

    if hwnd == nil then
        print("Failed to create window!")
        return
    end

    winapi.ShowWindow(hwnd, 5)
    winapi.UpdateWindow(hwnd)

    local msg = {}
    while winapi.GetMessage(msg, nil, 0, 0) do
        winapi.TranslateMessage(msg)
        winapi.DispatchMessage(msg)
    end
end

main()
