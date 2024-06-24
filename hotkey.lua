
local winapi = require("winapi")

winapi.MessageBox("hello", "tips", 0)

local VK_RETURN = 0x0D  -- VK_RETURN represents the Enter key

while true do
    local msg = winapi.MSG()
    if winapi.GetMessage(msg, nil, 0, 0) then
        if msg.message == winapi.WM_HOTKEY and msg.wParam == VK_RETURN then
            print("Enter key pressed")
        end
        winapi.TranslateMessage(msg)
        winapi.DispatchMessage(msg)
    end
end
