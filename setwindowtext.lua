local winapi = require("winapi")

-- 读取命令行参数
local processTitle = arg[1]  -- 第一个参数：进程的窗口标题
local newTitle = arg[2]  -- 第二个参数：新标题

if not processTitle or not newTitle then
    print("Usage: lua script.lua <process_title> <new_title>")
    return
end

-- 查找窗口
local hwnd = winapi.FindWindow(nil, processTitle)
if not hwnd then
    print("Failed to find window with title:", processTitle)
    return
end
print("Found window with title:", processTitle)

-- 设置新窗口标题
if not winapi.SetWindowText(hwnd, newTitle) then
    print("Failed to set window title to:", newTitle)
else
    print("Successfully set window title to:", newTitle)
end
