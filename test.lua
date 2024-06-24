local winapi = require("winapi")

local function printf(format, ...)
    local s = string.format(format, ...)
    print(s)
end

winapi.export_constants()
printf("PROCESS_ALL_ACCESS:0X%X", PROCESS_ALL_ACCESS)

local processID = 31916 -- 替换为目标进程的ID
local hProcess = winapi.OpenProcess(PROCESS_ALL_ACCESS, false, processID)
print("hProcess", hProcess)