local winapi = require("winapi")

local PROCESS_ALL_ACCESS = 0x1F0FFF
local PAGE_EXECUTE_READWRITE = 0x40

local function get_handle(pid)

    -- 打开进程
    local handle = winapi.OpenProcess(PROCESS_ALL_ACCESS, false, pid)
    if not handle then
        print("Failed to open process with PID", pid)
        return nil
    end

    print("Opened process with PID", pid)
    return handle
end

local function do_cheat(handle, address, value)

    -- 更改内存保护
    local size_word = 4
    local oldProtect = winapi.malloc(size_word)
    local newProtect = PAGE_EXECUTE_READWRITE
    local size = 4  -- 假设要修改 4 字节的值

    if not winapi.VirtualProtectEx(handle, address, size, newProtect, oldProtect) then
        print("Failed to change memory protection")
        winapi.free(oldProtect)
        winapi.CloseHandle(handle)
        return -1
    end
    print("Changed memory protection")

    -- 读取当前值
    local buffer = winapi.malloc(size)
    if not winapi.ReadProcessMemory(handle, address, buffer, size, nil) then
        print("Failed to read process memory")
        winapi.free(buffer)
        winapi.free(oldProtect)
        winapi.CloseHandle(handle)
        return -1
    end

    local currentValue = string.unpack("i", winapi.peek(buffer, size))
    print("Current value at address:", address, "is", currentValue)

    -- 修改值
    local newValue = value
    local newValueBuffer = string.pack("i", newValue)
    if not winapi.WriteProcessMemory(handle, address, newValueBuffer, size, nil) then
        print("Failed to write process memory")
        winapi.free(buffer)
        winapi.free(oldProtect)
        winapi.CloseHandle(handle)
        return -1
    end
    print("Modified value at address:", address, "to", newValue)

    oldProtect = winapi.peek(oldProtect, 4)

    -- 恢复原来的内存保护
    if not winapi.VirtualProtectEx(handle, address, size, oldProtect, nil) then
        print("Failed to restore memory protection")
    end

    -- 释放内存
    winapi.free(buffer)
    winapi.free(oldProtect)

    -- 关闭句柄
    winapi.CloseHandle(handle)

    print("Process handle closed")

    return 0
end

local function cheat(pid, address, value)

    local handle = get_handle(pid)
    if not handle then
        return
    end

    return do_cheat(handle, address, value)
end

-- 读取命令行参数
local pid = tonumber(arg[1])  -- 第一个参数：进程 PID
local address = tonumber(arg[2], 16)  -- 第二个参数：内存地址（16 进制）
local value = tonumber(arg[3])  -- 第三个参数：要写入的新值

if (not pid) or (not address) or (not value) then
    print("Usage: lua script.lua <pid> <address> <new_value>")
    return
end

cheat(pid, address, value)

--使用方法:
-- lua test.lua 1234 0x00400000 42
--lua test.lua 进程pid 地址 新的数值