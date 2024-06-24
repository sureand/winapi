local winapi = require("winapi")

----------------------------

-- 获取鼠标位置
local pos = winapi.GetCursorPos()
print("Current mouse position: x=" .. pos.x .. ", y=" .. pos.y)

-- 设置鼠标位置
winapi.SetCursorPos(100, 100)

-- 模拟鼠标左键点击
winapi.mouse_event(0x02, 0, 0, 0, 0) -- MOUSEEVENTF_LEFTDOWN
winapi.mouse_event(0x04, 0, 0, 0, 0) -- MOUSEEVENTF_LEFTUP

-- 模拟键盘事件
local VK_A = 0x41
winapi.keybd_event(VK_A, 0, 0, 0) -- 按下 'A' 键
winapi.keybd_event(VK_A, 0, 2, 0) -- 释放 'A' 键

-- MapVirtualKey 示例
local scanCode = winapi.MapVirtualKey(VK_A, 0)
print("Scan code for 'A': " .. scanCode)

-------------------------------------

-- 假设你已经获得了窗口句柄 hWnd
local hWnd = 123123
local threadId, processId = winapi.GetWindowThreadProcessId(hWnd)

print("Thread ID: " .. threadId)
print("Process ID: " .. processId)

---------------------------------------------

local PROCESS_ALL_ACCESS = 0x1F0FFF

local processID = 1234 -- 替换为目标进程的ID
local hProcess = winapi.OpenProcess(PROCESS_ALL_ACCESS, false, processID)

-- 分配内存
local mem = winapi.VirtualAllocEx(hProcess, nil, 4096, 0x1000, 0x40) -- MEM_COMMIT, PAGE_EXECUTE_READWRITE

-- 写入数据
local data = "Hello from Lua!"
winapi.WriteProcessMemory(hProcess, mem, data, #data, nil)

-- 获取 LoadLibraryA 的地址
local hKernel32 = winapi.LoadLibrary("kernel32.dll")
local loadLibraryAddr = winapi.GetProcAddress(hKernel32, "LoadLibraryA")

-- 创建远程线程来调用 LoadLibraryA
winapi.CreateRemoteThread(hProcess, nil, 0, loadLibraryAddr, mem, 0, nil)

--------------------------------
-- 提升权限
local success = winapi.EnablePriv()
if success then
    print("权限提升成功")
else
    print("权限提升失败")
end

-- 获取进程ID
local processName = "notepad.exe"
local pid = winapi.GetProcessIDByName(processName)
if pid then
    print("进程 " .. processName .. " 的PID是: " .. pid)
else
    print("未找到进程 " .. processName)
end

--------------------------------

-- 加载库
local hModule = winapi.LoadLibrary("user32.dll")
print("Module Handle: ", hModule)

-- 获取函数地址
local procAddr = winapi.GetProcAddress(hModule, "MessageBoxA")
print("Proc Address: ", procAddr)

------------------

-- 调用 ZwProtectVirtualMemory
local processHandle = winapi.OpenProcess(0x1F0FFF, false, 1234) -- 使用你的进程 ID 替换 1234
local baseAddress = winapi.malloc(4096)
local regionSize = 4096
local newProtect = 0x40 -- PAGE_EXECUTE_READWRITE

local success, oldProtect = winapi.ZwProtectVirtualMemory(processHandle, baseAddress, regionSize, newProtect)
if success then
    print("ZwProtectVirtualMemory succeeded. Old Protect: ", oldProtect)
else
    print("ZwProtectVirtualMemory failed")
end

winapi.free(baseAddress)
--------------------------------


-- 获取当前进程
hProcess = winapi.GetCurrentProcess()
print("Current Process Handle: ", hProcess)

-- 打开进程令牌
local hToken = winapi.OpenProcessToken(hProcess, 0x0020) -- TOKEN_ADJUST_PRIVILEGES
print("Token Handle: ", hToken)

-- 查找特权值
local lowPart, highPart = winapi.LookupPrivilegeValue(nil, "SeDebugPrivilege")
print("LUID: ", lowPart, highPart)

-- 调整令牌特权
local privilegeCount = 1
local attributes = 0x00000002 -- SE_PRIVILEGE_ENABLED
local success = winapi.AdjustTokenPrivileges(hToken, false, privilegeCount, lowPart, highPart, attributes)
if success then
    print("Adjusted Token Privileges successfully")
else
    print("Failed to adjust token privileges")
end

--------------------------------


-- 读取INI文件中的字符串
local section = "Settings"
local key = "Username"
local default_value = "guest"
local file = "config.ini"
local value = winapi.GetPrivateProfileString(section, key, default_value, file)
print("INI 文件中的值: " .. value)

-- 写入INI文件中的字符串
winapi.WritePrivateProfileString(section, key, "admin", file)

-- 读取INI文件中的整数
local int_key = "UserAge"
local default_int = 25
local int_value = winapi.GetPrivateProfileInt(section, int_key, default_int, file)
print("INI 文件中的整数值: " .. int_value)

-- 写入INI文件中的整数
winapi.WritePrivateProfileInt(section, int_key, 30, file)

--------------------------------

-- 打开注册表项
local hKey = winapi.RegOpenKeyEx("Software\\MySoftware")
if hKey then
    -- 读取注册表值
    local regValue = winapi.RegGetValue(hKey, nil, "MyValue")
    print("注册表值: " .. tostring(regValue))

    -- 设置注册表值
    winapi.RegSetValueEx(hKey, "MyValue", winapi.REG_SZ, "newValue")

    -- 关闭注册表项
    winapi.RegCloseKey(hKey)
end