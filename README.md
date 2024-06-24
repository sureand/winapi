# winapi
## 导出Windows的 api 到lua 中

example:

local winapi = require("winapi")

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
