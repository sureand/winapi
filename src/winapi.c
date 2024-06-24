#include <windows.h>
#include <tlhelp32.h>
#include <winternl.h>
#include <wchar.h>
#include <psapi.h>
#include <stdio.h>
#include <stdlib.h>

#include <lua.h>
#include <lauxlib.h>
#include <lualib.h>
#include "winapi.h"

// 定义需要导出的常量
static const int LUA_PROCESS_VM_OPERATION = PROCESS_VM_OPERATION;
static const int LUA_PROCESS_ALL_ACCESS = PROCESS_ALL_ACCESS;

// Lua C 函数：导出常量
static int lua_export_constants(lua_State *L)
{
    lua_pushinteger(L, LUA_PROCESS_VM_OPERATION);
    lua_setglobal(L, "PROCESS_VM_OPERATION");

    lua_pushinteger(L, LUA_PROCESS_ALL_ACCESS);
    lua_setglobal(L, "PROCESS_ALL_ACCESS");

    return 0;
}

// 封装 MessageBox 函数
static int lua_MessageBoxA(lua_State *L) {

    const char *message = luaL_checkstring(L, 1);
    const char *title = luaL_checkstring(L, 2);

    MessageBox(NULL, message, title, MB_OK);

    return 0;
}

static int lua_MessageBox(lua_State *L)
{
    size_t title_len, text_len;
    const char *message = luaL_checklstring(L, 1, &text_len);
    const char *title = luaL_checklstring(L, 2, &title_len);
    UINT type = luaL_checkinteger(L, 3);

    // Convert UTF-8 strings to wide strings
    int wtitle_len = MultiByteToWideChar(CP_UTF8, 0, title, title_len, NULL, 0);
    int wtext_len = MultiByteToWideChar(CP_UTF8, 0, message, text_len, NULL, 0);

    wchar_t *wtitle = (wchar_t *)malloc((wtitle_len + 1) * sizeof(wchar_t));
    wchar_t *wtext = (wchar_t *)malloc((wtext_len + 1) * sizeof(wchar_t));

    MultiByteToWideChar(CP_UTF8, 0, title, title_len, wtitle, wtitle_len);
    MultiByteToWideChar(CP_UTF8, 0, message, text_len, wtext, wtext_len);

    wtitle[wtitle_len] = L'\0';
    wtext[wtext_len] = L'\0';

    int result = MessageBoxW(NULL, wtext, wtitle, type);

    free(wtitle);
    free(wtext);

    lua_pushinteger(L, result);

    return 1;
}

// 封装 GetCurrentDirectory
static int lua_GetCurrentDirectory(lua_State *L)
{
    char buffer[MAX_PATH];

    DWORD length = GetCurrentDirectory(MAX_PATH, buffer);
    if (length > 0 && length < MAX_PATH) {
        lua_pushstring(L, buffer);
    } else {
        lua_pushnil(L);
    }

    return 1;
}

static int lua_FindWindow(lua_State *L)
{
    const char *className = luaL_optstring(L, 1, NULL);
    const char *windowName = luaL_optstring(L, 2, NULL);

    HWND hWnd = FindWindow(className, windowName);
    lua_pushlightuserdata(L, hWnd);

    return 1;
}

static int lua_SetWindowText(lua_State *L)
{
    HWND hWnd = (HWND)lua_touserdata(L, 1);
    const char *newTitle = luaL_checkstring(L, 2);
    BOOL result = SetWindowText(hWnd, newTitle);
    lua_pushboolean(L, result);

    return 1;
}

// Lua导出函数，用于枚举系统中的进程ID
int lua_EnumProcesses(lua_State *L)
{
    DWORD aProcesses[1024], cbNeeded, cProcesses;
    unsigned int i;

    if (!EnumProcesses(aProcesses, sizeof(aProcesses), &cbNeeded)) {
        lua_pushnil(L); // 返回空值表示失败
        return 1; // 返回一个结果值
    }

    cProcesses = cbNeeded / sizeof(DWORD);

    lua_newtable(L); // 创建一个新的Lua表，用于存储进程ID

    for (i = 0; i < cProcesses; i++) {
        lua_pushinteger(L, i + 1);
        lua_pushinteger(L, aProcesses[i]);
        lua_settable(L, -3);
    }

    return 1; // 返回一个结果值
}

static int lua_OpenProcess(lua_State *L)
{
    DWORD dwDesiredAccess = (DWORD)lua_tointeger(L, 1);
    BOOL bInheritHandle = (BOOL)lua_toboolean(L, 2);
    DWORD dwProcessId = (DWORD)lua_tointeger(L, 3);

    HANDLE hProcess = OpenProcess(dwDesiredAccess, bInheritHandle, dwProcessId);
    if (hProcess == NULL)
    {
        lua_pushnil(L);
        lua_pushstring(L, "Failed to open process");
    }
    else
    {
        lua_pushlightuserdata(L, hProcess);
    }
    return 1; // 返回值数量
}

// Lua C 函数：获取指定进程的名字
static int lua_GetProcessName(lua_State *L)
{
    DWORD pid = luaL_checkinteger(L, 1);
    HANDLE hProcess;
    CHAR szProcessName[MAX_PATH] = "";

    hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, pid);
    if (hProcess != NULL) {
        if (GetModuleFileNameExA(hProcess, NULL, szProcessName, MAX_PATH) != 0) {
            lua_pushstring(L, szProcessName);
        } else {
            lua_pushnil(L);
        }
        CloseHandle(hProcess);
    } else {
        lua_pushnil(L);
    }

    return 1;
}

// Lua导出函数，用于修改指定进程内存的保护属性
static int lua_VirtualProtectEx(lua_State *L)
{
    HANDLE hProcess = (HANDLE)luaL_checkudata(L, 1, "HANDLE"); // 第一个参数：进程句柄
    LPVOID lpAddress = luaL_checkudata(L, 2, NULL); // 第二个参数：要修改的内存地址
    SIZE_T dwSize = luaL_checkinteger(L, 3); // 第三个参数：内存区域的大小
    DWORD flNewProtect = luaL_checkinteger(L, 4); // 第四个参数：新的保护属性

    DWORD oldProtect;
    BOOL result = VirtualProtectEx(hProcess, lpAddress, dwSize, flNewProtect, &oldProtect);
    if (result) {
        lua_pushinteger(L, oldProtect); // 返回旧的保护属性
        return 1; // 返回一个结果值
    } else {
        lua_pushnil(L); // 返回空值表示失败
        return 1; // 返回一个结果值
    }
}

// Lua导出函数，用于读取指定进程内存
static int lua_ReadProcessMemory(lua_State *L)
{
    HANDLE hProcess = (HANDLE)luaL_checkudata(L, 1, "HANDLE"); // 第一个参数：进程句柄
    LPCVOID lpBaseAddress = luaL_checkudata(L, 2, NULL); // 第二个参数：要读取的内存地址
    SIZE_T nSize = luaL_checkinteger(L, 3); // 第三个参数：要读取的字节数

    BYTE *buffer = (BYTE *)malloc(nSize);
    SIZE_T bytesRead = 0;
    BOOL result = ReadProcessMemory(hProcess, lpBaseAddress, buffer, nSize, &bytesRead);
    if (result) {
        lua_pushlstring(L, (const char *)buffer, bytesRead); // 将读取的数据作为字符串返回
        free(buffer);
        return 1;
    } else {
        free(buffer);
        lua_pushnil(L);
        return 1;
    }
}

// Lua导出函数，用于写入指定进程内存
static int lua_WriteProcessMemory(lua_State *L)
{
    HANDLE hProcess = (HANDLE)luaL_checkudata(L, 1, "HANDLE"); // 第一个参数：进程句柄
    LPVOID lpBaseAddress = luaL_checkudata(L, 2, NULL); // 第二个参数：要写入的内存地址
    size_t nSize;
    const char *lpBuffer = luaL_checklstring(L, 3, &nSize); // 第三个参数：要写入的数据
    SIZE_T nBytesToWrite = luaL_checkinteger(L, 4); // 第四个参数：要写入的字节数

    SIZE_T bytesWritten = 0;
    BOOL result = WriteProcessMemory(hProcess, lpBaseAddress, lpBuffer, nBytesToWrite, &bytesWritten);
    if (result) {
        lua_pushinteger(L, bytesWritten);
        return 1;
    } else {
        lua_pushnil(L);
        return 1;
    }
}

static int lua_malloc(lua_State *L)
{
    size_t size = luaL_checkinteger(L, 1);
    void *ptr = malloc(size);
    lua_pushlightuserdata(L, ptr);
    return 1;
}

static int lua_free(lua_State *L)
{
    void *ptr = lua_touserdata(L, 1);
    free(ptr);

    return 0;
}

static int lua_peek(lua_State *L)
{
    void *ptr = lua_touserdata(L, 1);
    size_t size = luaL_checkinteger(L, 2);
    lua_pushlstring(L, ptr, size);

    return 1;
}

static int lua_ShellExecute(lua_State *L)
{
    HWND hwnd = (HWND)lua_touserdata(L, 1); // 第一个参数：窗口句柄
    const char *operation = luaL_optstring(L, 2, NULL); // 第二个参数：操作
    const char *file = luaL_checkstring(L, 3); // 第三个参数：文件
    const char *parameters = luaL_optstring(L, 4, NULL); // 第四个参数：参数
    const char *directory = luaL_optstring(L, 5, NULL); // 第五个参数：目录
    int showCmd = luaL_optinteger(L, 6, SW_SHOWNORMAL); // 第六个参数：显示命令

    HINSTANCE result = ShellExecute(hwnd, operation, file, parameters, directory, showCmd);

    // 将结果转换为 int 并推入 Lua 堆栈
    lua_pushinteger(L, (int)result);

    // 返回一个值
    return 1;
}

static int lua_GetCursorPos(lua_State *L)
{
    POINT pt;
    if (GetCursorPos(&pt)) {
        lua_newtable(L);
        lua_pushinteger(L, pt.x);
        lua_setfield(L, -2, "x");
        lua_pushinteger(L, pt.y);
        lua_setfield(L, -2, "y");
        return 1;
    } else {
        lua_pushnil(L);
        return 1;
    }
}

static int lua_SetCursorPos(lua_State *L)
{
    int x = luaL_checkinteger(L, 1);
    int y = luaL_checkinteger(L, 2);
    BOOL result = SetCursorPos(x, y);
    lua_pushboolean(L, result);

    return 1;
}

static int lua_mouse_event(lua_State *L)
{
    DWORD dwFlags = luaL_checkinteger(L, 1);
    DWORD dx = luaL_optinteger(L, 2, 0);
    DWORD dy = luaL_optinteger(L, 3, 0);
    DWORD dwData = luaL_optinteger(L, 4, 0);
    DWORD dwExtraInfo = luaL_optinteger(L, 5, 0);
    mouse_event(dwFlags, dx, dy, dwData, dwExtraInfo);

    return 0;
}

static int lua_MapVirtualKey(lua_State *L)
{
    UINT uCode = luaL_checkinteger(L, 1);
    UINT uMapType = luaL_checkinteger(L, 2);
    UINT result = MapVirtualKey(uCode, uMapType);
    lua_pushinteger(L, result);

    return 1;
}

static int lua_keybd_event(lua_State *L)
{
    BYTE bVk = luaL_checkinteger(L, 1);
    BYTE bScan = luaL_optinteger(L, 2, 0);
    DWORD dwFlags = luaL_optinteger(L, 3, 0);
    DWORD dwExtraInfo = luaL_optinteger(L, 4, 0);
    keybd_event(bVk, bScan, dwFlags, dwExtraInfo);

    return 0;
}

static int lua_GetWindowThreadProcessId(lua_State *L)
{
    HWND hWnd = (HWND)lua_touserdata(L, 1); // 获取传入的 HWND 参数
    DWORD processId;
    DWORD threadId = GetWindowThreadProcessId(hWnd, &processId);

    lua_pushinteger(L, threadId);   // 返回线程 ID
    lua_pushinteger(L, processId);  // 返回进程 ID

    return 2;
}

// 封装 LoadLibrary 函数
static int lua_LoadLibrary(lua_State *L)
{
    const char *libName = luaL_checkstring(L, 1);
    HMODULE hModule = LoadLibrary(libName);

    lua_pushlightuserdata(L, hModule);

    return 1;
}

static int lua_GetProcAddress(lua_State *L)
{
    HMODULE hModule = (HMODULE)lua_touserdata(L, 1);
    const char *procName = luaL_checkstring(L, 2);
    FARPROC procAddr = GetProcAddress(hModule, procName);

    lua_pushlightuserdata(L, (void*)procAddr);

    return 1;
}

typedef NTSTATUS (NTAPI *ZwProtectVirtualMemory_t)(
    HANDLE ProcessHandle,
    PVOID *BaseAddress,
    PULONG RegionSize,
    ULONG NewProtect,
    PULONG OldProtect
);

static int lua_ZwProtectVirtualMemory(lua_State *L)
{
    HANDLE hProcess = (HANDLE)lua_touserdata(L, 1);
    PVOID baseAddress = (PVOID)lua_touserdata(L, 2);
    ULONG regionSize = (ULONG)luaL_checkinteger(L, 3);
    ULONG newProtect = (ULONG)luaL_checkinteger(L, 4);
    ULONG oldProtect;

    HMODULE hNtDll = GetModuleHandle("ntdll.dll");
    if (hNtDll == NULL) {
        lua_pushnil(L);
        lua_pushstring(L, "Failed to get handle of ntdll.dll");
        return 2;
    }

    ZwProtectVirtualMemory_t ZwProtectVirtualMemory = (ZwProtectVirtualMemory_t)GetProcAddress(hNtDll, "ZwProtectVirtualMemory");
    if (ZwProtectVirtualMemory == NULL) {
        lua_pushnil(L);
        lua_pushstring(L, "Failed to get address of ZwProtectVirtualMemory");
        return 2;
    }

    NTSTATUS status = ZwProtectVirtualMemory(hProcess, &baseAddress, &regionSize, newProtect, &oldProtect);
    if (status != 0) {
        lua_pushnil(L);
        lua_pushstring(L, "ZwProtectVirtualMemory failed");
        return 2;
    }

    lua_pushboolean(L, 1);
    lua_pushinteger(L, oldProtect);

    return 2;
}

static int lua_GetCurrentProcess(lua_State *L)
{
    HANDLE hProcess = GetCurrentProcess();
    lua_pushlightuserdata(L, hProcess);

    return 1;
}

static int lua_OpenProcessToken(lua_State *L)
{
    HANDLE hProcess = (HANDLE)lua_touserdata(L, 1);
    DWORD desiredAccess = luaL_checkinteger(L, 2);
    HANDLE hToken;

    if (OpenProcessToken(hProcess, desiredAccess, &hToken)) {
        lua_pushlightuserdata(L, hToken);
    } else {
        lua_pushnil(L);
    }

    return 1;
}

static int lua_LookupPrivilegeValue(lua_State *L)
{
    const char *systemName = luaL_optstring(L, 1, NULL);
    const char *name = luaL_checkstring(L, 2);
    LUID luid;

    if (LookupPrivilegeValue(systemName, name, &luid)) {
        lua_pushinteger(L, luid.LowPart);
        lua_pushinteger(L, luid.HighPart);
    } else {
        lua_pushnil(L);
        lua_pushnil(L);
    }

    return 2;
}

static int lua_AdjustTokenPrivileges(lua_State *L)
{
    HANDLE hToken = (HANDLE)lua_touserdata(L, 1);
    BOOL disableAllPrivileges = lua_toboolean(L, 2);
    TOKEN_PRIVILEGES newState;
    TOKEN_PRIVILEGES previousState;
    DWORD returnLength;

    newState.PrivilegeCount = luaL_checkinteger(L, 3);
    newState.Privileges[0].Luid.LowPart = luaL_checkinteger(L, 4);
    newState.Privileges[0].Luid.HighPart = luaL_checkinteger(L, 5);
    newState.Privileges[0].Attributes = luaL_checkinteger(L, 6);

    if (AdjustTokenPrivileges(hToken, disableAllPrivileges, &newState, sizeof(previousState), &previousState, &returnLength)) {
        lua_pushboolean(L, 1);
    } else {
        lua_pushboolean(L, 0);
    }

    return 1;
}

static int lua_CloseHandle(lua_State *L)
{
    HANDLE hObject = (HANDLE)lua_touserdata(L, 1);
    if (CloseHandle(hObject)) {
        lua_pushboolean(L, 1);
    } else {
        lua_pushboolean(L, 0);
    }

    return 1;
}

static int lua_EnableDebugPrivilege(lua_State *L)
{
    BOOL fEnable = lua_toboolean(L, 1);
    HANDLE hToken;

    if (OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES, &hToken)) {
        TOKEN_PRIVILEGES tp;
        tp.PrivilegeCount = 1;
        LookupPrivilegeValue(NULL, SE_DEBUG_NAME, &tp.Privileges[0].Luid);
        tp.Privileges[0].Attributes = fEnable ? SE_PRIVILEGE_ENABLED : 0;
        AdjustTokenPrivileges(hToken, FALSE, &tp, sizeof(tp), NULL, NULL);
        CloseHandle(hToken);
    } else {
        lua_pushboolean(L, 0);
        return 1;
    }
    lua_pushboolean(L, GetLastError() == ERROR_SUCCESS);

    return 1;
}

// 线程启动函数
DWORD WINAPI ThreadFunc(LPVOID lpParam)
{
    lua_State *L = (lua_State *)lpParam;

    if (lua_pcall(L, 0, LUA_MULTRET, 0) != LUA_OK) {
        const char *error = lua_tostring(L, -1);
        printf("Error in thread: %s\n", error);
        lua_pop(L, 1);
    }

    return 0;
}

// 封装 CreateThread 函数
static int lua_CreateThread(lua_State *L)
{
    luaL_checktype(L, 1, LUA_TFUNCTION);

    lua_State *L1 = luaL_newstate();
    luaL_openlibs(L1);

    lua_pushvalue(L, 1);
    lua_xmove(L, L1, 1);

    DWORD threadId;
    HANDLE hThread = CreateThread(
        NULL,
        0,
        ThreadFunc,
        L1,
        0,
        &threadId
    );

    if (hThread == NULL) {
        lua_pushnil(L);
    } else {
        lua_pushlightuserdata(L, hThread);
    }
    return 1;
}

// 封装 SetThreadPriority 函数
static int lua_SetThreadPriority(lua_State *L)
{
    HANDLE hThread = (HANDLE)lua_touserdata(L, 1);
    int priority = luaL_checkinteger(L, 2);

    if (SetThreadPriority(hThread, priority)) {
        lua_pushboolean(L, 1);
    } else {
        lua_pushboolean(L, 0);
    }
    return 1;
}

// 封装 TerminateThread 函数
static int lua_TerminateThread(lua_State *L)
{
    HANDLE hThread = (HANDLE)lua_touserdata(L, 1);
    DWORD exitCode = luaL_checkinteger(L, 2);

    if (TerminateThread(hThread, exitCode)) {
        lua_pushboolean(L, 1);
    } else {
        lua_pushboolean(L, 0);
    }

    return 1;
}

static int lua_RegisterHotKey(lua_State *L)
{
    HWND hWnd = (HWND)lua_touserdata(L, 1);
    int id = luaL_checkinteger(L, 2);
    UINT fsModifiers = luaL_checkinteger(L, 3);
    UINT vk = luaL_checkinteger(L, 4);

    BOOL result = RegisterHotKey(hWnd, id, fsModifiers, vk);

    lua_pushboolean(L, result);

    return 1;
}

static int lua_UnregisterHotKey(lua_State *L)
{
    HWND hWnd = (HWND)lua_touserdata(L, 1);
    int id = luaL_checkinteger(L, 2);

    BOOL result = UnregisterHotKey(hWnd, id);

    lua_pushboolean(L, result);

    return 1;
}

// 封装 VirtualAllocEx
static int lua_VirtualAllocEx(lua_State *L)
{
    HANDLE hProcess = (HANDLE)lua_touserdata(L, 1);
    LPVOID lpAddress = (LPVOID)lua_touserdata(L, 2);
    SIZE_T dwSize = (SIZE_T)luaL_checkinteger(L, 3);
    DWORD flAllocationType = (DWORD)luaL_checkinteger(L, 4);
    DWORD flProtect = (DWORD)luaL_checkinteger(L, 5);

    LPVOID result = VirtualAllocEx(hProcess, lpAddress, dwSize, flAllocationType, flProtect);
    lua_pushlightuserdata(L, result);

    return 1;
}

// 封装 CreateRemoteThread
static int lua_CreateRemoteThread(lua_State *L)
{
    HANDLE hProcess = (HANDLE)lua_touserdata(L, 1);
    LPSECURITY_ATTRIBUTES lpThreadAttributes = NULL;
    SIZE_T dwStackSize = 0;
    LPTHREAD_START_ROUTINE lpStartAddress = (LPTHREAD_START_ROUTINE)lua_touserdata(L, 2);
    LPVOID lpParameter = (LPVOID)lua_touserdata(L, 3);
    DWORD dwCreationFlags = (DWORD)luaL_checkinteger(L, 4);
    LPDWORD lpThreadId = NULL;

    HANDLE result = CreateRemoteThread(hProcess, lpThreadAttributes, dwStackSize, lpStartAddress, lpParameter, dwCreationFlags, lpThreadId);
    lua_pushlightuserdata(L, result);

    return 1;
}

// 封装提权
static int lua_EnablePriv(lua_State *L)
{
    HANDLE hToken;
    if (OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken)) {
        TOKEN_PRIVILEGES tkp;
        LookupPrivilegeValue(NULL, SE_DEBUG_NAME, &tkp.Privileges[0].Luid);
        tkp.PrivilegeCount = 1;
        tkp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
        AdjustTokenPrivileges(hToken, FALSE, &tkp, sizeof(tkp), NULL, NULL);
        CloseHandle(hToken);
    }
    lua_pushboolean(L, GetLastError() == ERROR_SUCCESS);

    return 1;
}

static int lua_GetProcessIDByName(lua_State *L)
{
    const char *name = luaL_checkstring(L, 1);

    int wlen = MultiByteToWideChar(CP_UTF8, 0, name, -1, NULL, 0);
    if (wlen == 0) {
        lua_pushnil(L);
        return 1;
    }

    WCHAR *wName = (WCHAR *)malloc(wlen * sizeof(WCHAR));
    if (!MultiByteToWideChar(CP_UTF8, 0, name, -1, wName, wlen)) {
        free(wName);
        lua_pushnil(L);
        return 1;
    }

    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnapshot == INVALID_HANDLE_VALUE) {
        free(wName);
        lua_pushnil(L);
        return 1;
    }

    PROCESSENTRY32 pe = { sizeof(pe) };
    BOOL ret = Process32First(hSnapshot, &pe);
    DWORD processID = 0;
    while (ret) {
        WCHAR szExeFile[MAX_PATH];
        MultiByteToWideChar(CP_UTF8, 0, pe.szExeFile, -1, szExeFile, MAX_PATH);

        if (lstrcmpiW(szExeFile, wName) == 0) {
            processID = pe.th32ProcessID;
            break;
        }
        ret = Process32Next(hSnapshot, &pe);
    }

    free(wName);
    CloseHandle(hSnapshot);

    if (processID != 0) {
        lua_pushinteger(L, processID);
    } else {
        lua_pushnil(L);
    }

    return 1;
}

typedef NTSTATUS (NTAPI *NTQUERYINFORMATIONTHREAD)(
    HANDLE, THREADINFOCLASS, PVOID, ULONG, PULONG
);

typedef struct _THREAD_BASIC_INFORMATION
{
    NTSTATUS                ExitStatus;
    PVOID                   TebBaseAddress;
    CLIENT_ID               ClientId;
    KAFFINITY               AffinityMask;
    KPRIORITY               Priority;
    KPRIORITY               BasePriority;
} THREAD_BASIC_INFORMATION, *PTHREAD_BASIC_INFORMATION;

static int lua_GetThreadStartAddress(lua_State *L)
{
    DWORD tid = luaL_checkinteger(L, 1);
    HANDLE hThread = OpenThread(THREAD_QUERY_INFORMATION, FALSE, tid);
    if (!hThread) {
        lua_pushnil(L);
        return 1;
    }

    THREAD_BASIC_INFORMATION tbi;
    ULONG returnLength;
    NTSTATUS status = NtQueryInformationThread(hThread, (THREADINFOCLASS)0, &tbi, sizeof(tbi), &returnLength);
    CloseHandle(hThread);

    if (status != 0) {
        lua_pushnil(L);
        return 1;
    }

    lua_pushinteger(L, (DWORD_PTR)tbi.TebBaseAddress);

    return 1;
}

static int lua_EnumThread(lua_State *L)
{
    DWORD dwOwnerPID = luaL_checkinteger(L, 1);
    HANDLE hThreadSnap = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
    if (hThreadSnap == INVALID_HANDLE_VALUE) {
        lua_pushnil(L);
        return 1;
    }

    THREADENTRY32 te32;
    te32.dwSize = sizeof(THREADENTRY32);

    if (!Thread32First(hThreadSnap, &te32)) {
        CloseHandle(hThreadSnap);
        lua_pushnil(L);
        return 1;
    }

    lua_newtable(L);
    int index = 1;
    do {
        if (te32.th32OwnerProcessID == dwOwnerPID) {
            lua_pushinteger(L, te32.th32ThreadID);
            lua_rawseti(L, -2, index++);
        }
    } while (Thread32Next(hThreadSnap, &te32));

    CloseHandle(hThreadSnap);

    return 1;
}

// 读取ini
static int lua_GetPrivateProfileString(lua_State *L)
{
    const char *section = luaL_checkstring(L, 1);
    const char *key = luaL_checkstring(L, 2);
    const char *default_value = luaL_optstring(L, 3, "");
    const char *file = luaL_checkstring(L, 4);
    char buffer[1024];
    GetPrivateProfileString(section, key, default_value, buffer, sizeof(buffer), file);
    lua_pushstring(L, buffer);

    return 1;
}

// 写ini
static int lua_WritePrivateProfileString(lua_State *L)
{
    const char *section = luaL_checkstring(L, 1);
    const char *key = luaL_checkstring(L, 2);
    const char *value = luaL_checkstring(L, 3);
    const char *file = luaL_checkstring(L, 4);
    BOOL result = WritePrivateProfileString(section, key, value, file);
    lua_pushboolean(L, result);

    return 1;
}

static int lua_GetPrivateProfileInt(lua_State *L)
{
    const char *section = luaL_checkstring(L, 1);
    const char *key = luaL_checkstring(L, 2);
    int default_value = luaL_optinteger(L, 3, 0);
    const char *file = luaL_checkstring(L, 4);
    int result = GetPrivateProfileInt(section, key, default_value, file);
    lua_pushinteger(L, result);

    return 1;
}

static int lua_WritePrivateProfileInt(lua_State *L)
{
    const char *section = luaL_checkstring(L, 1);
    const char *key = luaL_checkstring(L, 2);
    int value = luaL_checkinteger(L, 3);
    const char *file = luaL_checkstring(L, 4);
    char buffer[16];
    snprintf(buffer, sizeof(buffer), "%d", value);
    BOOL result = WritePrivateProfileString(section, key, buffer, file);
    lua_pushboolean(L, result);

    return 1;
}

// 注册表
static int lua_RegOpenKeyEx(lua_State *L)
{
    HKEY hKey;
    const char *subKey = luaL_checkstring(L, 1);
    DWORD ulOptions = luaL_optinteger(L, 2, 0);
    REGSAM samDesired = luaL_optinteger(L, 3, KEY_READ);
    if (RegOpenKeyEx(HKEY_CURRENT_USER, subKey, ulOptions, samDesired, &hKey) == ERROR_SUCCESS) {
        lua_pushlightuserdata(L, hKey);
    } else {
        lua_pushnil(L);
    }
    return 1;
}

static int lua_RegCloseKey(lua_State *L)
{
    HKEY hKey = (HKEY)lua_touserdata(L, 1);
    if (hKey != NULL) {
        RegCloseKey(hKey);
    }
    return 0;
}

static int lua_RegGetValue(lua_State *L)
{
    HKEY hKey = (HKEY)lua_touserdata(L, 1);
    const char *subKey = luaL_checkstring(L, 2);
    const char *value = luaL_checkstring(L, 3);
    DWORD type, size = 1024;
    BYTE data[1024];
    if (RegGetValue(hKey, subKey, value, RRF_RT_ANY, &type, data, &size) == ERROR_SUCCESS) {
        if (type == REG_SZ) {
            lua_pushstring(L, (char*)data);
        } else if (type == REG_DWORD) {
            lua_pushinteger(L, *(DWORD*)data);
        } else {
            lua_pushnil(L);
        }
    } else {
        lua_pushnil(L);
    }
    return 1;
}

static int lua_RegSetValueEx(lua_State *L)
{
    HKEY hKey = (HKEY)lua_touserdata(L, 1);
    const char *value = luaL_checkstring(L, 2);
    DWORD type = luaL_checkinteger(L, 3);
    if (type == REG_SZ) {
        const char *data = luaL_checkstring(L, 4);
        RegSetValueEx(hKey, value, 0, type, (const BYTE*)data, strlen(data) + 1);
    } else if (type == REG_DWORD) {
        DWORD data = luaL_checkinteger(L, 4);
        RegSetValueEx(hKey, value, 0, type, (const BYTE*)&data, sizeof(data));
    }
    return 0;
}

static int lua_EnablePrivilege(lua_State *L)
{
    const char *privilege = luaL_checkstring(L, 1);
    BOOL enable = lua_toboolean(L, 2);

    HANDLE hToken;
    if (OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES, &hToken)) {
        TOKEN_PRIVILEGES tkp;
        LookupPrivilegeValue(NULL, privilege, &tkp.Privileges[0].Luid);
        tkp.PrivilegeCount = 1;
        tkp.Privileges[0].Attributes = enable ? SE_PRIVILEGE_ENABLED : 0;
        AdjustTokenPrivileges(hToken, FALSE, &tkp, sizeof(tkp), NULL, NULL);
        CloseHandle(hToken);
        lua_pushboolean(L, GetLastError() == ERROR_SUCCESS);
    } else {
        lua_pushboolean(L, FALSE);
    }
    return 1;
}

static int lua_InjectDLL(lua_State *L)
{
    DWORD pid = luaL_checkinteger(L, 1);
    const char *dllPath = luaL_checkstring(L, 2);

    HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
    if (hProcess == NULL) {
        lua_pushboolean(L, FALSE);
        return 1;
    }

    LPVOID pRemoteBuf = VirtualAllocEx(hProcess, NULL, strlen(dllPath) + 1, MEM_COMMIT, PAGE_READWRITE);
    if (pRemoteBuf == NULL) {
        CloseHandle(hProcess);
        lua_pushboolean(L, FALSE);
        return 1;
    }

    if (!WriteProcessMemory(hProcess, pRemoteBuf, (LPVOID)dllPath, strlen(dllPath) + 1, NULL)) {
        VirtualFreeEx(hProcess, pRemoteBuf, 0, MEM_RELEASE);
        CloseHandle(hProcess);
        lua_pushboolean(L, FALSE);
        return 1;
    }

    HMODULE hKernel32 = GetModuleHandle("kernel32.dll");
    LPVOID pLoadLibraryA = (LPVOID)GetProcAddress(hKernel32, "LoadLibraryA");
    if (pLoadLibraryA == NULL) {
        VirtualFreeEx(hProcess, pRemoteBuf, 0, MEM_RELEASE);
        CloseHandle(hProcess);
        lua_pushboolean(L, FALSE);
        return 1;
    }

    HANDLE hThread = CreateRemoteThread(hProcess, NULL, 0, (LPTHREAD_START_ROUTINE)pLoadLibraryA, pRemoteBuf, 0, NULL);
    if (hThread == NULL) {
        VirtualFreeEx(hProcess, pRemoteBuf, 0, MEM_RELEASE);
        CloseHandle(hProcess);
        lua_pushboolean(L, FALSE);
        return 1;
    }

    WaitForSingleObject(hThread, INFINITE);
    VirtualFreeEx(hProcess, pRemoteBuf, 0, MEM_RELEASE);
    CloseHandle(hThread);
    CloseHandle(hProcess);

    lua_pushboolean(L, TRUE);

    return 1;
}

static int lua_EnumDrives(lua_State *L)
{
    char buffer[256];
    DWORD result = GetLogicalDriveStrings(sizeof(buffer), buffer);
    if (result == 0 || result > sizeof(buffer)) {
        lua_pushnil(L);
        return 1;
    }

    lua_newtable(L);
    char *drive = buffer;
    int index = 1;
    while (*drive) {
        UINT type = GetDriveType(drive);
        lua_pushstring(L, drive);
        lua_newtable(L);

        lua_pushstring(L, "path");
        lua_pushstring(L, drive);
        lua_settable(L, -3);

        lua_pushstring(L, "type");
        switch (type) {
            case DRIVE_UNKNOWN:
                lua_pushstring(L, "UNKNOWN");
                break;
            case DRIVE_NO_ROOT_DIR:
                lua_pushstring(L, "NO_ROOT_DIR");
                break;
            case DRIVE_REMOVABLE:
                lua_pushstring(L, "REMOVABLE");
                break;
            case DRIVE_FIXED:
                lua_pushstring(L, "FIXED");
                break;
            case DRIVE_REMOTE:
                lua_pushstring(L, "REMOTE");
                break;
            case DRIVE_CDROM:
                lua_pushstring(L, "CDROM");
                break;
            case DRIVE_RAMDISK:
                lua_pushstring(L, "RAMDISK");
                break;
            default:
                lua_pushstring(L, "UNKNOWN");
        }
        lua_settable(L, -3);

        lua_rawseti(L, -2, index++);
        drive += strlen(drive) + 1;
    }

    return 1;
}

// 封装 TranslateMessage
static int lua_TranslateMessage(lua_State *L)
{
    MSG *msg = (MSG *)lua_touserdata(L, 1);
    int result = TranslateMessage(msg);
    lua_pushboolean(L, result);

    return 1;
}

// 封装 DispatchMessage
static int lua_DispatchMessage(lua_State *L)
{
    MSG *msg = (MSG *)lua_touserdata(L, 1);
    LRESULT result = DispatchMessage(msg);
    lua_pushinteger(L, result);

    return 1;
}

// 封装 GetMessage
static int lua_GetMessage(lua_State *L)
{
    MSG *msg = (MSG *)malloc(sizeof(MSG));
    HWND hwnd = (HWND)lua_touserdata(L, 1);
    UINT filterMin = (UINT)lua_tointeger(L, 2);
    UINT filterMax = (UINT)lua_tointeger(L, 3);
    int result = GetMessage(msg, hwnd, filterMin, filterMax);
    lua_pushboolean(L, result);
    lua_pushlightuserdata(L, msg);

    free(msg);

    return 2;
}

static int lua_ListAPIFunctions(lua_State *L)
{
    luaL_checktype(L, 1, LUA_TTABLE);

    lua_pushnil(L);
    while (lua_next(L, 1) != 0) {
        if (lua_isfunction(L, -1)) {
            const char *name = lua_tostring(L, -2);
            lua_pushstring(L, name);
            lua_pushboolean(L, 1);
            lua_settable(L, 2);
        }
        lua_pop(L, 1);
    }

    return 0;
}

LRESULT CALLBACK WindowProc(HWND hwnd, UINT uMsg, WPARAM wParam, LPARAM lParam)
{
    switch (uMsg)
    {
    case WM_DESTROY:
        PostQuitMessage(0);
        return 0;

    case WM_PAINT:
        {
            PAINTSTRUCT ps;
            HDC hdc = BeginPaint(hwnd, &ps);

            FillRect(hdc, &ps.rcPaint, (HBRUSH) (COLOR_WINDOW+1));

            EndPaint(hwnd, &ps);
        }
        return 0;

    }
    return DefWindowProc(hwnd, uMsg, wParam, lParam);
}

HWND CreateMainWindow(const wchar_t *className, const wchar_t *windowTitle, int width, int height)
{
    WNDCLASS wc = {0};
    wc.lpfnWndProc = WindowProc; // 设置窗口过程
    wc.hInstance = GetModuleHandle(NULL);
    wc.lpszClassName = className; // 类名
    RegisterClass(&wc);
    return CreateWindow(
        className, windowTitle,
        WS_OVERLAPPEDWINDOW,
        CW_USEDEFAULT, CW_USEDEFAULT, width, height,
        NULL, NULL, GetModuleHandle(NULL), NULL
    );
}

static int l_CreateMainWindow(lua_State *L)
{
    const wchar_t *className = NULL;
    const wchar_t *windowTitle = NULL;
    int width = 0;
    int height = 0;

    if (lua_gettop(L) < 4 || !lua_isstring(L, 1) || !lua_isstring(L, 2) || !lua_isinteger(L, 3) || !lua_isinteger(L, 4)) {
        lua_pushnil(L);
        lua_pushstring(L, "Invalid arguments");
        return 2;
    }

    className = (const wchar_t *)lua_tostring(L, 1);
    windowTitle = (const wchar_t *)lua_tostring(L, 2);
    width = lua_tointeger(L, 3);
    height = lua_tointeger(L, 4);

    HWND hwnd = CreateMainWindow(className, windowTitle, width, height);
    lua_pushlightuserdata(L, hwnd);
    return 1;
}

static int l_ShowWindow(lua_State *L)
{
    HWND hwnd = (HWND)lua_touserdata(L, 1);
    int nCmdShow = lua_tointeger(L, 2);
    BOOL result = ShowWindow(hwnd, nCmdShow);

    lua_pushboolean(L, result);

    return 1;
}

static int l_UpdateWindow(lua_State *L)
{
    HWND hwnd = (HWND)lua_touserdata(L, 1);
    BOOL result = UpdateWindow(hwnd);
    lua_pushboolean(L, result);

    return 1;
}

// 注册模块函数
static const struct luaL_Reg winapi[] = {

    {"export_constants", lua_export_constants},
    {"MessageBoxA", lua_MessageBoxA},
    {"MessageBox", lua_MessageBox},
    {"GetCurrentDirectory", lua_GetCurrentDirectory},
    {"EnumProcesses", lua_EnumProcesses},
    {"OpenProcess", lua_OpenProcess},
    {"GetProcessName", lua_GetProcessName},
    {"VirtualProtectEx", lua_VirtualProtectEx},
    {"ReadProcessMemory", lua_ReadProcessMemory},
    {"WriteProcessMemory", lua_WriteProcessMemory},
    {"FindWindow", lua_FindWindow},
    {"SetWindowText", lua_SetWindowText},
    {"malloc", lua_malloc},
    {"free", lua_free},
    {"peek", lua_peek},
    {"ShellExecute", lua_ShellExecute},
    {"GetCursorPos", lua_GetCursorPos},
    {"SetCursorPos", lua_SetCursorPos},
    {"mouse_event", lua_mouse_event},
    {"MapVirtualKey", lua_MapVirtualKey},
    {"keybd_event", lua_keybd_event},
    {"LoadLibrary", lua_LoadLibrary},
    {"GetProcAddress", lua_GetProcAddress},
    {"ZwProtectVirtualMemory", lua_ZwProtectVirtualMemory},
    {"GetWindowThreadProcessId", lua_GetWindowThreadProcessId},
    {"GetCurrentProcess", lua_GetCurrentProcess},
    {"OpenProcessToken", lua_OpenProcessToken},
    {"LookupPrivilegeValue", lua_LookupPrivilegeValue},
    {"AdjustTokenPrivileges", lua_AdjustTokenPrivileges},
    {"EnableDebugPrivilege", lua_EnableDebugPrivilege},
    {"CloseHandle", lua_CloseHandle},
    {"CreateThread", lua_CreateThread},
    {"SetThreadPriority", lua_SetThreadPriority},
    {"TerminateThread", lua_TerminateThread},
    {"RegisterHotKey", lua_RegisterHotKey},
    {"UnregisterHotKey", lua_UnregisterHotKey},
    {"VirtualAllocEx", lua_VirtualAllocEx},
    {"CreateRemoteThread", lua_CreateRemoteThread},
    {"EnablePriv", lua_EnablePriv},
    {"GetProcessIDByName", lua_GetProcessIDByName},
    {"GetThreadStartAddress", lua_GetThreadStartAddress},
    {"EnumThread", lua_EnumThread},
    {"GetPrivateProfileString", lua_GetPrivateProfileString},
    {"WritePrivateProfileString", lua_WritePrivateProfileString},
    {"GetPrivateProfileInt", lua_GetPrivateProfileInt},
    {"WritePrivateProfileInt", lua_WritePrivateProfileInt},
    {"RegOpenKeyEx", lua_RegOpenKeyEx},
    {"RegCloseKey", lua_RegCloseKey},
    {"RegGetValue", lua_RegGetValue},
    {"RegSetValueEx", lua_RegSetValueEx},
    {"EnablePrivilege", lua_EnablePrivilege},
    {"InjectDLL", lua_InjectDLL},
    {"EnumDrives", lua_EnumDrives},
    {"GetMessage", lua_GetMessage},
    {"TranslateMessage", lua_TranslateMessage},
    {"DispatchMessage", lua_DispatchMessage},
    {"ListAPIFunctions", lua_ListAPIFunctions},
    {"CreateMainWindow", l_CreateMainWindow},
    {"ShowWindow", l_ShowWindow},
    {"UpdateWindow", l_UpdateWindow},

    {NULL, NULL} // 数组结束标志
};

LUA_winapi int luaopen_winapi(lua_State *L)
{
    luaL_newlib(L, winapi);

    lua_newtable(L);
    lua_pushvalue(L, -2);
    lua_pushnil(L);
    while (lua_next(L, -2) != 0) {
        if (lua_isstring(L, -2)) {
            lua_pushvalue(L, -2);
            lua_pushvalue(L, -2);
            lua_settable(L, -6);
        }
        lua_pop(L, 1);
    }
    lua_pop(L, 1);

    lua_pushcclosure(L, lua_ListAPIFunctions, 1);
    lua_setfield(L, -2, "ListAPIFunctions");

    return 1;
}