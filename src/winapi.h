#ifndef winapi_H
#define winapi_H

#ifdef __cplusplus
extern "C" {
#endif

#define LUA_winapi __declspec(dllexport)

#include <lua.h>

LUA_winapi int luaopen_winapi(lua_State *L);

#ifdef __cplusplus
}
#endif

#endif