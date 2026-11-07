#include "happ_reg.h"

DWORD reg_dword(const wchar_t *key, const wchar_t *name, DWORD def)
{
    HKEY k;
    DWORD type, size = sizeof(DWORD), v = def;
    if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, key, 0, 0, &k) != ERROR_SUCCESS) return def;
    if (RegQueryValueExW(k, name, NULL, &type, (LPBYTE)&v, &size) != ERROR_SUCCESS || type != REG_DWORD) v = def;
    RegCloseKey(k);
    return v;
}

int reg_set_dword(const wchar_t *key, const wchar_t *name, DWORD v)
{
    HKEY k;
    DWORD disp;
    LONG r;
    if (RegCreateKeyExW(HKEY_LOCAL_MACHINE, key, 0, NULL, 0, 0, NULL, &k, &disp) != ERROR_SUCCESS) return 0;
    r = RegSetValueExW(k, name, 0, REG_DWORD, (const BYTE *)&v, sizeof(v));
    RegCloseKey(k);
    return r == ERROR_SUCCESS;
}

int reg_str_w(const wchar_t *key, const wchar_t *name, wchar_t *out, DWORD cch)
{
    HKEY k;
    DWORD type, size = (cch - 1) * sizeof(wchar_t);
    LONG r;
    out[0] = 0;
    if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, key, 0, 0, &k) != ERROR_SUCCESS) return 0;
    r = RegQueryValueExW(k, name, NULL, &type, (LPBYTE)out, &size);
    RegCloseKey(k);
    if (r != ERROR_SUCCESS || type != REG_SZ) { out[0] = 0; return 0; }
    out[size / sizeof(wchar_t)] = 0;
    return 1;
}

int reg_set_str_w(const wchar_t *key, const wchar_t *name, const wchar_t *v)
{
    HKEY k;
    DWORD disp;
    LONG r;
    if (RegCreateKeyExW(HKEY_LOCAL_MACHINE, key, 0, NULL, 0, 0, NULL, &k, &disp) != ERROR_SUCCESS) return 0;
    r = RegSetValueExW(k, name, 0, REG_SZ, (const BYTE *)v, (lstrlenW(v) + 1) * sizeof(wchar_t));
    RegCloseKey(k);
    return r == ERROR_SUCCESS;
}

int reg_str_a(const wchar_t *key, const wchar_t *name, char *out, int cb)
{
    wchar_t w[512];
    out[0] = 0;
    if (!reg_str_w(key, name, w, 512)) return 0;
    return WideCharToMultiByte(CP_UTF8, 0, w, -1, out, cb, NULL, NULL) > 0;
}

int reg_set_str_a(const wchar_t *key, const wchar_t *name, const char *v)
{
    wchar_t w[512];
    if (!MultiByteToWideChar(CP_UTF8, 0, v, -1, w, 512)) w[0] = 0;
    return reg_set_str_w(key, name, w);
}

void module_dir_a(HINSTANCE h, char *out, int cb)
{
    wchar_t w[MAX_PATH];
    int n = (int)GetModuleFileNameW(h, w, MAX_PATH);
    while (n > 0 && w[n - 1] != L'\\') n--;
    w[n] = 0;
    WideCharToMultiByte(CP_ACP, 0, w, -1, out, cb, NULL, NULL);
}
