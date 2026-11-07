/* Реестр и общие имена для happd.exe и HappNative.dll (только WinCE). */
#ifndef HAPP_REG_H
#define HAPP_REG_H

#include <windows.h>

#define HAPP_NATIVE_VERSION 9

#define CFG_KEY  L"Software\\HappWP"
#define LIVE_KEY L"Software\\HappWP\\Live"

#define EVT_STOP    L"HappWP.Stop"
#define EVT_RELOAD  L"HappWP.Reload"
#define MTX_ENGINE  L"HappWP.Engine"

DWORD reg_dword(const wchar_t *key, const wchar_t *name, DWORD def);
int   reg_set_dword(const wchar_t *key, const wchar_t *name, DWORD v);
/* Строки в реестре — UTF-16, ядру нужны UTF-8. */
int   reg_str_a(const wchar_t *key, const wchar_t *name, char *out, int cb);
int   reg_set_str_a(const wchar_t *key, const wchar_t *name, const char *v);
int   reg_str_w(const wchar_t *key, const wchar_t *name, wchar_t *out, DWORD cch);
int   reg_set_str_w(const wchar_t *key, const wchar_t *name, const wchar_t *v);
/* Папка модуля (со слешем на конце), в ANSI. */
void  module_dir_a(HINSTANCE h, char *out, int cb);

#endif
