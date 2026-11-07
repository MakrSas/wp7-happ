/* Чего mbedTLS ждёт от «большой» Windows, но нет в coredll WinCE. */
#ifdef _WIN32_WCE
#include <stdio.h>
#include <windows.h>

/* mbedtls_setbuf() для файлов с ключами — буферизация нам не важна. */
void setbuf(FILE *f, char *buf)
{
    (void)f;
    (void)buf;
}

/* mbedtls_platform_zeroize() на _WIN32. volatile — чтобы компилятор не выкинул обнуление. */
PVOID SecureZeroMemory(PVOID p, SIZE_T n)
{
    volatile unsigned char *v = (volatile unsigned char *)p;
    while (n--) *v++ = 0;
    return p;
}

/* mbedtls_ms_time() на _WIN32 (сроки сессий TLS 1.3). */
void GetSystemTimeAsFileTime(LPFILETIME ft)
{
    SYSTEMTIME st;
    GetSystemTime(&st);
    SystemTimeToFileTime(&st, ft);
}
#endif
