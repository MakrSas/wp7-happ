/* Мьютексы mbedTLS на WinCE (MBEDTLS_THREADING_ALT). */
#ifndef HAPP_THREADING_ALT_H
#define HAPP_THREADING_ALT_H

#include <windows.h>

typedef struct {
    CRITICAL_SECTION cs;
    int valid;
} mbedtls_threading_mutex_t;

#endif
