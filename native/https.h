#ifndef HAPP_HTTPS_H
#define HAPP_HTTPS_H

#include <stddef.h>

/*
 * GET по https://, с переходами по редиректам. extra_headers — строки «Имя: значение\r\n».
 * Тело (UTF-8, с завершающим нулём) выделяется malloc, освобождает вызывающий.
 */
int https_get(const char *url, const char *extra_headers, int *status, char **body, size_t *body_len,
              char *err, size_t errlen);

#endif
