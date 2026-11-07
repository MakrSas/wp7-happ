#ifndef HAPP_PROXY_H
#define HAPP_PROXY_H

#include "tunnel.h"

/* Текущий сервер: меняется на лету, новые соединения идут уже через него. */
void proxy_set_outbound(const Outbound *o);
void proxy_get_outbound(Outbound *o);

/* Слушать addr:port (HTTP-прокси с CONNECT и SOCKS5 на одном порту), пока *stop == 0. */
int proxy_run(const char *addr, int port, volatile int *stop);

/* Перехват HTTPS для клиентов со старым TLS (IE9): 1 — включён. */
extern volatile int g_mitm;

/* Последняя ошибка выхода в интернет (для статуса в приложении). */
void proxy_last_error(char *buf, size_t len);

#endif
