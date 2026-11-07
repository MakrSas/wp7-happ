/*
 * Платформенный слой happd: сокеты, потоки, журнал, случайные числа.
 * Одна и та же логика прокси собирается под Linux/macOS (для проверки с компьютера) и под WinCE (HD7).
 */
#ifndef HAPP_PLAT_H
#define HAPP_PLAT_H

#include <stddef.h>
#include <stdint.h>

#ifdef _WIN32_WCE
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
typedef SOCKET sock_t;
typedef int socklen_t;
#define SOCK_INVALID INVALID_SOCKET
#else
#include <sys/types.h>
typedef int sock_t;
#define SOCK_INVALID (-1)
#endif

int  plat_init(void);
void plat_log(const char *fmt, ...);

/* TCP. host — имя или IP. timeout_ms для connect. Возвращает SOCK_INVALID при ошибке. */
sock_t net_connect(const char *host, int port, int timeout_ms);
sock_t net_listen(const char *addr, int port);
sock_t net_accept(sock_t s);
int    net_send_all(sock_t s, const void *buf, size_t len);
int    net_recv(sock_t s, void *buf, size_t len);       /* >0 байт, 0 закрыто, <0 ошибка */
void   net_close(sock_t s);
/* Ждать данных на любом из двух сокетов (b может быть SOCK_INVALID). Возвращает маску: 1 — a, 2 — b, 0 — таймаут, <0 ошибка. */
int    net_wait2(sock_t a, sock_t b, int timeout_ms);

typedef void (*thread_fn)(void *arg);
int  plat_thread(thread_fn fn, void *arg);
void plat_sleep(int ms);
unsigned long plat_ms(void);

/* Криптостойкие случайные байты (для энтропии TLS). 0 — успех. */
int plat_random(unsigned char *out, size_t len);

/* Счётчики для статуса в приложении. */
extern volatile long g_active_conns, g_total_conns;
extern volatile long long g_bytes_up, g_bytes_down;
void plat_add(volatile long *v, long d);
void plat_add64(volatile long long *v, long long d);

#endif
