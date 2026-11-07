#include "plat.h"

#include <stdarg.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>

volatile long g_active_conns, g_total_conns;
volatile long long g_bytes_up, g_bytes_down;

#ifdef _WIN32_WCE
/* ===================================================================== WinCE */

static CRITICAL_SECTION g_lock;
static FILE *g_logf;

int plat_init(void)
{
    static int done;
    WSADATA wsa;
    if (done) return 0;
    done = 1;
    InitializeCriticalSection(&g_lock);
    return WSAStartup(MAKEWORD(2, 2), &wsa) == 0 ? 0 : -1;
}

void plat_log_file(const char *path)
{
    g_logf = fopen(path, "w");
}

void plat_log(const char *fmt, ...)
{
    va_list ap;
    if (!g_logf) return;
    EnterCriticalSection(&g_lock);
    fprintf(g_logf, "%lu ", (unsigned long)GetTickCount());
    va_start(ap, fmt);
    vfprintf(g_logf, fmt, ap);
    va_end(ap);
    fputc('\n', g_logf);
    fflush(g_logf);
    LeaveCriticalSection(&g_lock);
}

void plat_add(volatile long *v, long d) { InterlockedExchangeAdd((LONG *)v, d); }
void plat_add64(volatile long long *v, long long d)
{
    EnterCriticalSection(&g_lock);
    *v += d;
    LeaveCriticalSection(&g_lock);
}

typedef struct { thread_fn fn; void *arg; } ThreadStart;

static DWORD WINAPI thread_tramp(LPVOID p)
{
    ThreadStart ts = *(ThreadStart *)p;
    LocalFree(p);
    ts.fn(ts.arg);
    return 0;
}

int plat_thread(thread_fn fn, void *arg)
{
    ThreadStart *ts = (ThreadStart *)LocalAlloc(LMEM_FIXED, sizeof(ThreadStart));
    HANDLE h;
    if (!ts) return -1;
    ts->fn = fn;
    ts->arg = arg;
    /* 64 КБ стека: mbedTLS в рукопожатии ест заметно, а потоков может быть много. */
    h = CreateThread(NULL, 64 * 1024, thread_tramp, ts, STACK_SIZE_PARAM_IS_A_RESERVATION, NULL);
    if (!h) { LocalFree(ts); return -1; }
    CloseHandle(h);
    return 0;
}

void plat_sleep(int ms) { Sleep(ms); }
unsigned long plat_ms(void) { return GetTickCount(); }

/* CeGenRandom есть в coredll начиная с CE 5. */
BOOL WINAPI CeGenRandom(DWORD dwLen, PBYTE pbBuffer);

int plat_random(unsigned char *out, size_t len)
{
    return CeGenRandom((DWORD)len, out) ? 0 : -1;
}

#define CLOSESOCK closesocket
#define SOCKERR (WSAGetLastError())

#else
/* ===================================================================== POSIX */
#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <netdb.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <pthread.h>
#include <signal.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <time.h>
#include <unistd.h>

static pthread_mutex_t g_lock = PTHREAD_MUTEX_INITIALIZER;

int plat_init(void)
{
    signal(SIGPIPE, SIG_IGN);
    return 0;
}

void plat_log(const char *fmt, ...)
{
    va_list ap;
    pthread_mutex_lock(&g_lock);
    fprintf(stderr, "%lu ", plat_ms());
    va_start(ap, fmt);
    vfprintf(stderr, fmt, ap);
    va_end(ap);
    fputc('\n', stderr);
    pthread_mutex_unlock(&g_lock);
}

void plat_add(volatile long *v, long d) { __sync_fetch_and_add(v, d); }
void plat_add64(volatile long long *v, long long d) { __sync_fetch_and_add(v, d); }

typedef struct { thread_fn fn; void *arg; } ThreadStart;

static void *thread_tramp(void *p)
{
    ThreadStart ts = *(ThreadStart *)p;
    free(p);
    ts.fn(ts.arg);
    return NULL;
}

#include <stdlib.h>
int plat_thread(thread_fn fn, void *arg)
{
    pthread_t t;
    pthread_attr_t a;
    ThreadStart *ts = malloc(sizeof(ThreadStart));
    if (!ts) return -1;
    ts->fn = fn;
    ts->arg = arg;
    pthread_attr_init(&a);
    pthread_attr_setdetachstate(&a, PTHREAD_CREATE_DETACHED);
    pthread_attr_setstacksize(&a, 256 * 1024);
    if (pthread_create(&t, &a, thread_tramp, ts)) { free(ts); return -1; }
    return 0;
}

void plat_sleep(int ms) { usleep(ms * 1000); }

unsigned long plat_ms(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (unsigned long)(ts.tv_sec * 1000 + ts.tv_nsec / 1000000);
}

int plat_random(unsigned char *out, size_t len)
{
    FILE *f = fopen("/dev/urandom", "rb");
    size_t n;
    if (!f) return -1;
    n = fread(out, 1, len, f);
    fclose(f);
    return n == len ? 0 : -1;
}

#define CLOSESOCK close
#define SOCKERR errno
#endif

/* ===================================================================== общие сокеты */

#ifndef _WIN32_WCE
#include <netdb.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <sys/select.h>
#include <fcntl.h>
#include <errno.h>
#endif

static void set_nonblock(sock_t s, int on)
{
#ifdef _WIN32_WCE
    u_long v = on;
    ioctlsocket(s, FIONBIO, &v);
#else
    int f = fcntl(s, F_GETFL, 0);
    fcntl(s, F_SETFL, on ? (f | O_NONBLOCK) : (f & ~O_NONBLOCK));
#endif
}

sock_t net_connect(const char *host, int port, int timeout_ms)
{
    struct addrinfo hints, *res = NULL, *ai;
    char ps[8];
    sock_t s = SOCK_INVALID;
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_INET; /* у WP7 IPv6 на Wi-Fi нет */
    hints.ai_socktype = SOCK_STREAM;
    sprintf(ps, "%d", port);
    if (getaddrinfo(host, ps, &hints, &res) != 0 || !res) {
        plat_log("dns: не нашёл %s", host);
        return SOCK_INVALID;
    }
    for (ai = res; ai; ai = ai->ai_next) {
        fd_set wf;
        struct timeval tv;
        int r, one = 1;
        s = socket(ai->ai_family, ai->ai_socktype, ai->ai_protocol);
        if (s == SOCK_INVALID) continue;
        set_nonblock(s, 1);
        r = connect(s, ai->ai_addr, (int)ai->ai_addrlen);
        if (r != 0) {
            FD_ZERO(&wf);
            FD_SET(s, &wf);
            tv.tv_sec = timeout_ms / 1000;
            tv.tv_usec = (timeout_ms % 1000) * 1000;
            r = select((int)s + 1, NULL, &wf, NULL, &tv);
            if (r == 1) {
                int err = 0;
                socklen_t el = sizeof(err);
                getsockopt(s, SOL_SOCKET, SO_ERROR, (char *)&err, &el);
                r = err == 0 ? 0 : -1;
            } else {
                r = -1;
            }
        }
        if (r == 0) {
            set_nonblock(s, 0);
            setsockopt(s, IPPROTO_TCP, TCP_NODELAY, (const char *)&one, sizeof(one));
            break;
        }
        CLOSESOCK(s);
        s = SOCK_INVALID;
    }
    freeaddrinfo(res);
    return s;
}

sock_t net_listen(const char *addr, int port)
{
    struct sockaddr_in sa;
    int one = 1;
    sock_t s = socket(AF_INET, SOCK_STREAM, 0);
    if (s == SOCK_INVALID) return s;
    setsockopt(s, SOL_SOCKET, SO_REUSEADDR, (const char *)&one, sizeof(one));
    memset(&sa, 0, sizeof(sa));
    sa.sin_family = AF_INET;
    sa.sin_port = htons((unsigned short)port);
    sa.sin_addr.s_addr = inet_addr(addr);
    if (bind(s, (struct sockaddr *)&sa, sizeof(sa)) != 0 || listen(s, 32) != 0) {
        plat_log("listen %s:%d — ошибка %d", addr, port, SOCKERR);
        CLOSESOCK(s);
        return SOCK_INVALID;
    }
    return s;
}

sock_t net_accept(sock_t s)
{
    int one = 1;
    sock_t c = accept(s, NULL, NULL);
    if (c != SOCK_INVALID) setsockopt(c, IPPROTO_TCP, TCP_NODELAY, (const char *)&one, sizeof(one));
    return c;
}

int net_send_all(sock_t s, const void *buf, size_t len)
{
    const char *p = (const char *)buf;
    while (len > 0) {
        int n = send(s, p, (int)len, 0);
        if (n <= 0) return -1;
        p += n;
        len -= (size_t)n;
    }
    return 0;
}

int net_recv(sock_t s, void *buf, size_t len)
{
    return recv(s, (char *)buf, (int)len, 0);
}

void net_close(sock_t s)
{
    if (s != SOCK_INVALID) CLOSESOCK(s);
}

int net_wait2(sock_t a, sock_t b, int timeout_ms)
{
    fd_set rf;
    struct timeval tv;
    int r, m = 0, maxfd = (int)a;
    FD_ZERO(&rf);
    FD_SET(a, &rf);
    if (b != SOCK_INVALID) {
        FD_SET(b, &rf);
        if ((int)b > maxfd) maxfd = (int)b;
    }
    tv.tv_sec = timeout_ms / 1000;
    tv.tv_usec = (timeout_ms % 1000) * 1000;
    r = select(maxfd + 1, &rf, NULL, NULL, &tv);
    if (r < 0) return -1;
    if (FD_ISSET(a, &rf)) m |= 1;
    if (b != SOCK_INVALID && FD_ISSET(b, &rf)) m |= 2;
    return m;
}
