#include "ca.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "bearssl.h"
#include "mbedtls/ctr_drbg.h"
#include "mbedtls/oid.h"
#include "mbedtls/pk.h"
#include "mbedtls/rsa.h"
#include "mbedtls/x509_crt.h"
#include "plat.h"
#include "tunnel.h"

#ifdef _WIN32_WCE
static CRITICAL_SECTION g_lock;
#define LOCK() EnterCriticalSection(&g_lock)
#define UNLOCK() LeaveCriticalSection(&g_lock)
#define LOCK_INIT() InitializeCriticalSection(&g_lock)
#else
#include <pthread.h>
static pthread_mutex_t g_lock = PTHREAD_MUTEX_INITIALIZER;
#define LOCK() pthread_mutex_lock(&g_lock)
#define UNLOCK() pthread_mutex_unlock(&g_lock)
#define LOCK_INIT() ((void)0)
#endif

#define CA_NAME "CN=Happ HD7 Root,O=HappWP,OU=generated on device"
#define CACHE 48
/* Имя корневого сертификата в хранилище; меняется, когда меняется формат (v2 — подпись SHA-1). */
#define ROOT_NAME "root_v2"

static volatile int g_ready;
static mbedtls_pk_context g_key;
static unsigned char g_root[2048];
static size_t g_root_len;

/* Ключ для BearSSL: части CRT, big-endian. */
static unsigned char kp[256], kq[256], kdp[256], kdq[256], kiq[256];
static br_rsa_private_key g_brkey;

static struct { char host[256]; unsigned char *der; size_t len; unsigned long used; } g_cache[CACHE];

/* ---------------------------------------------------------------- хранилище */

#ifdef _WIN32_WCE
#include <windows.h>
int ca_store_load(const char *name, unsigned char *buf, size_t cap, size_t *len)
{
    HKEY k;
    wchar_t w[64];
    DWORD type, size = (DWORD)cap;
    LONG r;
    MultiByteToWideChar(CP_ACP, 0, name, -1, w, 64);
    if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, L"Software\\HappWP\\Ca", 0, 0, &k) != ERROR_SUCCESS) return -1;
    r = RegQueryValueExW(k, w, NULL, &type, buf, &size);
    RegCloseKey(k);
    if (r != ERROR_SUCCESS || type != REG_BINARY) return -1;
    *len = size;
    return 0;
}

int ca_store_save(const char *name, const unsigned char *buf, size_t len)
{
    HKEY k;
    DWORD disp;
    wchar_t w[64];
    LONG r;
    MultiByteToWideChar(CP_ACP, 0, name, -1, w, 64);
    if (RegCreateKeyExW(HKEY_LOCAL_MACHINE, L"Software\\HappWP\\Ca", 0, NULL, 0, 0, NULL, &k, &disp) != ERROR_SUCCESS) return -1;
    r = RegSetValueExW(k, w, 0, REG_BINARY, buf, (DWORD)len);
    RegCloseKey(k);
    return r == ERROR_SUCCESS ? 0 : -1;
}

static void utc_now(int *y, int *mo, int *d, int *h, int *mi, int *s)
{
    SYSTEMTIME st;
    GetSystemTime(&st);
    *y = st.wYear; *mo = st.wMonth; *d = st.wDay; *h = st.wHour; *mi = st.wMinute; *s = st.wSecond;
}
#else
static void path_of(const char *name, char *out, size_t cap)
{
    const char *home = getenv("HOME");
    snprintf(out, cap, "%s/.happtest/ca_%s.bin", home ? home : ".", name);
}

int ca_store_load(const char *name, unsigned char *buf, size_t cap, size_t *len)
{
    char p[512];
    FILE *f;
    path_of(name, p, sizeof(p));
    f = fopen(p, "rb");
    if (!f) return -1;
    *len = fread(buf, 1, cap, f);
    fclose(f);
    return *len > 0 ? 0 : -1;
}

int ca_store_save(const char *name, const unsigned char *buf, size_t len)
{
    char p[512];
    FILE *f;
    path_of(name, p, sizeof(p));
    f = fopen(p, "wb");
    if (!f) return -1;
    fwrite(buf, 1, len, f);
    fclose(f);
    return 0;
}

static void utc_now(int *y, int *mo, int *d, int *h, int *mi, int *s)
{
    time_t t = time(NULL);
    struct tm tm;
    gmtime_r(&t, &tm);
    *y = tm.tm_year + 1900; *mo = tm.tm_mon + 1; *d = tm.tm_mday; *h = tm.tm_hour; *mi = tm.tm_min; *s = tm.tm_sec;
}
#endif

/* «YYYYMMDDhhmmss» со сдвигом на целые годы (для начала — на день назад, чтобы не споткнуться о часы). */
static void stamp(char *out, int years, int day_back)
{
    int y, mo, d, h, mi, s;
    utc_now(&y, &mo, &d, &h, &mi, &s);
    if (day_back) {
        if (d > 1) d--;
        else if (mo > 1) { mo--; d = 28; }
        else { y--; mo = 12; d = 31; }
    }
    if (mo == 2 && d == 29) d = 28;
    sprintf(out, "%04d%02d%02d%02d%02d%02d", y + years, mo, d, h, mi, s);
}

/* ---------------------------------------------------------------- выпуск */

static int rng(void *p, unsigned char *out, size_t len)
{
    return mbedtls_ctr_drbg_random(p, out, len);
}

static int is_ip(const char *h)
{
    unsigned a, b, c, d;
    char x;
    return sscanf(h, "%u.%u.%u.%u%c", &a, &b, &c, &d, &x) == 4;
}

/* Выписать сертификат: корневой (host == NULL) или для сайта. Результат — в конце buf. */
static int issue(const char *host, unsigned char *buf, size_t cap, unsigned char **der, size_t *len)
{
    mbedtls_x509write_cert crt;
    unsigned char serial[16];
    char subject[300], from[16], to[16];
    mbedtls_x509_san_list san;
    mbedtls_asn1_sequence eku;
    unsigned char ipbuf[4];
    int r;

    mbedtls_x509write_crt_init(&crt);
    mbedtls_x509write_crt_set_version(&crt, MBEDTLS_X509_CRT_VERSION_3);
    /*
     * SHA-1, а не SHA-256: WP7 (CryptoAPI CE 7) с SHA-2 в сертификатах может не справиться.
     * Коллизии SHA-1 здесь не опасны: Happ подписывает только то, что выпускает сам.
     */
    mbedtls_x509write_crt_set_md_alg(&crt, MBEDTLS_MD_SHA1);
    mbedtls_x509write_crt_set_subject_key(&crt, &g_key);
    mbedtls_x509write_crt_set_issuer_key(&crt, &g_key);
    mbedtls_x509write_crt_set_issuer_name(&crt, CA_NAME);
    rng(tun_drbg(), serial, sizeof(serial));
    serial[0] &= 0x7f; /* положительный */
    mbedtls_x509write_crt_set_serial_raw(&crt, serial, sizeof(serial));
    stamp(from, 0, 1);

    if (!host) {
        stamp(to, 10, 0);
        mbedtls_x509write_crt_set_subject_name(&crt, CA_NAME);
        mbedtls_x509write_crt_set_basic_constraints(&crt, 1, 0);
        mbedtls_x509write_crt_set_key_usage(&crt, MBEDTLS_X509_KU_KEY_CERT_SIGN | MBEDTLS_X509_KU_CRL_SIGN);
        mbedtls_x509write_crt_set_subject_key_identifier(&crt);
    } else {
        stamp(to, 1, 0);
        snprintf(subject, sizeof(subject), "CN=%s", host);
        mbedtls_x509write_crt_set_subject_name(&crt, subject);
        mbedtls_x509write_crt_set_basic_constraints(&crt, 0, -1);
        mbedtls_x509write_crt_set_key_usage(&crt, MBEDTLS_X509_KU_DIGITAL_SIGNATURE | MBEDTLS_X509_KU_KEY_ENCIPHERMENT);
        memset(&san, 0, sizeof(san));
        if (is_ip(host)) {
            unsigned a, b, c, d;
            sscanf(host, "%u.%u.%u.%u", &a, &b, &c, &d);
            ipbuf[0] = (unsigned char)a; ipbuf[1] = (unsigned char)b; ipbuf[2] = (unsigned char)c; ipbuf[3] = (unsigned char)d;
            san.node.type = MBEDTLS_X509_SAN_IP_ADDRESS;
            san.node.san.unstructured_name.p = ipbuf;
            san.node.san.unstructured_name.len = 4;
        } else {
            san.node.type = MBEDTLS_X509_SAN_DNS_NAME;
            san.node.san.unstructured_name.p = (unsigned char *)host;
            san.node.san.unstructured_name.len = strlen(host);
        }
        mbedtls_x509write_crt_set_subject_alternative_name(&crt, &san);
        memset(&eku, 0, sizeof(eku));
        eku.buf.tag = MBEDTLS_ASN1_OID;
        eku.buf.p = (unsigned char *)MBEDTLS_OID_SERVER_AUTH;
        eku.buf.len = MBEDTLS_OID_SIZE(MBEDTLS_OID_SERVER_AUTH);
        mbedtls_x509write_crt_set_ext_key_usage(&crt, &eku);
        mbedtls_x509write_crt_set_authority_key_identifier(&crt);
    }
    mbedtls_x509write_crt_set_validity(&crt, from, to);
    r = mbedtls_x509write_crt_der(&crt, buf, cap, rng, tun_drbg());
    mbedtls_x509write_crt_free(&crt);
    if (r <= 0) return r ? r : -1;
    *der = buf + cap - (size_t)r;
    *len = (size_t)r;
    return 0;
}

/* ---------------------------------------------------------------- ключ */

static int mpi_out(const mbedtls_mpi *m, unsigned char *out, size_t *len)
{
    *len = mbedtls_mpi_size(m);
    return mbedtls_mpi_write_binary(m, out, *len);
}

static int load_brkey(void)
{
    mbedtls_rsa_context *rsa = mbedtls_pk_rsa(g_key);
    mbedtls_mpi P, Q, DP, DQ, QP;
    int r;
    mbedtls_mpi_init(&P); mbedtls_mpi_init(&Q); mbedtls_mpi_init(&DP); mbedtls_mpi_init(&DQ); mbedtls_mpi_init(&QP);
    r = mbedtls_rsa_export(rsa, NULL, &P, &Q, NULL, NULL);
    if (!r) r = mbedtls_rsa_export_crt(rsa, &DP, &DQ, &QP);
    if (!r) r = mpi_out(&P, kp, &g_brkey.plen);
    if (!r) r = mpi_out(&Q, kq, &g_brkey.qlen);
    if (!r) r = mpi_out(&DP, kdp, &g_brkey.dplen);
    if (!r) r = mpi_out(&DQ, kdq, &g_brkey.dqlen);
    if (!r) r = mpi_out(&QP, kiq, &g_brkey.iqlen);
    g_brkey.n_bitlen = (uint32_t)mbedtls_pk_get_bitlen(&g_key);
    g_brkey.p = kp; g_brkey.q = kq; g_brkey.dp = kdp; g_brkey.dq = kdq; g_brkey.iq = kiq;
    mbedtls_mpi_free(&P); mbedtls_mpi_free(&Q); mbedtls_mpi_free(&DP); mbedtls_mpi_free(&DQ); mbedtls_mpi_free(&QP);
    return r;
}

int ca_init(void)
{
    static int once;
    unsigned char *buf;
    size_t len;
    int r;
    if (!once) { once = 1; LOCK_INIT(); }
    if (g_ready) return 0;
    buf = (unsigned char *)malloc(8192);
    if (!buf) return -1;
    mbedtls_pk_init(&g_key);

    if (ca_store_load("key", buf, 8192, &len) == 0 &&
        mbedtls_pk_parse_key(&g_key, buf, len, NULL, 0, rng, tun_drbg()) == 0) {
        /* Ключ есть. Корневой сертификат версии ROOT_NAME — тоже, или перевыпускаем его тем же ключом. */
        if (ca_store_load(ROOT_NAME, g_root, sizeof(g_root), &g_root_len) == 0) {
            plat_log("корневой сертификат Happ загружен");
        } else {
            unsigned char *der;
            if (issue(NULL, buf, 8192, &der, &len) != 0) { free(buf); return -1; }
            memcpy(g_root, der, len);
            g_root_len = len;
            ca_store_save(ROOT_NAME, g_root, g_root_len);
            plat_log("корневой сертификат перевыпущен (%s)", ROOT_NAME);
        }
    } else {
        unsigned long t0 = plat_ms();
        unsigned char *der;
        plat_log("создаю ключ RSA-2048 для корневого сертификата…");
        mbedtls_pk_free(&g_key);
        mbedtls_pk_init(&g_key);
        r = mbedtls_pk_setup(&g_key, mbedtls_pk_info_from_type(MBEDTLS_PK_RSA));
        if (!r) r = mbedtls_rsa_gen_key(mbedtls_pk_rsa(g_key), rng, tun_drbg(), 2048, 65537);
        if (r) { plat_log("ключ не создан: -0x%04x", -r); free(buf); return -1; }
        r = mbedtls_pk_write_key_der(&g_key, buf, 8192);
        if (r <= 0) { free(buf); return -1; }
        ca_store_save("key", buf + 8192 - r, (size_t)r);
        if (issue(NULL, buf, 8192, &der, &len) != 0) { plat_log("корневой сертификат не выписан"); free(buf); return -1; }
        memcpy(g_root, der, len);
        g_root_len = len;
        ca_store_save(ROOT_NAME, g_root, g_root_len);
        plat_log("корневой сертификат создан за %lu мс", plat_ms() - t0);
    }
    free(buf);
    if (load_brkey() != 0) { plat_log("ключ для BearSSL не разобран"); return -1; }
    g_ready = 1;
    return 0;
}

int ca_ready(void) { return g_ready; }

const unsigned char *ca_root_der(size_t *len)
{
    *len = g_root_len;
    return g_ready ? g_root : NULL;
}

const void *ca_br_key(void) { return &g_brkey; }

const unsigned char *ca_leaf_der(const char *host, size_t *len)
{
    static unsigned long tick;
    unsigned char *buf, *der;
    size_t l;
    int i, victim = 0;
    if (!g_ready) return NULL;
    LOCK();
    for (i = 0; i < CACHE; i++) {
        if (g_cache[i].der && strcmp(g_cache[i].host, host) == 0) {
            g_cache[i].used = ++tick;
            *len = g_cache[i].len;
            UNLOCK();
            return g_cache[i].der;
        }
        if (g_cache[i].used < g_cache[victim].used) victim = i;
    }
    buf = (unsigned char *)malloc(4096);
    if (!buf || issue(host, buf, 4096, &der, &l) != 0) {
        UNLOCK();
        free(buf);
        return NULL;
    }
    free(g_cache[victim].der);
    g_cache[victim].der = (unsigned char *)malloc(l);
    memcpy(g_cache[victim].der, der, l);
    g_cache[victim].len = l;
    snprintf(g_cache[victim].host, sizeof(g_cache[victim].host), "%s", host);
    g_cache[victim].used = ++tick;
    free(buf);
    *len = l;
    der = g_cache[victim].der;
    UNLOCK();
    return der;
}
