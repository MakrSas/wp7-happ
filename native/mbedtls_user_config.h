/* Дополнения к стандартному конфигу mbedTLS 3.6 (подключается через MBEDTLS_USER_CONFIG_FILE). */

/* Соединений много, каждое в своём потоке; PSA (TLS 1.3) держит общие слоты ключей. */
#define MBEDTLS_THREADING_C

#ifdef _WIN32_WCE
#define MBEDTLS_THREADING_ALT
/* Энтропию даём сами (CeGenRandom), сокеты и таймеры тоже свои. */
#define MBEDTLS_NO_PLATFORM_ENTROPY
#define MBEDTLS_ENTROPY_HARDWARE_ALT   /* mbedtls_hardware_poll() в tunnel.c, нужен и для PSA */
#undef MBEDTLS_NET_C
#undef MBEDTLS_TIMING_C
#undef MBEDTLS_PSA_ITS_FILE_C
#undef MBEDTLS_PSA_CRYPTO_STORAGE_C
/* gmtime_r на CE нет: сроки действия сертификатов не проверяем, цепочку и имя — проверяем. */
#undef MBEDTLS_HAVE_TIME_DATE
#else
#define MBEDTLS_THREADING_PTHREAD
#endif
