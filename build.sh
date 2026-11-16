#!/bin/bash
# Сборка HappWP на s8build.
#
#   ./build.sh linux            — happd для Linux (проверка ядра с компьютера)
#   ./build.sh ce               — happd.exe и нативная DLL для HD7
#   ./build.sh xap [release]    — всё приложение: build/HappWP.xap
#   ./build.sh remote <цель>    — залить исходники на s8build, собрать там и забрать XAP
set -euo pipefail

WP7=${WP7:-/mnt/mui/wp7sdk}
HOST=${HOST:-s8build}
MBED=${MBED:-$WP7/mbedtls-3.6.7}
HERE=$(cd "$(dirname "$0")" && pwd)

if [ "${1:-}" = remote ]; then
    shift
    rsync -a --delete --exclude build/ --exclude release/ --exclude logs/ "$HERE/" "$HOST:$WP7/HappWP/"
    ssh "$HOST" "cd $WP7/HappWP && ./build.sh $*"
    if [ "${1:-}" = xap ]; then
        mkdir -p "$HERE/build"
        scp -q "$HOST:$WP7/HappWP/build/HappWP.xap" "$HERE/build/"
        ls -l "$HERE/build/HappWP.xap"
        if [ "${2:-}" = release ]; then
            VER=$(unzip -p "$HERE/build/HappWP.xap" WMAppManifest.xml | grep -o ' Version="[0-9.]*"' | tail -1 | cut -d'"' -f2)
            mkdir -p "$HERE/release" && cp "$HERE/build/HappWP.xap" "$HERE/release/HappWP-$VER.xap"
            ls -l "$HERE/release/HappWP-$VER.xap"
        fi
    fi
    exit 0
fi

if [ "${1:-}" = xap ]; then
    "$0" ce
    exec "$(dirname "$0")/tools/build_xap.sh" "${2:-}"
fi

cd "$HERE"
TARGET=${1:-linux}
B=build/$TARGET
mkdir -p $B/mbedtls

BEAR=${BEAR:-$WP7/bearssl-0.6}
MBED_FLAGS="-I$MBED/include -I$MBED/library -I$BEAR/inc -I$HERE/native -DMBEDTLS_USER_CONFIG_FILE=\"mbedtls_user_config.h\""
SRC="native/plat.c native/tunnel.c native/proxy.c native/https.c native/ca.c native/mitm.c"
[ "${1:-linux}" = ce ] && SRC="$SRC native/happ_reg.c native/ce_shim.c native/wifiproxy.c"

case $TARGET in
linux)
    CC=${CC:-gcc}
    CFLAGS="-O2 -g -Wall -Wno-unused-parameter -Wno-format-truncation $MBED_FLAGS"
    LIBS="-lpthread"
    MAIN=native/happd_posix.c
    OUT=$B/happd
    ;;
ce)
    CE=$WP7/cegcc/cegcc/bin
    CC=$CE/arm-mingw32ce-gcc
    CFLAGS="-O2 -Wall -Wno-unused-parameter -Wno-format-truncation -DUNICODE -D_UNICODE -D_WIN32_WCE=0x700 $MBED_FLAGS"
    LIBS="-lws2 -static-libgcc -Wl,--major-subsystem-version,5,--minor-subsystem-version,2"
    MAIN=native/happd_ce.c
    OUT=$B/happd.exe
    ;;
*) echo "цель: linux или ce" >&2; exit 2 ;;
esac

echo "== mbedTLS ($TARGET)"
# Собираем только то, что изменилось: объектники лежат в $B/mbedtls.
OBJS=()
for f in $MBED/library/*.c; do
    o=$B/mbedtls/$(basename "${f%.c}").o
    if [ ! -f "$o" ] || [ "$f" -nt "$o" ] || [ native/mbedtls_user_config.h -nt "$o" ]; then
        $CC $CFLAGS -w -c "$f" -o "$o" &
        while [ "$(jobs -rp | wc -l)" -ge 8 ]; do wait -n; done
    fi
    OBJS+=("$o")
done
wait

echo "== BearSSL ($TARGET)"
mkdir -p $B/bearssl
BEARFLAGS="-I$BEAR/inc -I$BEAR/src -DBR_USE_URANDOM=0 -DBR_USE_WIN32_RAND=0 -DBR_USE_UNIX_TIME=0 -DBR_USE_WIN32_TIME=0"
for f in $(find $BEAR/src -name "*.c"); do
    o=$B/bearssl/$(echo "${f#$BEAR/src/}" | tr / _ | sed 's/\.c$/.o/')
    if [ ! -f "$o" ] || [ "$f" -nt "$o" ]; then
        $CC ${CFLAGS%%-I*} -O2 -w $BEARFLAGS -c "$f" -o "$o" &
        while [ "$(jobs -rp | wc -l)" -ge 8 ]; do wait -n; done
    fi
    OBJS+=("$o")
done
wait

echo "== happd ($TARGET)"
$CC $CFLAGS -o $OUT $MAIN $SRC "${OBJS[@]}" $LIBS
if [ $TARGET = ce ]; then
    $CE/arm-mingw32ce-strip $OUT
    echo "== HappNative.dll"
    $CC $CFLAGS -DHAPP_DLL -shared -s -Wl,--kill-at -o $B/HappNative.dll \
        native/happ_native.c native/happd_ce.c $SRC "${OBJS[@]}" -lole32 -loleaut32 $LIBS
    ls -l $B/HappNative.dll
    $CE/arm-mingw32ce-objdump -p $B/HappNative.dll | grep -E "DLL Name|\] Dll"
fi
ls -l $OUT
