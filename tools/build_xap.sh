#!/bin/bash
# Сборка HappWP.xap (вызывается из ./build.sh xap [release] на s8build, после нативной части).
# Те же шаги, что у SIM-эмулятора: gen_g → mkres → mcs → fixcom → xamlcheck → zip.
set -euo pipefail

WP7=${WP7:-/mnt/mui/wp7sdk}
REF=$WP7/ref
LIB=$WP7/lib
CAB=$WP7/cab
cd "$(dirname "$0")/.."
B=build/app
NATIVE=build/ce
rm -rf $B
mkdir -p $B/xap/Images $B/gen

if [ "${1:-}" = release ]; then
    VER="1.1.$(date +%-m%d).$((10#$(date +%H%M)))"
    DEFINES="SILVERLIGHT;WINDOWS_PHONE;RELEASE"
else
    VER="1.0.$(date +%-m%d).$((10#$(date +%H%M)))"
    DEFINES="SILVERLIGHT;WINDOWS_PHONE"
fi
echo "== версия $VER"
cat > $B/gen/BuildInfo.cs <<EOF
[assembly: System.Reflection.AssemblyVersion("$VER")]
[assembly: System.Reflection.AssemblyFileVersion("$VER")]
namespace HappWP { static class BuildInfo { public const string Version = "$VER"; } }
EOF

echo "== XAML"
XAML="app/App.xaml app/Pages/MainPage.xaml"
python3 tools/gen_g.py HappWP $B/gen app $XAML
RES=()
for x in $XAML; do
    rel=${x#app/}
    RES+=("$(echo "$rel" | tr 'A-Z' 'a-z')=$x")
done
python3 tools/mkres.py $B/HappWP.g.resources "${RES[@]}"

echo "== C#"
mcs -nologo -noconfig -nostdlib -target:library -optimize+ -debug- -langversion:4 \
    -define:"$DEFINES" -nowarn:1701,1702,0162 \
    -r:$REF/mscorlib.dll -r:$REF/System.dll -r:$REF/System.Core.dll -r:$REF/System.Windows.dll \
    -r:$REF/System.Net.dll -r:$REF/System.Xml.dll -r:$REF/Microsoft.Phone.dll -r:$REF/Microsoft.Phone.Interop.dll \
    -r:$LIB/Microsoft.Phone.Controls.dll -r:$LIB/Microsoft.Phone.Controls.Toolkit.dll \
    -resource:$B/HappWP.g.resources,HappWP.g.resources \
    -out:$B/xap/HappWP.dll \
    app/*.cs app/Properties/*.cs app/Pages/*.cs $B/gen/*.cs

echo "== COM-конструкторы как у csc"
mcs -nologo -out:$B/fixcom.exe -r:/usr/lib/mono/gac/Mono.Cecil/0.11.0.0__0738eb9f132ed756/Mono.Cecil.dll tools/fixcom.cs
mono $B/fixcom.exe $REF $LIB $B/xap/HappWP.dll

echo "== проверка XAML"
mcs -nologo -out:$B/xamlcheck.exe -r:System.Xml.Linq.dll -r:System.Xml.dll tools/xamlcheck.cs
mono $B/xamlcheck.exe $REF $LIB $B/xap/HappWP.dll $XAML

echo "== XAP"
cp app/AppManifest.xaml $B/xap/
sed "s/Version=\"1.0.0.0\"/Version=\"$VER\"/" app/WMAppManifest.xml > $B/xap/WMAppManifest.xml
grep -q "Version=\"$VER\"" $B/xap/WMAppManifest.xml
cp app/WPInteropManifest.xml $B/xap/WPInteropManifest.xml
cp app/WPInteropManifest.xml $B/xap/WMInteropManifest.xml
cp $LIB/Microsoft.Phone.Controls.dll $LIB/Microsoft.Phone.Controls.Toolkit.dll $B/xap/
cp $NATIVE/HappNative.dll $NATIVE/happd.exe $B/xap/
# Корневые сертификаты для проверки серверов (Mozilla, как в системе сборочной машины).
cp /etc/ssl/certs/ca-certificates.crt $B/xap/cacert.pem
python3 tools/icons.py $B/xap
S=3643236F_FC70_11D3_A536_0090278A1BB8
for i in sync refresh questionmark; do
    cp $CAB/FL_Dappbar.$i.rest.png_v71.$S $B/xap/Images/appbar.$i.rest.png 2>/dev/null ||
    cp $CAB/filDappbar.$i.rest.png $B/xap/Images/appbar.$i.rest.png
done
(cd $B/xap && rm -f ../../HappWP.xap && zip -q -X -r ../../HappWP.xap .)
unzip -l build/HappWP.xap | tail -3
ls -l build/HappWP.xap
