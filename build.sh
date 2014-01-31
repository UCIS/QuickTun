#!/bin/sh
set -e

tar="tar"
cc="cc"

if [ "$(uname -s)" = "OpenBSD" -o "$(uname -s)" = "FreeBSD" -o "$(uname -s)" = "NetBSD" ]; then
	echo "Detected *BSD"
	tar="gtar"
elif [ "$(uname -s)" = "SunOS" ]; then
	echo "Detected SunOS"
	tar="gtar"
	CFLAGS="$CFLAGS -DSOLARIS -m64"
	LDFLAGS="$LDFLAGS -lnsl -lsocket"
elif [ "$(uname -s)" = "Darwin" ]; then
	echo "Detected Mac OS X (Darwin)"
	CFLAGS="$CFLAGS -arch i686"
	LDFLAGS="$LDFLAGS -arch i686"
fi

echo Cleaning up...
rm -rf out/ obj/ tmp/

mkdir -p out
echo Creating source archive...
$tar --transform "s,^,quicktun-`cat version`/," -czf "out/quicktun-`cat version`.tgz" build.sh clean.sh debian src version --exclude "debian/data"

mkdir -p obj tmp tmp/include

export LIBRARY_PATH="/usr/local/lib/:${LIBRARY_PATH}"

echo '#include <sodium/crypto_box_curve25519xsalsa20poly1305.h>' > tmp/libtest1.c
echo '#include <nacl/crypto_box_curve25519xsalsa20poly1305.h>' > tmp/libtest2.c
if $cc -shared -lsodium tmp/libtest1.c -o tmp/libtest 2>/dev/null; then
	echo Using shared libsodium.
	echo '#include <sodium/crypto_box_curve25519xsalsa20poly1305.h>' > tmp/include/crypto_box_curve25519xsalsa20poly1305.h
	echo '#include <sodium/crypto_scalarmult_curve25519.h>' > tmp/include/crypto_scalarmult_curve25519.h
	export CPATH="./tmp/include/:${CPATH}"
	export CRYPTLIB="sodium"
elif $cc -shared -lnacl tmp/libtest2.c -o tmp/libtest 2>/dev/null; then
	echo Using shared libnacl.
	echo '#include <nacl/crypto_box_curve25519xsalsa20poly1305.h>' > tmp/include/crypto_box_curve25519xsalsa20poly1305.h
	echo '#include <nacl/crypto_scalarmult_curve25519.h>' > tmp/include/crypto_scalarmult_curve25519.h
	export CPATH="./tmp/include/:${CPATH}"
	export CRYPTLIB="nacl"
else
	mkdir -p lib include
	echo Checking for NaCl library...
	if [ -e lib/libnacl.a -a -e include/crypto_box_curve25519xsalsa20poly1305.h -a -e include/crypto_scalarmult_curve25519.h ]; then
		echo Found.
	else
		echo Not found, building...
		mkdir tmp/nacl
		cd tmp/nacl
		NACLURL="http://hyperelliptic.org/nacl/nacl-20110221.tar.bz2"
		(wget -q -O- "${NACLURL}" || curl -q "${NACLURL}") | bunzip2 | $tar -xf - --strip-components 1
		./do
		cd ../../
		NACLDIR="tmp/nacl/build/`hostname | sed 's/\..*//' | tr -cd '[a-z][A-Z][0-9]'`"
		ABI=`"${NACLDIR}/bin/okabi" | head -n 1`
		cp "${NACLDIR}/lib/${ABI}/libnacl.a" lib/
		cp "${NACLDIR}/include/${ABI}/crypto_box_curve25519xsalsa20poly1305.h" include/
		cp "${NACLDIR}/include/${ABI}/crypto_scalarmult_curve25519.h" include/
		echo Done.
	fi
	export CPATH="./include/:${CPATH}"
	export LIBRARY_PATH="./lib/:${LIBRARY_PATH}"
	export CRYPTLIB="nacl"
fi

CFLAGS="$CFLAGS -DQT_VERSION=\"`cat version`\""

echo Building combined binary...
$cc $CFLAGS -c -DCOMBINED_BINARY	src/proto.raw.c		-o obj/proto.raw.o
$cc $CFLAGS -c -DCOMBINED_BINARY	src/proto.nacl0.c	-o obj/proto.nacl0.o
$cc $CFLAGS -c -DCOMBINED_BINARY	src/proto.nacltai.c	-o obj/proto.nacltai.o
$cc $CFLAGS -c -DCOMBINED_BINARY	src/proto.salty.c	-o obj/proto.salty.o
$cc $CFLAGS -c -DCOMBINED_BINARY	src/run.combined.c	-o obj/run.combined.o
$cc $CFLAGS -c				src/common.c		-o obj/common.o
$cc $CFLAGS -o out/quicktun.combined obj/common.o obj/run.combined.o obj/proto.raw.o obj/proto.nacl0.o obj/proto.nacltai.o obj/proto.salty.o -l$CRYPTLIB $LDFLAGS
ln out/quicktun.combined out/quicktun

echo Building single protocol binaries...
$cc $CFLAGS -o out/quicktun.raw		src/proto.raw.c				$LDFLAGS
$cc $CFLAGS -o out/quicktun.nacl0	src/proto.nacl0.c	-l$CRYPTLIB	$LDFLAGS
$cc $CFLAGS -o out/quicktun.nacltai	src/proto.nacltai.c	-l$CRYPTLIB	$LDFLAGS
$cc $CFLAGS -o out/quicktun.salty	src/proto.salty.c	-l$CRYPTLIB	$LDFLAGS
$cc $CFLAGS -o out/quicktun.keypair	src/keypair.c		-l$CRYPTLIB	$LDFLAGS

if [ -f /etc/network/interfaces ]; then
	echo Building debian binary...
	$cc $CFLAGS -c -DCOMBINED_BINARY -DDEBIAN_BINARY src/run.combined.c -o obj/run.debian.o
	$cc $CFLAGS -o out/quicktun.debian obj/common.o obj/run.debian.o obj/proto.raw.o obj/proto.nacl0.o obj/proto.nacltai.o obj/proto.salty.o -l$CRYPTLIB $LDFLAGS
	if [ -x /usr/bin/dpkg-deb -a -x /usr/bin/fakeroot ]; then
		echo -n Building debian package...
		cd debian
		./build.sh
		cd ..
	fi
fi

