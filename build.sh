#!/bin/sh
set -e

tar="tar"
cc="cc"

if [ "$(uname -s)" = "OpenBSD" -o "$(uname -s)" = "FreeBSD" -o "$(uname -s)" = "NetBSD" ]; then
	echo "Detected *BSD"
	tar="gtar"
	export CPATH="/usr/local/include:${CPATH}"
elif [ "$(uname -s)" = "SunOS" ]; then
	echo "Detected SunOS"
	tar="gtar"
	CFLAGS="$CFLAGS -DSOLARIS -m64"
	LDFLAGS="$LDFLAGS -lnsl -lsocket"
elif [ "$(uname -s)" = "Darwin" ]; then
	echo "Detected Mac OS X (Darwin)"
	tar="gnutar"
	cc="clang"
fi

echo Cleaning up...
rm -rf out/ obj/ tmp/

mkdir -p out
if [ "$1" != "debian" ]; then
	echo Creating source archive...
	$tar --transform "s,^,quicktun-`cat version`/," --exclude "debian/data" -czf "out/quicktun-`cat version`.tgz" build.sh clean.sh deb src version
fi

mkdir -p obj tmp tmp/include

export LIBRARY_PATH="/usr/local/lib/:${LIBRARY_PATH}"

echo '#include <sodium/crypto_box_curve25519xsalsa20poly1305.h>' > tmp/libtest1.c
echo '#include <nacl/crypto_box_curve25519xsalsa20poly1305.h>' > tmp/libtest2.c
if [ "$1" = "debian" ] || $cc -shared -lsodium tmp/libtest1.c -o tmp/libtest 2>/dev/null; then
	echo Using shared libsodium.
	echo '#include <sodium/crypto_box_curve25519xsalsa20poly1305.h>' > tmp/include/crypto_box_curve25519xsalsa20poly1305.h
	echo '#include <sodium/crypto_scalarmult_curve25519.h>' > tmp/include/crypto_scalarmult_curve25519.h
	export CPATH="./tmp/include/:${CPATH}"
	export CRYPTLIB="-lsodium"
elif $cc -shared -lnacl tmp/libtest2.c -o tmp/libtest 2>/dev/null; then
	echo Using shared libnacl.
	echo '#include <nacl/crypto_box_curve25519xsalsa20poly1305.h>' > tmp/include/crypto_box_curve25519xsalsa20poly1305.h
	echo '#include <nacl/crypto_scalarmult_curve25519.h>' > tmp/include/crypto_scalarmult_curve25519.h
	export CPATH="./tmp/include/:${CPATH}"
	export CRYPTLIB="-lnacl"
else
	echo Building TweetNaCl...
	echo 'The TweetNaCl cryptography library is not optimized for performance. Please install libsodium or libnacl before building QuickTun for best performance.'
	$cc $CFLAGS -c src/tweetnacl.c -o obj/tweetnacl.o
	$cc $CFLAGS -c src/randombytes.c -o obj/randombytes.o
	echo '#include <src/tweetnacl.h>' > tmp/include/crypto_box_curve25519xsalsa20poly1305.h
	echo '#include <src/tweetnacl.h>' > tmp/include/crypto_scalarmult_curve25519.h
	export CPATH="./tmp/include/:${CPATH}"
	export CRYPTLIB="obj/randombytes.o obj/tweetnacl.o"
fi

CFLAGS="$CFLAGS -DQT_VERSION=\"`cat version`\""

echo Building combined binary...
$cc $CFLAGS -c -DCOMBINED_BINARY	src/proto.raw.c		-o obj/proto.raw.o
$cc $CFLAGS -c -DCOMBINED_BINARY	src/proto.nacl0.c	-o obj/proto.nacl0.o
$cc $CFLAGS -c -DCOMBINED_BINARY	src/proto.nacltai.c	-o obj/proto.nacltai.o
$cc $CFLAGS -c -DCOMBINED_BINARY	src/proto.salty.c	-o obj/proto.salty.o
$cc $CFLAGS -c -DCOMBINED_BINARY	src/run.combined.c	-o obj/run.combined.o
$cc $CFLAGS -c				src/common.c		-o obj/common.o
$cc $CFLAGS -o out/quicktun.combined obj/common.o obj/run.combined.o obj/proto.raw.o obj/proto.nacl0.o obj/proto.nacltai.o obj/proto.salty.o $CRYPTLIB $LDFLAGS
ln out/quicktun.combined out/quicktun

echo Building single protocol binaries...
$cc $CFLAGS -o out/quicktun.raw		src/proto.raw.c				$LDFLAGS
$cc $CFLAGS -o out/quicktun.nacl0	src/proto.nacl0.c	$CRYPTLIB	$LDFLAGS
$cc $CFLAGS -o out/quicktun.nacltai	src/proto.nacltai.c	$CRYPTLIB	$LDFLAGS
$cc $CFLAGS -o out/quicktun.salty	src/proto.salty.c	$CRYPTLIB	$LDFLAGS
$cc $CFLAGS -o out/quicktun.keypair	src/keypair.c		$CRYPTLIB	$LDFLAGS

if [ -f /etc/network/interfaces -o "$1" = "debian" ]; then
	echo Building debian binary...
	$cc $CFLAGS -c -DCOMBINED_BINARY -DDEBIAN_BINARY src/run.combined.c -o obj/run.debian.o
	$cc $CFLAGS -o out/quicktun.debian obj/common.o obj/run.debian.o obj/proto.raw.o obj/proto.nacl0.o obj/proto.nacltai.o obj/proto.salty.o $CRYPTLIB $LDFLAGS
	if [ "$1" != "debian" -a -x /usr/bin/dpkg-deb -a -x /usr/bin/fakeroot ]; then
		echo -n Building debian package...
		cd deb
		./build.sh
		cd ..
	fi
fi

