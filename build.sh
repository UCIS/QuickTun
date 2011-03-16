#!/bin/sh

if [ "$(uname -s)" = "OpenBSD" -o "$(uname -s)" = "FreeBSD" ]; then
	echo "Detected *BSD"
	tar="gtar"
elif [ "$(uname -s)" = "SunOS" ]; then
	echo "Detected SunOS"
	tar="gtar"
	CFLAGS="$CFLAGS -DSOLARIS -m64"
	LDFLAGS="$LDFLAGS -lnsl -lsocket"
else
	tar="tar"
fi

echo Cleaning up...
rm -rf out/ obj/ tmp/

mkdir -p out
echo Creating source archive...
$tar --transform "s,^,quicktun-`cat version`/," -czf "out/quicktun-`cat version`.tgz" build.sh clean.sh debian src version --exclude "debian/data"

mkdir -p obj tmp

export LIBRARY_PATH="/usr/local/lib/:${LIBRARY_PATH}"
if [ -z "${NACL_SHARED}" ]; then
	mkdir -p lib include
	echo Checking for NaCl library...
	if [ -e lib/libnacl.a -a -e include/crypto_box_curve25519xsalsa20poly1305.h -a -e include/crypto_scalarmult_curve25519.h ]; then
		echo Found.
	else
		echo Not found, building...
		mkdir tmp/nacl
		cd tmp/nacl
		wget -q -O- http://hyperelliptic.org/nacl/nacl-20110221.tar.bz2 | bunzip2 | $tar -xf - --strip-components 1
		./do
		cd ../../
		cp tmp/nacl/build/*/lib/*/libnacl.a lib/
		cp tmp/nacl/build/*/include/*/crypto_box_curve25519xsalsa20poly1305.h include/
		cp tmp/nacl/build/*/include/*/crypto_scalarmult_curve25519.h include/
		echo Done.
	fi
	export CPATH="./include/:${CPATH}"
	export LIBRARY_PATH="/usr/local/lib/:./lib/:${LIBRARY_PATH}"
else
	echo Using shared NaCl library.
	export CPATH="/usr/include/nacl/:${CPATH}"
fi

echo Building combined binary...
gcc $CFLAGS -c -DCOMBINED_BINARY	src/proto.raw.c		-o obj/proto.raw.o
gcc $CFLAGS -c -DCOMBINED_BINARY	src/proto.nacl0.c	-o obj/proto.nacl0.o
gcc $CFLAGS -c -DCOMBINED_BINARY	src/proto.nacltai.c	-o obj/proto.nacltai.o
gcc $CFLAGS -c -DCOMBINED_BINARY	src/run.combined.c	-o obj/run.combined.o
gcc $CFLAGS -c 				src/common.c		-o obj/common.o
gcc $CFLAGS -o out/quicktun.combined obj/common.o obj/run.combined.o obj/proto.raw.o obj/proto.nacl0.o obj/proto.nacltai.o -lnacl $LDFLAGS

echo Building single protocol binaries...
gcc $CFLAGS -o out/quicktun.raw		src/proto.raw.c 		$LDFLAGS
gcc $CFLAGS -o out/quicktun.nacl0	src/proto.nacl0.c	-lnacl	$LDFLAGS
gcc $CFLAGS -o out/quicktun.nacltai	src/proto.nacltai.c	-lnacl	$LDFLAGS
gcc $CFLAGS -o out/quicktun.keypair	src/keypair.c		-lnacl	$LDFLAGS

if [ -f /etc/network/interfaces ]; then
	echo Building debian binary...
	gcc $CFLAGS -c -DCOMBINED_BINARY -DDEBIAN_BINARY src/run.combined.c -o obj/run.debian.o
	gcc $CFLAGS -o out/quicktun.debian obj/common.o obj/run.debian.o obj/proto.raw.o obj/proto.nacl0.o obj/proto.nacltai.o -lnacl $LDFLAGS
	if [ -x /usr/bin/dpkg-deb -a -x /usr/bin/fakeroot ]; then
		echo -n Building debian package...
		cd debian
		./build.sh
		cd ..
	fi
fi

rm -rf obj tmp
