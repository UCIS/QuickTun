#!/bin/sh
echo Cleaning up...
rm -rf out/ obj/ tmp/

mkdir -p out
echo Creating source archive...
tar --transform "s,^\.,quicktun-`cat version`/," -czf "out/quicktun-`cat version`.tgz" . --exclude "./out" --exclude "./lib" --exclude "./debian/data"

mkdir -p obj tmp lib

echo -n Checking for NaCl library...
if [ ! -e lib/libnacl.a ]; then
	echo -n building...
	mkdir tmp/nacl
	cd tmp/nacl
	wget -q -O- http://hyperelliptic.org/nacl/nacl-20090405.tar.bz2 | bunzip2 | tar -xf - --strip-components 1
	./do
	cd ../../
	cp tmp/nacl/build/*/lib/*/libnacl.a lib/
	cp tmp/nacl/build/*/include/*/crypto_box.h include/
	cp tmp/nacl/build/*/include/*/crypto_box_curve25519salsa20hmacsha512.h include/
	cp tmp/nacl/build/*/include/*/crypto_box_curve25519xsalsa20poly1305.h include/
fi
echo Done.

export CPATH=./include/
export LIBRARY_PATH=/usr/local/lib/:./lib/

echo Building combined binary...
gcc -c -DCOMBINED_BINARY	src/proto.raw.c		-o obj/proto.raw.o
gcc -c -DCOMBINED_BINARY	src/crypto_scalarmult_curve25519.c	-o obj/crypto_scalarmult_curve25519.o 
gcc -c -DCOMBINED_BINARY	src/proto.nacl0.c	-o obj/proto.nacl0.o
gcc -c -DCOMBINED_BINARY	src/proto.nacltai.c	-o obj/proto.nacltai.o
gcc -c -DCOMBINED_BINARY	src/run.combined.c	-o obj/run.combined.o
gcc -c 				src/common.c		-o obj/common.o
gcc -o out/quicktun.combined obj/common.o obj/run.combined.o obj/proto.raw.o obj/proto.nacl0.o obj/proto.nacltai.o obj/crypto_scalarmult_curve25519.o -lnacl

echo Building single protocol binaries...
gcc -o out/quicktun.raw		src/proto.raw.c
gcc -o out/quicktun.nacl0	src/proto.nacl0.c	-lnacl
gcc -o out/quicktun.nacltai	src/proto.nacltai.c src/crypto_scalarmult_curve25519.c	-lnacl
gcc -o out/quicktun.keypair	src/keypair.c		-lnacl

echo Building shared libraries...
gcc -fPIC -shared -Wl,-soname,quicktun.raw -o out/libquicktun.raw src/proto.raw.c
##gcc -fPIC -shared -Wl,-soname,quicktun.nacl0 -o out/libquicktun.nacl0 src/proto.nacl0.c -lnacl

##echo Building frontends...
##gcc -o out/quicktun.debian	src/run.debian.c -ldl

if [ -x /usr/bin/dpkg-deb -a -x /usr/bin/fakeroot ]; then
	echo Building debian binary...
	gcc -c -DCOMBINED_BINARY -DDEBIAN_BINARY src/run.combined.c -o obj/run.debian.o
	gcc -o out/quicktun.debian obj/common.o obj/run.debian.o obj/proto.raw.o obj/proto.nacl0.o obj/proto.nacltai.o obj/crypto_scalarmult_curve25519.o -lnacl
	echo -n Building debian package...
	cd debian
	./build.sh
	cd ..
fi
