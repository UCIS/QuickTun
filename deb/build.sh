#!/bin/sh
set -e
VERSION=`cat ../version`-0
if [ ! $ARCH ]; then
	ARCH=`dpkg --print-architecture`
fi
rm -r data 2>/dev/null || true
cp -r static data
mkdir -p data/usr data/usr/sbin data/DEBIAN
sed "s/%ARCHITECTURE%/${ARCH}/" -i data/DEBIAN/control
sed "s/%VERSION%/${VERSION}/" -i data/DEBIAN/control
if [ -n "${NACL_SHARED}" ]; then
	sed "s/\\(Depends: .*\\)/\\1, libnacl | libnacl-ref | libnacl-build/" -i data/DEBIAN/control
fi
cp ../out/quicktun.raw data/usr/sbin/
cp ../out/quicktun.nacl0 data/usr/sbin/
cp ../out/quicktun.nacltai data/usr/sbin/
cp ../out/quicktun.debian data/usr/sbin/
cp ../out/quicktun.keypair data/usr/sbin/
cp ../out/quicktun data/usr/sbin/
fakeroot dpkg-deb --build data quicktun-${VERSION}_${ARCH}.deb
mv quicktun*.deb ../out/
