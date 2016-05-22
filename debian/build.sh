#!/bin/sh
set -e
VERSION=`cat ../version`-0
ARCH=`dpkg --print-architecture`
rm -r data 2>/dev/null || true
cp -r static data
mkdir -p data/usr data/usr/sbin data/DEBIAN
sed "s/%ARCHITECTURE%/${ARCH}/" -i data/DEBIAN/control
sed "s/%VERSION%/${VERSION}/" -i data/DEBIAN/control
if [ -n "${NACL_SHARED}" ]; then
	sed "s/\\(Depends: .*\\)/\\1, libnacl | libnacl-ref | libnacl-build/" -i data/DEBIAN/control
fi
cp ../quicktun data/usr/sbin/
cp ../quicktun-keypair data/usr/sbin/
fakeroot dpkg-deb --build data quicktun-${VERSION}_${ARCH}.deb
mv quicktun*.deb ../../
