#!/bin/sh
VERSION=`cat ../version`-0
ARCH=`dpkg --print-architecture`
rm -r data 2>/dev/null
cp -r static data
mkdir -p data/usr data/usr/sbin data/DEBIAN
sed "s/%ARCHITECTURE%/${ARCH}/" -i data/DEBIAN/control
sed "s/%VERSION%/${VERSION}/" -i data/DEBIAN/control
cp ../out/quicktun.debian data/usr/sbin/
cp ../out/quicktun.keypair data/usr/sbin/
fakeroot dpkg-deb --build data quicktun-${VERSION}_${ARCH}.deb
mv quicktun*.deb ../out/
