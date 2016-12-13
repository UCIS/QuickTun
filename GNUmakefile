#
# Copyright 2016 (c) Andreas Rottmann <mail@rotty.xx.vu>. Licensed
# under the 2-clause BSD license (see
# <https://opensource.org/licenses/BSD-2-Clause>).
#

#
# User-configurable settings (can be overridden via make command line)
#

# Preprocessor, compiler and linker flags
CPPFLAGS =
CFLAGS = -Wall -g -O2
LDFLAGS = -g

# Should refer to GNU tar, adjust via command line if needed
TAR = tar
# The list of protocols that should be built into the quicktun binary
PROTOCOLS = raw nacl0 nacltai salty
# Crypto library to use, may be "sodium" or "nacl"
CRYPTLIB = sodium

# Required libraries (non-OS-specific)
LDLIBS += -l$(CRYPTLIB)

#
# OS detection
#
OSNAME = $(shell uname -s)

ifeq ($(shell uname -s | sed -E 's/^(Open|Net|Free)BSD$$/BSD/'),BSD)
TAR = gtar
CPPFLAGS += -I/usr/local/include
LDFLAGS += -L/usr/local/lib
endif

ifeq ($(OSNAME),SunOS)
TAR = gtar
CFLAGS += -m64
CPPFLAGS += -DSOLARIS
LDLIBS += -lnsl -lsocket
endif

ifeq ($(OSNAME),Darwin)
TAR = gtar
CFLAGS += -arch i686
LDFLAGS += -arch i686
endif

#
# What follows does the actual work
#

all: quicktun quicktun-keypair

CFLAGS += -DQT_VERSION="\"$(shell cat version)\"" 	\
	  $(patsubst %,-DQT_PROTO_%,$(PROTOCOLS)) 	\
	  -DQT_CRYPTLIB_$(CRYPTLIB)			\
	  $(NULL)

OBJECTS = $(patsubst %,src/proto.%.o,$(PROTOCOLS)) src/common.o src/protos.o src/main.o

quicktun: $(OBJECTS)
	$(CC) $(LDFLAGS) -o $@ $^ $(LDLIBS)

quicktun-keypair: src/keypair.o src/common.o
	$(CC) $(LDFLAGS) -o $@ $^ $(LDLIBS)

clean:
	rm -f quicktun $(OBJECTS)
	rm -f quicktun-keypair src/keypair.o

dist:
	$(TAR) --transform "s,^,quicktun-`cat version`/," -czf "quicktun-`cat version`.tar.gz" GNUmakefile README.md src version

$(OBJECTS): src/common.h

.PHONY: all clean dist
