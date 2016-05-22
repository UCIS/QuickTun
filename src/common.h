/* Copyright 2010 Ivo Smits <Ivo@UCIS.nl>. All rights reserved.
   Redistribution and use in source and binary forms, with or without modification, are
   permitted provided that the following conditions are met:

   1. Redistributions of source code must retain the above copyright notice, this list of
      conditions and the following disclaimer.

   2. Redistributions in binary form must reproduce the above copyright notice, this list
      of conditions and the following disclaimer in the documentation and/or other materials
      provided with the distribution.

   THIS SOFTWARE IS PROVIDED ``AS IS'' AND ANY EXPRESS OR IMPLIED
   WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND
   FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE AUTHORS OR
   CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
   CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
   SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON
   ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING
   NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF
   ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

   The views and conclusions contained in the software and documentation are those of the
   authors and should not be interpreted as representing official policies, either expressed
   or implied, of Ivo Smits.*/

#ifndef COMMON_H_
#define COMMON_H_ 1

#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <unistd.h>

#include <netinet/in.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <net/if.h>
#ifdef linux
	#include <linux/if_tun.h>
	#include <linux/if_ether.h>
#else
	#define ETH_FRAME_LEN 1514
	#include <net/if_tun.h>
	#ifdef SOLARIS
		#include <sys/stropts.h>
		#include <sys/sockio.h>
	#endif
#endif

#ifdef QT_CRYPTLIB_sodium
#include <sodium/crypto_box_curve25519xsalsa20poly1305.h>
#include <sodium/crypto_scalarmult_curve25519.h>
#else
#include <nacl/crypto_box_curve25519xsalsa20poly1305.h>
#include <nacl/crypto_scalarmult_curve25519.h>
#endif

#define MAX_PACKET_LEN (ETH_FRAME_LEN+4) //Some space for optional packet information

typedef union {
	struct sockaddr any;
	struct sockaddr_in ip4;
	struct sockaddr_in6 ip6;
} sockaddr_any;

struct qtsession;
struct qtproto {
	int encrypted;
	int buffersize_raw;
	int buffersize_enc;
	int offset_raw;
	int offset_enc;
	int (*encode)(struct qtsession* sess, char* raw, char* enc, int len);
	int (*decode)(struct qtsession* sess, char* enc, char* raw, int len);
	int (*init)(struct qtsession* sess);
	int protocol_data_size;
	void (*idle)(struct qtsession* sess);
};
struct qtsession {
	struct qtproto protocol;
	void* protocol_data;
	int fd_socket;
	int fd_dev;
	int remote_float;
	sockaddr_any remote_addr;
	int use_pi;
	int poll_timeout;
	void (*sendnetworkpacket)(struct qtsession* sess, char* msg, int len);
};

char* (*getconf)(const char*);
int errorexit(const char*);
int errorexitp(const char*);
void print_header();
void hex2bin(unsigned char*, const char*, const int);
int debug;
int qtrun(struct qtproto* p);
int qtprocessargs(int argc, char** argv);

struct qtproto *getproto(const char *name);

#endif
