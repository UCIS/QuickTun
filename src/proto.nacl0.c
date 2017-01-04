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

#include "common.c"
#include "crypto_box_curve25519xsalsa20poly1305.h"

struct qt_proto_data_nacl0 {
	unsigned char cnonce[crypto_box_curve25519xsalsa20poly1305_NONCEBYTES], cbefore[crypto_box_curve25519xsalsa20poly1305_BEFORENMBYTES];
};

static int encode(struct qtsession* sess, char* raw, char* enc, int len) {
	struct qt_proto_data_nacl0* d = (struct qt_proto_data_nacl0*)sess->protocol_data;
	memset(raw, 0, crypto_box_curve25519xsalsa20poly1305_ZEROBYTES);
	if (crypto_box_curve25519xsalsa20poly1305_afternm((unsigned char*)enc, (unsigned char*)raw, len+crypto_box_curve25519xsalsa20poly1305_ZEROBYTES, d->cnonce, d->cbefore)) return errorexit("Crypto failed");
	return len + crypto_box_curve25519xsalsa20poly1305_BOXZEROBYTES;
}

static int decode(struct qtsession* sess, char* enc, char* raw, int len) {
	struct qt_proto_data_nacl0* d = (struct qt_proto_data_nacl0*)sess->protocol_data;
	if (len < crypto_box_curve25519xsalsa20poly1305_BOXZEROBYTES) {
		fprintf(stderr, "Short packet received: %d\n", len);
		return -1;
	}
	len -= crypto_box_curve25519xsalsa20poly1305_BOXZEROBYTES;
	memset(enc, 0, crypto_box_curve25519xsalsa20poly1305_BOXZEROBYTES);
	if (crypto_box_curve25519xsalsa20poly1305_open_afternm((unsigned char*)raw, (unsigned char*)enc, len+crypto_box_curve25519xsalsa20poly1305_ZEROBYTES, d->cnonce, d->cbefore)) {
		fprintf(stderr, "Decryption failed len=%d\n", len);
		return -1;
	}
	return len;
}

static int init(struct qtsession* sess) {
	char* envval;
	struct qt_proto_data_nacl0* d = (struct qt_proto_data_nacl0*)sess->protocol_data;
	printf("Initializing cryptography...\n");
	memset(d->cnonce, 0, crypto_box_curve25519xsalsa20poly1305_NONCEBYTES);
	unsigned char cpublickey[crypto_box_curve25519xsalsa20poly1305_PUBLICKEYBYTES], csecretkey[crypto_box_curve25519xsalsa20poly1305_SECRETKEYBYTES];
	if (!(envval = getconf("PUBLIC_KEY"))) return errorexit("Missing PUBLIC_KEY");
	if (strlen(envval) != 2*crypto_box_curve25519xsalsa20poly1305_PUBLICKEYBYTES) return errorexit("PUBLIC_KEY length");
	hex2bin(cpublickey, envval, crypto_box_curve25519xsalsa20poly1305_PUBLICKEYBYTES);
	if ((envval = getconf("PRIVATE_KEY"))) {
		if (strlen(envval) != 2*crypto_box_curve25519xsalsa20poly1305_PUBLICKEYBYTES) return errorexit("PRIVATE_KEY length");
		hex2bin(csecretkey, envval, crypto_box_curve25519xsalsa20poly1305_SECRETKEYBYTES);
	} else if ((envval = getconf("PRIVATE_KEY_FILE"))) {
		FILE* pkfile = fopen(envval, "rb");
		if (!pkfile) return errorexitp("Could not open PRIVATE_KEY_FILE");
		char pktextbuf[crypto_box_curve25519xsalsa20poly1305_SECRETKEYBYTES * 2];
		const size_t pktextsize = fread(pktextbuf, 1, sizeof(pktextbuf), pkfile);
		if (pktextsize == crypto_box_curve25519xsalsa20poly1305_SECRETKEYBYTES) {
			memcpy(csecretkey, pktextbuf, crypto_box_curve25519xsalsa20poly1305_SECRETKEYBYTES);
		} else if (pktextsize == 2 * crypto_box_curve25519xsalsa20poly1305_SECRETKEYBYTES) {
			hex2bin(csecretkey, pktextbuf, crypto_box_curve25519xsalsa20poly1305_SECRETKEYBYTES);
		} else {
			return errorexit("PRIVATE_KEY length");
		}
		fclose(pkfile);
	} else {
		return errorexit("Missing PRIVATE_KEY");
	}
	return crypto_box_curve25519xsalsa20poly1305_beforenm(d->cbefore, cpublickey, csecretkey);
}

struct qtproto qtproto_nacl0 = {
	1,
	MAX_PACKET_LEN + crypto_box_curve25519xsalsa20poly1305_ZEROBYTES,
	MAX_PACKET_LEN + crypto_box_curve25519xsalsa20poly1305_BOXZEROBYTES + crypto_box_curve25519xsalsa20poly1305_BOXZEROBYTES,
	crypto_box_curve25519xsalsa20poly1305_ZEROBYTES,
	crypto_box_curve25519xsalsa20poly1305_BOXZEROBYTES,
	encode,
	decode,
	init,
	sizeof(struct qt_proto_data_nacl0),
};

#ifndef COMBINED_BINARY
int main(int argc, char** argv) {
	print_header();
	int rc = qtprocessargs(argc, argv);
	if (rc <= 0) return rc;
	return qtrun(&qtproto_nacl0);
}
#endif
