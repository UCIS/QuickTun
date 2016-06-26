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
#include "crypto_scalarmult_curve25519.h"
#include <sys/types.h>
#include <sys/time.h>

struct packedtaia {
	unsigned char buffer[16];
};

struct qt_proto_data_nacltai {
	unsigned char cenonce[crypto_box_curve25519xsalsa20poly1305_NONCEBYTES], cdnonce[crypto_box_curve25519xsalsa20poly1305_NONCEBYTES];
	unsigned char cbefore[crypto_box_curve25519xsalsa20poly1305_BEFORENMBYTES];
	struct packedtaia cdtailog[5];
};

#define noncelength 16
#define nonceoffset (crypto_box_curve25519xsalsa20poly1305_NONCEBYTES - noncelength)
static const int overhead                 = crypto_box_curve25519xsalsa20poly1305_BOXZEROBYTES + noncelength;

static void taia_now_packed(unsigned char* b, int secoffset) {
	struct timeval now;
	gettimeofday(&now, NULL);
	u_int64_t sec = 4611686018427387914ULL + (u_int64_t)now.tv_sec + secoffset;
	b[0] = (sec >> 56) & 0xff;
	b[1] = (sec >> 48) & 0xff;
	b[2] = (sec >> 40) & 0xff;
	b[3] = (sec >> 32) & 0xff;
	b[4] = (sec >> 24) & 0xff;
	b[5] = (sec >> 16) & 0xff;
	b[6] = (sec >> 8) & 0xff;
	b[7] = (sec >> 0) & 0xff;
	u_int32_t nano = 1000 * now.tv_usec + 500;
	b[8] = (nano >> 24) & 0xff;
	b[9] = (nano >> 16) & 0xff;
	b[10] = (nano >> 8) & 0xff;
	b[11] = (nano >> 0) & 0xff;
	if (++b[15] == 0 && ++b[14] == 0 && ++b[13] == 0) ++b[12];
}

//Packet format: <16 bytes taia packed timestamp><16 bytes checksum><n bytes encrypted data>

static int encode(struct qtsession* sess, char* raw, char* enc, int len) {
	if (debug) fprintf(stderr, "Encoding packet of %d bytes from %p to %p\n", len, raw, enc);
	struct qt_proto_data_nacltai* d = (struct qt_proto_data_nacltai*)sess->protocol_data;
	memset(raw, 0, crypto_box_curve25519xsalsa20poly1305_ZEROBYTES);
	taia_now_packed(d->cenonce + nonceoffset, 0);
	if (crypto_box_curve25519xsalsa20poly1305_afternm((unsigned char*)enc, (unsigned char*)raw, len + crypto_box_curve25519xsalsa20poly1305_ZEROBYTES, d->cenonce, d->cbefore)) return errorexit("Encryption failed");
	memcpy((void*)(enc + crypto_box_curve25519xsalsa20poly1305_BOXZEROBYTES - noncelength), d->cenonce + nonceoffset, noncelength);
	len += overhead;
	if (debug) fprintf(stderr, "Encoded packet of %d bytes from %p to %p\n", len, raw, enc);
	return len;
}

static int decode(struct qtsession* sess, char* enc, char* raw, int len) {
	if (debug) fprintf(stderr, "Decoding packet of %d bytes from %p to %p\n", len, enc, raw);
	struct qt_proto_data_nacltai* d = (struct qt_proto_data_nacltai*)sess->protocol_data;
	int i;
	if (len < overhead) {
		fprintf(stderr, "Short packet received: %d\n", len);
		return -1;
	}
	len -= overhead;
	struct packedtaia* tailog = &d->cdtailog[0];
	struct packedtaia* taiold = tailog;
	for (i = 0; i < 5; i++) {
		if (memcmp(enc, tailog, 16) == 0) {
			fprintf(stderr, "Duplicate timestamp received\n");
			return -1;
		}
		if (memcmp(tailog, taiold, 16) < 0) taiold = tailog;
		tailog++;
	}
	if (memcmp(enc, taiold, 16) <= 0) {
		fprintf(stderr, "Timestamp going back, ignoring packet\n");
		return -1;
	}
	memcpy(d->cdnonce + nonceoffset, enc, noncelength);
	memset(enc, 0, crypto_box_curve25519xsalsa20poly1305_BOXZEROBYTES);
	if (crypto_box_curve25519xsalsa20poly1305_open_afternm((unsigned char*)raw, (unsigned char*)enc, len + crypto_box_curve25519xsalsa20poly1305_ZEROBYTES, d->cdnonce, d->cbefore)) {
		fprintf(stderr, "Decryption failed len=%d\n", len);
		return -1;
	}
	memcpy(taiold, d->cdnonce + nonceoffset, 16);
	if (debug) fprintf(stderr, "Decoded packet of %d bytes from %p to %p\n", len, enc, raw);
	return len;
}

static int init(struct qtsession* sess) {
	struct qt_proto_data_nacltai* d = (struct qt_proto_data_nacltai*)sess->protocol_data;
	char* envval;
	printf("Initializing cryptography...\n");
	unsigned char cownpublickey[crypto_box_curve25519xsalsa20poly1305_PUBLICKEYBYTES], cpublickey[crypto_box_curve25519xsalsa20poly1305_PUBLICKEYBYTES], csecretkey[crypto_box_curve25519xsalsa20poly1305_SECRETKEYBYTES];
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
	if (crypto_box_curve25519xsalsa20poly1305_beforenm(d->cbefore, cpublickey, csecretkey) != 0) {
		return -1;
        }

	memset(d->cenonce, 0, crypto_box_curve25519xsalsa20poly1305_NONCEBYTES);
	memset(d->cdnonce, 0, crypto_box_curve25519xsalsa20poly1305_NONCEBYTES);
	memset(d->cdtailog, 0, 5 * 16);

	crypto_scalarmult_curve25519_base(cownpublickey, csecretkey);

	if ((envval = getconf("TIME_WINDOW"))) {
		struct packedtaia* tailog = d->cdtailog;
		taia_now_packed((unsigned char*)&tailog[0], -atol(envval));
		tailog[4] = tailog[3] = tailog[2] = tailog[1] = tailog[0];
	} else {
		fprintf(stderr, "Warning: TIME_WINDOW not set, risking an initial replay attack\n");
	}
	int role = memcmp(cownpublickey, cpublickey, crypto_box_curve25519xsalsa20poly1305_PUBLICKEYBYTES);
	if ((envval = getconf("ROLE"))) role = atoi(envval) ? 1 : -1;
	role = (role == 0) ? 0 : ((role > 0) ? 1 : 2);
	d->cenonce[nonceoffset-1] = role & 1;
	d->cdnonce[nonceoffset-1] = (role >> 1) & 1;
	return 0;
}

struct qtproto qtproto_nacltai = {
	1,
	MAX_PACKET_LEN + crypto_box_curve25519xsalsa20poly1305_ZEROBYTES,
	MAX_PACKET_LEN + crypto_box_curve25519xsalsa20poly1305_ZEROBYTES,
	crypto_box_curve25519xsalsa20poly1305_ZEROBYTES,
	crypto_box_curve25519xsalsa20poly1305_BOXZEROBYTES - noncelength,
	encode,
	decode,
	init,
	sizeof(struct qt_proto_data_nacltai),
};

#ifndef COMBINED_BINARY
int main(int argc, char** argv) {
	print_header();
	if (qtprocessargs(argc, argv) < 0) return -1;
	return qtrun(&qtproto_nacltai);
}
#endif
