/* Copyright 2013 Ivo Smits <Ivo@UCIS.nl>. All rights reserved.
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

/*
QuickTun Salty protocol
A curve25519xsalsa20poly1305 based VPN protocol providing encryption, authentication and PFS.
The Salty protocol is stateful; each side of the connection keeps track of the current and previous state of the local and remote encoder for minimal overhead and little to none packet loss during key transitions.

Wire format:
	3 bit flags + 29 bit time + 16 byte checksum + encrypted data
		flag 7 = 0
		flag 6 = sender key id
		flag 5 = recipient key id
	8 bit flags + 64 bit time + 16 byte checksum + encrypted data
		flag 7 = 1
		encrypted data = 8 bit flags + 32 byte sender key + 24 byte sender nonce + 32 byte recipient key + 24 byte recipient nonce + 64 bit last received and accepted control timestamp
			flag 7 = 0
			flag 6 = sender key id
			flag 5 = recipient key id
			flag 4 = is acknowledgment

Key update (begin):
	Generate new key pair <newkey> and nonce <newnonce> (last 4 bytes in nonce should be 0)
	Set <keys[!<keyid>]> = <newkey>
	Set <nonces[!<keyid>]> = <newnonce>
	Send key update: sender key id = !<keyid>, sender key = <newkey>.Public, nonce = <newnonce>, recipient key id = <remotekeyid>, recipient key = <remotekey>, recipient nonce = <remotenonce>

Key update received:
	Set <remotekeyid> = sender key id
	Set <remotekey> = sender key
	Set <remotenonce> = sender nonce
	If <keys[0]> exists then
		Set <decstate[0][<remotekeyid>]> = decoder(<keys[0]>, <remotekey>, <remotenonce>)
	If <keys[1]> exists then
		Set <decstate[1][<remotekeyid>]> = decoder(<keys[0]>, <remotekey>, <remotenonce>)
	If <keys[recipient key id]> == recipient key && <nonces[recipient key id]> == recipient nonce
		If recipient key id == <keyid> then
			If encoder exists then
				Set encodenonce = encoder.Nonce
			Else
				Set encodenonce = <nonces[<keyid>]>
			Set encoder(<key>, <remotekey>, encodenonce)
		Else if recipient key id == !<keyid> && <newkey> is set
			Set <key> = <newkey>
			Set <keyid> = !<keyid>
			Set <newkey> = NULL
			Set encoder(<key>, <remotekey>, <newnonce>)
		If ! is acknowledgment then
			Send key update: sender key id = <keyid>, sender key = <key>, nonce = <nonces[<keyid>], recipient key id = <remotekeyid>, recipient key = <remotekey>, recipient nonce = <remotenonce>
	Else
		Send key update: sender key id = <keyid>, sender key = <key>, nonce = <nonces[<keyid>], recipient key id = <remotekeyid>, recipient key = <remotekey>, recipient nonce = <remotenonce>

On startup:
	Begin key update

Every 1 minute:
	If <newkey> is set:
		Send key update: sender key id = <keyid>, sender key = <key>, nonce = <nonces[<keyid>], recipient key id = <remotekeyid>, recipient key = <remotekey>, recipient nonce = <remotenonce>

Every 10 minutes:
	Begin key update (if any packets have been sent with current key)

When sending packet:
	If <key> and <remotekey> are set:
		If packets sent with this key == (1<<29)-1
			Switch to <newkey> or drop packet
		If packets sent with this key > (1<<28)
			If <newkey> is set:
				Send key update: sender key id = !<keyid>, sender key = <newkey>.Public, nonce = <newnonce>, recipient key id = <remotekeyid>, recipient key = <remotekey>, recipient nonce = <remotenonce>
			Else
				Begin key update
	Else
		If <newkey> is set:
			Send key update: sender key id = !<keyid>, sender key = <newkey>.Public, nonce = <newnonce>, recipient key id = <remotekeyid>, recipient key = <remotekey>, recipient nonce = <remotenonce>
		Else
			Begin key update

When receiving packet:
	if flag 0 == 1
		If time <= <lastcontroltime> then
			Ignore packet
		Decrypt packet
		Set <lastcontroltime> = time
		Key update received
	Else
		Use decoder decstate[recipient key id][sender key id]
		Find index and value of lowest value in recenttimes as mintime and mintimeidx
		If time <= mintime then
			Ignore packet
		Decode packet
		Set recenttimes[mintimeidx] = time
		Write packet to tunnel
*/

#include "common.c"
#include "crypto_box_curve25519xsalsa20poly1305.h"
#include "crypto_scalarmult_curve25519.h"
#include <sys/types.h>
#include <sys/time.h>
#include <stdbool.h>

#define NONCEBYTES crypto_box_curve25519xsalsa20poly1305_NONCEBYTES
#define BEFORENMBYTES crypto_box_curve25519xsalsa20poly1305_BEFORENMBYTES
#define PRIVATEKEYBYTES crypto_box_curve25519xsalsa20poly1305_SECRETKEYBYTES
#define PUBLICKEYBYTES crypto_box_curve25519xsalsa20poly1305_PUBLICKEYBYTES

typedef unsigned int uint32;
typedef unsigned long long uint64;

struct qt_proto_data_salty_decstate {
	unsigned char remotekey[PUBLICKEYBYTES];
	unsigned char nonce[NONCEBYTES];
	unsigned char sharedkey[BEFORENMBYTES];
	uint32 timestamps[5];
};
struct qt_proto_data_salty_keyset {
	unsigned char privatekey[PRIVATEKEYBYTES];
	unsigned char publickey[PUBLICKEYBYTES];
	unsigned char sharedkey[BEFORENMBYTES];
	unsigned char nonce[NONCEBYTES];
};
struct qt_proto_data_salty {
	time_t lastkeyupdate, lastkeyupdatesent;
	unsigned char controlkey[BEFORENMBYTES];
	int controlroles;
	uint64 controldecodetime;
	uint64 controlencodetime;
	struct qt_proto_data_salty_keyset* dataencoder;
	struct qt_proto_data_salty_keyset datalocalkeys[2];
	int datalocalkeyid;
	int datalocalkeynextid;
	int dataremotekeyid;
	unsigned char dataremotekey[PUBLICKEYBYTES];
	unsigned char dataremotenonce[NONCEBYTES];
	struct qt_proto_data_salty_decstate datadecoders[4];
};

static void encodeuint32(char* b, uint32 v) {
	b[0] = (v >> 24) & 255;
	b[1] = (v >> 16) & 255;
	b[2] = (v >> 8) & 255;
	b[3] = (v >> 0) & 255;
}
static uint32 decodeuint32(char* sb) {
	unsigned char* b = (unsigned char*)sb;
	return (b[0] << 24) | (b[1] << 16) | (b[2] << 8) | b[3];
}
static void encodeuint64(char* b, uint64 v) {
	b[0] = (v >> 56) & 255;
	b[1] = (v >> 48) & 255;
	b[2] = (v >> 40) & 255;
	b[3] = (v >> 32) & 255;
	b[4] = (v >> 24) & 255;
	b[5] = (v >> 16) & 255;
	b[6] = (v >> 8) & 255;
	b[7] = (v >> 0) & 255;
}
static uint64 decodeuint64(char* sb) {
	unsigned char* b = (unsigned char*)sb;
	return ((uint64)b[0] << 56) | ((uint64)b[1] << 48) | ((uint64)b[2] << 40) | ((uint64)b[3] << 32) | ((uint64)b[4] << 24) | ((uint64)b[5] << 16) | ((uint64)b[6] << 8) | (uint64)b[7];
}

static int devurandomfd = -1;

static void dumphex(unsigned char* lbl, unsigned char* buffer, int len) {
	fprintf(stderr, "%s: ", lbl);
	for (; len > 0; len--, buffer++) fprintf(stderr, "%02x", *buffer);
	fprintf(stderr, "\n");
}

static bool randombytes(unsigned char* buffer, int len) {
	if (devurandomfd == -1) devurandomfd = open("/dev/urandom", O_RDONLY);
	if (devurandomfd == -1) return false;
	while (len > 0) {
		int got = read(devurandomfd, buffer, len);
		if (got < 0) return false;
		buffer += got;
		len -= got;
	}
	return true;
}

static void initdecoder(struct qt_proto_data_salty_decstate* d, unsigned char rkey[], unsigned char lkey[], unsigned char nonce[]) {
	memcpy(d->remotekey, rkey, PUBLICKEYBYTES);
	memcpy(d->nonce, nonce, NONCEBYTES);
	memset(d->timestamps, 0, 5 * sizeof(uint32));
	if (debug) dumphex("INIT DECODER SK", lkey, 32);
	if (debug) dumphex("INIT DECODER RK", rkey, 32);
	crypto_box_curve25519xsalsa20poly1305_beforenm(d->sharedkey, rkey, lkey);
}

static void sendkeyupdate(struct qtsession* sess, bool ack) {
	struct qt_proto_data_salty* d = (struct qt_proto_data_salty*)sess->protocol_data;
	unsigned char buffer[32 + (1 + 32 + 24 + 32 + 24 + 8)];
	int keyid = (d->datalocalkeynextid == -1) ? d->datalocalkeyid : d->datalocalkeynextid;
	if (debug) fprintf(stderr, "Sending key update nlkid=%d, rkid=%d, ack=%d\n", keyid, d->dataremotekeyid, ack);
	buffer[32] = (0 << 7) | (keyid << 6) | (d->dataremotekeyid << 5) | (ack ? (1 << 4) : (0 << 4));
	memcpy(buffer + 32 + 1, d->datalocalkeys[keyid].publickey, 32);
	memcpy(buffer + 32 + 1 + 32, d->datalocalkeys[keyid].nonce, 24);
	memcpy(buffer + 32 + 1 + 32 + 24, d->dataremotekey, 32);
	memcpy(buffer + 32 + 1 + 32 + 24 + 32, d->dataremotenonce, 24);
	encodeuint64(buffer + 32 + 1 + 32 + 24 + 32 + 24, d->controldecodetime);
	memset(buffer, 0, 32);
	d->controlencodetime++;
	unsigned char nonce[24];
	memset(nonce, 0, 24);
	nonce[0] = d->controlroles & 1;
	encodeuint64(nonce + 16, d->controlencodetime);
	unsigned char encbuffer[32 + 1 + 32 + 24 + 32 + 24 + 8];
	if (crypto_box_curve25519xsalsa20poly1305_afternm(encbuffer, buffer, 32 + (1 + 32 + 24 + 32 + 24 + 8), nonce, d->controlkey)) return;
	memcpy(encbuffer + 16 - 8, nonce + 16, 8);
	encbuffer[16 - 1 - 8] = 0x80;
	if (sess->sendnetworkpacket) sess->sendnetworkpacket(sess, encbuffer + 16 - 1 - 8, 1 + 8 + 16 + (1 + 32 + 24 + 32 + 24 + 8));
	d->lastkeyupdatesent = time(NULL);
}

static bool beginkeyupdate(struct qtsession* sess) {
	struct qt_proto_data_salty* d = (struct qt_proto_data_salty*)sess->protocol_data;
	d->datalocalkeynextid = (d->datalocalkeyid + 1) % 2;
	if (debug) fprintf(stderr, "Beginning key update nlkid=%d, rkid=%d\n", d->datalocalkeynextid, d->dataremotekeyid);
	struct qt_proto_data_salty_keyset* enckey = &d->datalocalkeys[d->datalocalkeynextid];
	if (!randombytes(enckey->nonce, 20)) return false;
	if (!randombytes(enckey->privatekey, PRIVATEKEYBYTES)) return false;
	crypto_scalarmult_curve25519_base(enckey->publickey, enckey->privatekey);
	memset(enckey->nonce + 20, 0, 4);
	if (debug) dumphex("New public key", enckey->publickey, 32);
	if (debug) dumphex("New base nonce", enckey->nonce, 24);
	initdecoder(&d->datadecoders[(d->dataremotekeyid << 1) | d->datalocalkeynextid], d->dataremotekey, enckey->privatekey, d->dataremotenonce);
	sendkeyupdate(sess, false);
	d->lastkeyupdate = time(NULL);
}

static void beginkeyupdateifnecessary(struct qtsession* sess) {
	struct qt_proto_data_salty* d = (struct qt_proto_data_salty*)sess->protocol_data;
	time_t t = time(NULL);
	if (t - d->lastkeyupdate > 300) {
		beginkeyupdate(sess);
	} else if (d->datalocalkeynextid != -1 && t - d->lastkeyupdatesent > 1) {
		sendkeyupdate(sess, false);
	}
}

static int init(struct qtsession* sess) {
	struct qt_proto_data_salty* d = (struct qt_proto_data_salty*)sess->protocol_data;
	char* envval;
	printf("Initializing cryptography...\n");
	unsigned char cpublickey[PUBLICKEYBYTES], csecretkey[PRIVATEKEYBYTES];
	if (!(envval = getconf("PUBLIC_KEY"))) return errorexit("Missing PUBLIC_KEY");
	if (strlen(envval) != 2*PUBLICKEYBYTES) return errorexit("PUBLIC_KEY length");
	hex2bin(cpublickey, envval, PUBLICKEYBYTES);
	if (envval = getconf("PRIVATE_KEY")) {
		if (strlen(envval) != 2 * PUBLICKEYBYTES) return errorexit("PRIVATE_KEY length");
		hex2bin(csecretkey, envval, PRIVATEKEYBYTES);
	} else if (envval = getconf("PRIVATE_KEY_FILE")) {
		FILE* pkfile = fopen(envval, "rb");
		if (!pkfile) return errorexitp("Could not open PRIVATE_KEY_FILE");
		char pktextbuf[PRIVATEKEYBYTES * 2];
		size_t pktextsize = fread(pktextbuf, 1, sizeof(pktextbuf), pkfile);
		if (pktextsize == PRIVATEKEYBYTES) {
			memcpy(csecretkey, pktextbuf, PRIVATEKEYBYTES);
		} else if (pktextsize = 2 * PRIVATEKEYBYTES) {
			hex2bin(csecretkey, pktextbuf, PRIVATEKEYBYTES);
		} else {
			return errorexit("PRIVATE_KEY length");
		}
		fclose(pkfile);
	} else {
		return errorexit("Missing PRIVATE_KEY");
	}
	crypto_box_curve25519xsalsa20poly1305_beforenm(d->controlkey, cpublickey, csecretkey);
	unsigned char cownpublickey[PUBLICKEYBYTES];
	crypto_scalarmult_curve25519_base(cownpublickey, csecretkey);
	int role = memcmp(cownpublickey, cpublickey, PUBLICKEYBYTES);
	d->controlroles = (role == 0) ? 0 : ((role > 0) ? 1 : 2);
	d->controldecodetime = 0;
	d->controlencodetime = ((uint64)time(NULL)) << 8;
	d->datalocalkeyid = 0;
	d->datalocalkeynextid = -1;
	d->dataremotekeyid = 0;
	beginkeyupdate(sess);
	d->datalocalkeyid = d->datalocalkeynextid;
	sess->poll_timeout = 5000;
	return 0;
}

static int encode(struct qtsession* sess, char* raw, char* enc, int len) {
	beginkeyupdateifnecessary(sess);
	struct qt_proto_data_salty* d = (struct qt_proto_data_salty*)sess->protocol_data;
	struct qt_proto_data_salty_keyset* e = d->dataencoder;
	if (!e) {
		if (debug) fprintf(stderr, "Discarding outgoing packet of %d bytes because encoder is not available\n", len);
		return 0;
	}
	if (debug) fprintf(stderr, "Encoding packet of %d bytes from %p to %p\n", len, raw, enc);
	//Check if nonce has exceeded half of maximum value (key update) or has exceeded maximum value (drop packet)
	if (e->nonce[20] & 0xF0) {
		if (d->datalocalkeynextid == -1) {
			beginkeyupdate(sess);
		} else {
			sendkeyupdate(sess, false);
		}
		if (e->nonce[20] & 0xE0) return 0;
	}
	//Increment nonce in big endian
	int i;
	for (i = NONCEBYTES - 1; i >= 0 && ++e->nonce[i] == 0; i--) ;
	if (e->nonce[20] & 0xE0) return 0;
	if (debug) dumphex("ENCODE KEY", e->sharedkey, 32);
	if (crypto_box_curve25519xsalsa20poly1305_afternm(enc, raw, len + 32, e->nonce, e->sharedkey)) return errorexit("Encryption failed");
	enc[12] = (e->nonce[20] & 0x1F) | (0 << 7) | (d->datalocalkeyid << 6) | (d->dataremotekeyid << 5);
	enc[13] = e->nonce[21];
	enc[14] = e->nonce[22];
	enc[15] = e->nonce[23];
	if (debug) fprintf(stderr, "Encoded packet of %d bytes to %d bytes\n", len, len + 16 + 4);
	return len + 16 + 4;
}

static int decode(struct qtsession* sess, char* enc, char* raw, int len) {
	beginkeyupdateifnecessary(sess);
	int i;
	struct qt_proto_data_salty* d = (struct qt_proto_data_salty*)sess->protocol_data;
	if (len < 1) {
		fprintf(stderr, "Short packet received: %d\n", len);
		return -1;
	}
	int flags = (unsigned char)enc[12];
	if (!(flags & 0x80)) {
		//<12 byte padding>|<4 byte timestamp><n+16 bytes encrypted data>
		if (len < 4 + 16) {
			fprintf(stderr, "Short data packet received: %d\n", len);
			return -1;
		}
		struct qt_proto_data_salty_decstate* dec = &d->datadecoders[(flags >> 5) & 0x03];
		uint32 ts = decodeuint32(enc + 12) & 0x1FFFFFFF;
		if (debug) fprintf(stderr, "Decoding data packet of %d bytes with timestamp %u and flags %d\n", len, ts, flags & 0xE0);
		int ltsi = 0;
		uint32 ltsv = 0xFFFFFFFF;
		for (i = 0; i < 5; i++) {
			uint32 v = dec->timestamps[i];
			if (ts == v) {
				fprintf(stderr, "Duplicate data packet received: %u\n", ts);
				return -1;
			}
			if (v < ltsv) {
				ltsi = i;
				ltsv = v;
			}
		}
		if (ts <= ltsv) {
			fprintf(stderr, "Late data packet received: %u\n", ts);
			return -1;
		}
		dec->nonce[20] = enc[12] & 0x1F;
		dec->nonce[21] = enc[13];
		dec->nonce[22] = enc[14];
		dec->nonce[23] = enc[15];
		memset(enc, 0, 16);
	if (debug) dumphex("DECODE KEY", dec->sharedkey, 32);
		if (crypto_box_curve25519xsalsa20poly1305_open_afternm(raw, enc, len - 4 + 16, dec->nonce, dec->sharedkey)) {
			fprintf(stderr, "Decryption of data packet failed len=%d\n", len);
			return -1;
		}
		dec->timestamps[ltsi] = ts;
		return len - 16 - 4;
	} else {
		//<12 byte padding>|<1 byte flags><8 byte timestamp><n+16 bytes encrypted control data>
		if (len < 9 + 16 + 1 + 32 + 24 + 32 + 24 + 8) {
			fprintf(stderr, "Short control packet received: %d\n", len);
			return -1;
		}
		uint64 ts = decodeuint64(enc + 13);
		if (debug) fprintf(stderr, "Decoding control packet of %d bytes with timestamp %llu and flags %d\n", len, ts, flags);
		if (ts <= d->controldecodetime) {
			fprintf(stderr, "Late control packet received: %llu < %llu\n", ts, d->controldecodetime);
			return -1;
		}
		unsigned char cnonce[NONCEBYTES];
		memset(cnonce, 0, 24);
		cnonce[0] = (d->controlroles >> 1) & 1;
		memcpy(cnonce + 16, enc + 13, 8);
		memset(enc + 12 + 1 + 8 - 16, 0, 16);
		if (crypto_box_curve25519xsalsa20poly1305_open_afternm(raw, enc + 12 + 1 + 8 - 16, len - 1 - 8 + 16, cnonce, d->controlkey)) {
			fprintf(stderr, "Decryption of control packet failed len=%d\n", len);
			return -1;
		}
		d->controldecodetime = ts;
		int dosendkeyupdate = 0;
		//<32 byte padding><1 byte flags><32 byte sender key><24 byte sender nonce><32 byte recipient key><24 byte recipient nonce><8 byte timestamp>
		int cflags = (unsigned char)raw[32];
		d->dataremotekeyid = (cflags >> 6) & 0x01;
		int lkeyid = (cflags >> 5) & 0x01;
		if ((cflags & (1 << 4)) == 0) dosendkeyupdate |= 1;
		memcpy(d->dataremotekey, raw + 32 + 1, 32);
		memcpy(d->dataremotenonce, raw + 32 + 1 + 32, 24);
		uint64 lexpectts = decodeuint64(raw + 32 + 1 + 32 + 24 + 32 + 24);
		if (lexpectts > d->controlencodetime) {
			fprintf(stderr, "Remote expects newer control timestamp (%llu > %llu), moving forward.\n", lexpectts, d->controlencodetime);
			d->controlencodetime = lexpectts;
		}
		struct qt_proto_data_salty_keyset* enckey = &d->datalocalkeys[lkeyid];
		if (memcmp(enckey->publickey, raw + 32 + 1 + 32 + 24, 32) || memcmp(enckey->nonce, raw + 32 + 1 + 32 + 24 + 32, 20)) {
			dosendkeyupdate |= 2;
			lkeyid = -1;
		}
		initdecoder(&d->datadecoders[(d->dataremotekeyid << 1) | 0x00], d->dataremotekey, d->datalocalkeys[0].privatekey, d->dataremotenonce);
		initdecoder(&d->datadecoders[(d->dataremotekeyid << 1) | 0x01], d->dataremotekey, d->datalocalkeys[1].privatekey, d->dataremotenonce);
		if (lkeyid != -1 && lkeyid == d->datalocalkeynextid) {
			d->datalocalkeyid = lkeyid;
			d->datalocalkeynextid = -1;
		}
		if (lkeyid == d->datalocalkeyid) {
			crypto_box_curve25519xsalsa20poly1305_beforenm(enckey->sharedkey, d->dataremotekey, enckey->privatekey);
			d->dataencoder = enckey;
		}
		if (debug) fprintf(stderr, "Decoded control packet: rkid=%d, lkid=%d, ack=%d, lkvalid=%d, uptodate=%d\n", d->dataremotekeyid, (cflags >> 5) & 0x01, (cflags >> 4) & 0x01, lkeyid != -1, d->datalocalkeynextid == -1);
		if (d->datalocalkeynextid != -1) dosendkeyupdate |= 2;
		if (dosendkeyupdate) sendkeyupdate(sess, (dosendkeyupdate & 2) == 0);
		return 0;
	}
}

static void idle(struct qtsession* sess) {
	beginkeyupdateifnecessary(sess);
}

struct qtproto qtproto_salty = {
	1,
	MAX_PACKET_LEN + crypto_box_curve25519xsalsa20poly1305_ZEROBYTES,
	MAX_PACKET_LEN + crypto_box_curve25519xsalsa20poly1305_ZEROBYTES,
	crypto_box_curve25519xsalsa20poly1305_ZEROBYTES,
	crypto_box_curve25519xsalsa20poly1305_BOXZEROBYTES - 4,
	encode,
	decode,
	init,
	sizeof(struct qt_proto_data_salty),
	idle,
};

#ifndef COMBINED_BINARY
int main(int argc, char** argv) {
	print_header();
	if (qtprocessargs(argc, argv) < 0) return -1;
	return qtrun(&qtproto_salty);
}
#endif
