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
#include <fcntl.h>
#include <unistd.h>

int main(int argc, char** argv) {
	print_header();

	unsigned char cpublickey[crypto_box_curve25519xsalsa20poly1305_PUBLICKEYBYTES];
	unsigned char csecretkey[crypto_box_curve25519xsalsa20poly1305_SECRETKEYBYTES];
	int input_mode = 0; //0=generate random, 1=read from argument
	int output_mode = 0; //0=human readable, 1=space separated, 2=concatenated binary
	int i;

	for (i = 1; i < argc; i++) {
		char* a = argv[i];
		if (!strcmp(a, "-h") || !strcmp(a, "--help")) {
			printf("Please read the documentation at http://wiki.ucis.nl/QuickTun\n");
			return 0;
		} else if (!strcmp(a, "-v") || !strcmp(a, "--version")) {
			printf("UCIS QuickTun "QT_VERSION"\n");
			return 0;
		} else if (!strcmp(a, "-i")) {
			i++;
			if (i >= argc) return errorexit("Missing argument for -i");
			if (!hex2bin(csecretkey, argv[i], crypto_box_curve25519xsalsa20poly1305_SECRETKEYBYTES)) return errorexit("Invalid secret key argument");
			input_mode = 1;
		} else if (!strcmp(a, "-f")) {
			int len = fread(csecretkey, 1, crypto_box_curve25519xsalsa20poly1305_SECRETKEYBYTES, stdin);
			if (len < crypto_box_curve25519xsalsa20poly1305_SECRETKEYBYTES) return errorexitp("Error or end of file on STDIN");
			input_mode = 1;
		} else if (!strcmp(a, "-o")) {
			i++;
			a = argv[i];
			if (i >= argc) return errorexit("Missing argument for -o");
			if (!strcmp(a, "human")) output_mode = 0;
			else if (!strcmp(a, "space")) output_mode = 1;
			else if (!strcmp(a, "bin")) output_mode = 2;
			else return errorexit("Invalid argument specified for -o");
		} else {
			return errorexit("Unexpected command line argument");
		}
	}

	if (input_mode == 0) {
		crypto_box_curve25519xsalsa20poly1305_keypair(cpublickey, csecretkey);
	} else {
		crypto_scalarmult_curve25519_base(cpublickey, csecretkey);
	}

	if (output_mode == 2) {
		fwrite(csecretkey, 1, crypto_box_curve25519xsalsa20poly1305_SECRETKEYBYTES, stdout);
		fwrite(cpublickey, 1, crypto_box_curve25519xsalsa20poly1305_PUBLICKEYBYTES, stdout);
	} else if (output_mode == 1) {
		for (i = 0; i < crypto_box_curve25519xsalsa20poly1305_SECRETKEYBYTES; i++) printf("%02x", csecretkey[i]);
		printf(" ");
		for (i = 0; i < crypto_box_curve25519xsalsa20poly1305_PUBLICKEYBYTES; i++) printf("%02x", cpublickey[i]);
		printf("\n");
	} else {
		printf("SECRET: ");
		for (i = 0; i < crypto_box_curve25519xsalsa20poly1305_SECRETKEYBYTES; i++) printf("%02x", csecretkey[i]);
		printf("\n");

		printf("PUBLIC: ");
		for (i = 0; i < crypto_box_curve25519xsalsa20poly1305_PUBLICKEYBYTES; i++) printf("%02x", cpublickey[i]);
		printf("\n");
	}

	return 0;
}
