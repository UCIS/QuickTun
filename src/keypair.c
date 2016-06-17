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

#include "common.h"
#include "crypto_box_curve25519xsalsa20poly1305.h"
#include "crypto_scalarmult_curve25519.h"
#include <time.h>
#include <fcntl.h>

int main() {
	print_header();

	unsigned char cpublickey[crypto_box_curve25519xsalsa20poly1305_PUBLICKEYBYTES];
	unsigned char csecretkey[crypto_box_curve25519xsalsa20poly1305_SECRETKEYBYTES];
	int i;

	fprintf(stderr, "Please feed 32 bytes of random data to stdin.\n");
	fprintf(stderr, "Example (slow but secure): quicktun.keypair < /dev/random\n");
	fprintf(stderr, "Example (fast but insecure): quicktun.keypair < /dev/urandom\n");

	int len = fread(csecretkey, 1, crypto_box_curve25519xsalsa20poly1305_SECRETKEYBYTES, stdin);
	if (len < crypto_box_curve25519xsalsa20poly1305_SECRETKEYBYTES) return errorexitp("Error or end of file on STDIN");
/*	char* b;
	srand(time(NULL));
	for (b = csecretkey; b < csecretkey + crypto_box_curve25519xsalsa20poly1305_SECRETKEYBYTES; b++) *b = rand() % 255;*/

	crypto_scalarmult_curve25519_base(cpublickey, csecretkey);

	printf("SECRET: ");
	for (i = 0; i < crypto_box_curve25519xsalsa20poly1305_SECRETKEYBYTES; i++) printf("%02x", csecretkey[i]);
	printf("\n");

	printf("PUBLIC: ");
	for (i = 0; i < crypto_box_curve25519xsalsa20poly1305_PUBLICKEYBYTES; i++) printf("%02x", cpublickey[i]);
	printf("\n");

	return 0;
}
