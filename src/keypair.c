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
#include "crypto_box.h"
#include <time.h>

int main() {
	print_header();

	unsigned char cpublickey[crypto_box_PUBLICKEYBYTES];
	unsigned char csecretkey[crypto_box_SECRETKEYBYTES];
	int i;

	crypto_box_keypair(cpublickey, csecretkey);

	printf("SECRET: ");
	for (i = 0; i < crypto_box_SECRETKEYBYTES; i++) printf("%02x", csecretkey[i]);
	printf("\n");

	printf("PUBLIC: ");
	for (i = 0; i < crypto_box_PUBLICKEYBYTES; i++) printf("%02x", cpublickey[i]);
	printf("\n");

	return 0;
}

void randombytes(char* bytes) {
	char* b;
	srand(time(NULL));
	for (b = bytes; b < bytes + crypto_box_SECRETKEYBYTES; b++) *b = rand() % 255;
}
