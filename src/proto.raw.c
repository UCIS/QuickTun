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

static int encode(struct qtsession* sess, char* raw, char* enc, int len) {
	memcpy(enc, raw, len);
	return len;
}

static int decode(struct qtsession* sess, char* enc, char* raw, int len) {
	memcpy(raw, enc, len);
	return len;
}

struct qtproto qtproto_raw = {
	0,
	MAX_PACKET_LEN,
	MAX_PACKET_LEN,
	0,
	0,
	decode,
	encode,
	NULL,
	0,
};

#ifndef COMBINED_BINARY
int main() {
	print_header();
	return qtrun(&qtproto_raw);
}
#endif
