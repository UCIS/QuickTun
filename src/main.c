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

#include <assert.h>

int main(int argc, char** argv) {
	print_header();
	if (qtprocessargs(argc, argv) < 0) return -1;
	char* envval;
	if ((envval = getconf("PROTOCOL"))) {
		struct qtproto *proto = getproto(envval);
		if (proto == NULL) {
			return errorexit("Unknown PROTOCOL specified");
		}
		return qtrun(proto);
	}

	if (getconf("PRIVATE_KEY")) {
		/* This priority list starts with nacl0 for backward
		   compatibility, maybe the order should be changed? */
		static const char *proto_prio[] = { "nacl0", "salty", "nacltai", NULL };
		int i;
		for (i = 0; proto_prio[i]; i++) {
			struct qtproto *proto = getproto(proto_prio[i]);
			if (proto) {
				fprintf(stderr, "Warning: PROTOCOL not specified, using %s protocol\n", proto_prio[i]);
				return qtrun(proto);
			}
		}
	}

	/* Try "raw" protocol as a last resort. */
	struct qtproto *raw_proto = getproto("raw");
	if (raw_proto) {
		fprintf(stderr, "Warning: neither PROTOCOL nor PRIVATE_KEY specified, using insecure raw protocol\n");
		return qtrun(raw_proto);
	} else {
		fprintf(stderr, "No PROTOCOL specified, and insecure raw protocol not available; terminating.");
		return 1;
	}
}
