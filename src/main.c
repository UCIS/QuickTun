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

extern struct qtproto qtproto_raw;
extern struct qtproto qtproto_nacl0;
extern struct qtproto qtproto_nacltai;
extern struct qtproto qtproto_salty;

#ifdef DEBIAN_BINARY
char* getenvdeb(const char* name) {
	char tmp[1024] = "IF_QT_";
	if (strcmp(name, "INTERFACE") == 0) return getenv("IFACE");
	if (strlen(tmp) + strlen(name) >= 1024) {
		fprintf(stderr, "Error: prefixed environment variable name is too long");
		return NULL;
	}
	strcat(tmp, name);
	return getenv(tmp);
}
#endif

const char *execproto(const char *path)
{
	const char* last_dot;
	const char* last_slash;

	if (!path) return NULL;

	last_dot = strrchr(path, '.');
	last_slash = strrchr(path, '/');
	if (last_dot && (!last_slash || last_slash < last_dot)) {
		if (strcmp(last_dot + 1, "combined") == 0) {
			return NULL;
		}
		return last_dot + 1;
	}
	return NULL;
}

int main(int argc, char** argv) {
	print_header();
#ifdef DEBIAN_BINARY
	getconf = getenvdeb;
#else
	getconf = getenv;
#endif
	if (qtprocessargs(argc, argv) < 0) return -1;
	const char* proto = execproto(argv[0]);
	const char* envval = getconf("PROTOCOL");
	if (proto && envval) {
	  fprintf(stderr, "Warning: ignoring PROTOCOL setting '%s' in favor single-protocol compatibility '%s'\n",
		  envval, proto);
	} else if (!proto) {
	  proto = envval;
	}
	if (proto) {
		if (strcmp(proto, "raw") == 0) {
			return qtrun(&qtproto_raw);
		} else if (strcmp(proto, "nacl0") == 0) {
			return qtrun(&qtproto_nacl0);
		} else if (strcmp(proto, "nacltai") == 0) {
			return qtrun(&qtproto_nacltai);
		} else if (strcmp(proto, "salty") == 0) {
			return qtrun(&qtproto_salty);
		} else {
			return errorexit("Unknown PROTOCOL specified");
		}
	} else if (getconf("PRIVATE_KEY")) {
		fprintf(stderr, "Warning: PROTOCOL not specified, using insecure nacl0 protocol\n");
		return qtrun(&qtproto_nacl0);
	} else {
		fprintf(stderr, "Warning: PROTOCOL not specified, using insecure raw protocol\n");
		return qtrun(&qtproto_raw);
	}
}
