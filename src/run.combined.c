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

int main() {
	print_header();
#ifdef DEBIAN_BINARY
	getconf = getenvdeb;
#else
	getconf = getenv;
#endif
	char* envval;
	if (envval = getconf("PROTOCOL")) {
		if (strcmp(envval, "raw") == 0) {
			return tunmain_raw();
		} else if (strcmp(envval, "nacl0") == 0) {
			return tunmain_nacl0();
		} else if (strcmp(envval, "nacltai") == 0) {
			return tunmain_nacltai();
		} else {
			fprintf(stderr, "Unknown protocol specified: %s\n", envval);
			return -1;
		}
	} else if (getconf("PRIVATE_KEY")) {
		return tunmain_nacl0();
	} else {
		return tunmain_raw();
	}
}