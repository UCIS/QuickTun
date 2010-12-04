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

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdlib.h>
#include <dlfcn.h>

char* getenvdeb(const char* name) {
	char tmp[1024] = "IF_QT_";
	if (strcmp(name, "INTERFACE") == 0) return getenv("IFACE");
	/*if (strlen(tmp) + strlen(name) >= 1024) {
		fprintf(stderr, "Error: prefixed environment variable name is too long");
		return NULL;
	}*/
	strncat(tmp, name, 1024 - 6 - 1);
	return getenv(tmp);
}

int main() {
	/* Header */
	printf("UCIS QuickTun (c) 2010 Ivo Smits <Ivo@UCIS.nl>\n");
	printf("More information: http://wiki.qontrol.nl/QuickTun\n");

	char* lib = NULL;
	if (getenvdeb("PRIVATE_KEY")) {
		lib = "libquicltun.nacl0";
	} else {
		lib = "libquicltun.raw";
	}

	void* dl = dlopen(lib, RTLD_LAZY);
	if (!dl) {
		fprintf(stderr, "Error: library %s not found: %s\n", lib, dlerror());
		return -1;
	}
	void** getconfig = dlsym(dl, "getconf");
	if (!dl) {
		fprintf(stderr, "Error: symbol getconf not found: %s\n", dlerror());
		return -1;
	}
	void* tunmain = dlsym(dl, "tunmain");
	if (!dl) {
		fprintf(stderr, "Error: symbol tunmain not found: %s\n", dlerror());
		return -1;
	}

	*getconfig = (void*)getenvdeb;
	((void (*)())tunmain)();
}
