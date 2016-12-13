/* Copyright 2016 (c) Andreas Rottmann <mail@rotty.xx.vu>. Licensed
   under the 2-clause BSD license (see
   <https://opensource.org/licenses/BSD-2-Clause>).
*/
#include "common.h"

struct qtnamedproto {
  const char *name;
  struct qtproto *proto;
};

extern struct qtproto qtproto_raw;
extern struct qtproto qtproto_nacl0;
extern struct qtproto qtproto_nacltai;
extern struct qtproto qtproto_salty;

static struct qtnamedproto qtprotocols[] = {
#ifdef QT_PROTO_raw
  { "raw", &qtproto_raw },
#endif
#ifdef QT_PROTO_nacl0
  { "nacl0", &qtproto_nacl0 },
#endif
#ifdef QT_PROTO_nacltai
  { "nacltai", &qtproto_nacltai },
#endif
#ifdef QT_PROTO_salty
  { "salty", &qtproto_salty },
#endif
  { NULL, NULL }
};

struct qtproto *getproto(const char *name) {
	int i;
	for (i = 0; qtprotocols[i].name != NULL; i++) {
		if (strcmp(name, qtprotocols[i].name) == 0) {
			return qtprotocols[i].proto;
		}
	}
	return NULL;
}
