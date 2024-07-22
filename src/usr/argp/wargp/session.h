#ifndef SRC_USR_ARGP_WARGP_SESSION_H_
#define SRC_USR_ARGP_WARGP_SESSION_H_

#include "usr/argp/joold/netsocket.h"
#include "usr/argp/joold/statsocket.h"

int handle_session_display(char *, int, char **, void const *);
int handle_session_follow(char *, int, char **, void const *);
int handle_session_proxy(char *, int, char **, void const *);

void autocomplete_session_display(void const *);
void autocomplete_session_follow(void const *);
void autocomplete_session_proxy(void const *);

int joold_start(char const *iname, struct netsocket_cfg *netcfg,
		struct statsocket_cfg *statcfg);

#endif /* SRC_USR_ARGP_WARGP_SESSION_H_ */
