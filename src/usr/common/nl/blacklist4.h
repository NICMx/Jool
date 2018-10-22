#ifndef _JOOL_USR_BLACKLIST_H
#define _JOOL_USR_BLACKLIST_H

#include "common/config.h"

typedef int (*blacklist4_foreach_cb)(struct ipv4_prefix *entry, void *args);

int blacklist4_foreach(char *iname, blacklist4_foreach_cb cb, void *_args);
int blacklist4_add(char *iname, struct ipv4_prefix *addrs, bool force);
int blacklist4_rm(char *iname, struct ipv4_prefix *addrs);
int blacklist4_flush(char *iname);

#endif /* _JOOL_USR_BLACKLIST_H */
