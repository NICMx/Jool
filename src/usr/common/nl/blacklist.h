#ifndef _JOOL_USR_BLACKLIST_H
#define _JOOL_USR_BLACKLIST_H

#include "common/config.h"

typedef int (*blacklist_foreach_cb)(struct ipv4_prefix *entry, void *args);

int blacklist_foreach(char *iname, blacklist_foreach_cb cb, void *_args);
int blacklist_add(char *iname, struct ipv4_prefix *addrs, bool force);
int blacklist_rm(char *iname, struct ipv4_prefix *addrs);
int blacklist_flush(char *iname);

#endif /* _JOOL_USR_BLACKLIST_H */
