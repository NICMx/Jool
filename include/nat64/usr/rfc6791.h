#ifndef _JOOL_USR_RFC6791_H
#define _JOOL_USR_RFC6791_H

#include "nat64/common/types.h"


int rfc6791_display(void);
int rfc6791_count(void);
int rfc6791_add(struct ipv4_prefix *addrs);
int rfc6791_remove(struct ipv4_prefix *addrs, bool quick);
int rfc6791_flush(bool quick);


#endif /* _JOOL_USR_RFC6791_H */
