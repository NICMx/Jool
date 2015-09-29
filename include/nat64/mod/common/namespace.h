#ifndef _JOOL_MOD_NAMESPACE_H
#define _JOOL_MOD_NAMESPACE_H

#include <net/net_namespace.h>

int joolns_init(void);
void joolns_destroy(void);

struct net *joolns_get(void);

#endif /* _JOOL_MOD_NAMESPACE_H */
