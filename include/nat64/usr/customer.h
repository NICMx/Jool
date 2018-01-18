#ifndef _JOOL_USR_CUSTOMER_H
#define _JOOL_USR_CUSTOMER_H

#include "nat64/common/config.h"
#include "nat64/usr/types.h"

int customer_display(display_flags flags);
int customer_add(struct customer_entry_usr *entry);
int customer_rm(bool quick);
int customer_flush(bool quick);

#endif /* _JOOL_USR_CUSTOMER_H */
