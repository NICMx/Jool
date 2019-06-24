#ifndef _JOOL_USR_SESSION_H
#define _JOOL_USR_SESSION_H

#include "common/config.h"

typedef int (*session_foreach_cb)(struct session_entry_usr *entry, void *args);

int session_foreach(char *iname, l4_protocol proto,
		session_foreach_cb cb, void *args);

#endif /* _JOOL_USR_SESSION_H */
