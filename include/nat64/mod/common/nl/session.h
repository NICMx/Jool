#ifndef __NL_SESSION_H__
#define __NL_SESSION_H__

#include <net/genetlink.h>
#include "nat64/mod/stateful/session/db.h"

int handle_session_config(struct sessiondb *db, struct genl_info *info);

#endif
