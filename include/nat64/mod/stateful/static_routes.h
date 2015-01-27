#ifndef _JOOL_MOD_STATIC_ROUTES_H
#define _JOOL_MOD_STATIC_ROUTES_H

/**
 * @file
 * A bridge between the configuration module and the BIB and session modules.
 *
 * @author Miguel Gonzalez
 * @author Alberto Leiva
 */

#include "nat64/common/config.h"

/**
 * Adds a static entry to the BIB.
 *
 * @param req description of the BIB to be added. Uses the fields from the "add" substructure.
 * @return success status as a unix error code.
 */
int add_static_route(struct request_bib *req);

/**
 * Mainly deletes static entries from the BIB. It can also remove dynamic entries, though.
 *
 * @param req description of the BIB to be removed.
 * @return success status as a unix error code.
 */
int delete_static_route(struct request_bib *req);

#endif /* _JOOL_MOD_STATIC_ROUTES_H */
