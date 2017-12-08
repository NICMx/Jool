#ifndef _JOOL_MOD_FILTERING_H
#define _JOOL_MOD_FILTERING_H

/**
 * @file
 * Second step of the stateful NAT64 translation algorithm: "Filtering and Updating Binding and
 * Session Information", as defined in RFC6146 section 3.5.
 */

#include "nat64/mod/common/translation_state.h"
#include "nat64/mod/stateful/bib/entry.h"

verdict filtering_and_updating(struct xlation *state);
enum session_fate tcp_est_expire_cb(struct session_entry *session, void *arg);

#endif /* _JOOL_MOD_FILTERING_H */
