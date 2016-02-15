#ifndef _JOOL_MOD_TRANSLATION_STATE_H
#define _JOOL_MOD_TRANSLATION_STATE_H

#include "nat64/mod/common/xlator.h"
#include "nat64/mod/common/packet.h"

/**
 * State of the current translation.
 */
struct xlation {
	/**
	 * The instance of Jool that's in charge of carrying out this
	 * translation.
	 */
	struct xlator jool;

	/** The original packet. */
	struct packet in;
	/** The translated version of @in. */
	struct packet out;

	/**
	 * Convenient accesor to the session that corresponds to the packet
	 * being translated, so you don't have to find it again.
	 *
	 * You should never trust this has been set.
	 */
	struct session_entry *session;
};

void xlation_put(struct xlation *state);

#endif /* _JOOL_MOD_TRANSLATION_STATE_H */
