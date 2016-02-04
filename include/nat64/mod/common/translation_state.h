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

	/*
	 * TODO (stateful) we should probably store the session here as well, so
	 * compute_out_tuple can skip the lookup.
	 */
};

void xlation_put(struct xlation *state);

#endif /* _JOOL_MOD_TRANSLATION_STATE_H */
