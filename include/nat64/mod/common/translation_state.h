#ifndef _JOOL_MOD_TRANSLATION_STATE_H
#define _JOOL_MOD_TRANSLATION_STATE_H

#include "nat64/mod/common/icmp_wrapper.h"
#include "nat64/mod/common/packet.h"
#include "nat64/mod/common/stats.h"
#include "nat64/mod/common/xlator.h"
#include "nat64/mod/stateful/bib/entry.h"

struct xlation_result {
	enum icmp_errcode icmp;
	__u32 info;
};

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
	 * Convenient accesor to the BIB and session entries that correspond
	 * to the packet being translated, so you don't have to find it again.
	 */
	struct bib_session entries;

	struct xlation_result result;
};

void xlation_init(struct xlation *state, struct xlator *jool);
/* xlation_clean() is not needed for now. */

verdict untranslatable(struct xlation *state, enum jool_stat stat);
verdict drop(struct xlation *state, enum jool_stat stat);
verdict drop_icmp(struct xlation *state, enum jool_stat stat,
		enum icmp_errcode icmp, __u32 info);
verdict stolen(struct xlation *state, enum jool_stat stat);

#endif /* _JOOL_MOD_TRANSLATION_STATE_H */
