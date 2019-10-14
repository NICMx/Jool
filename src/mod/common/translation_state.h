#ifndef SRC_MOD_COMMON_TRANSLATION_STATE_H_
#define SRC_MOD_COMMON_TRANSLATION_STATE_H_

#include "mod/common/icmp_wrapper.h"
#include "mod/common/packet.h"
#include "mod/common/xlator.h"
#include "mod/common/db/bib/entry.h"

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

verdict untranslatable(struct xlation *state, enum jool_stat_id stat);
verdict untranslatable_icmp(struct xlation *state, enum jool_stat_id stat,
		enum icmp_errcode icmp, __u32 info);
verdict drop(struct xlation *state, enum jool_stat_id stat);
verdict drop_icmp(struct xlation *state, enum jool_stat_id stat,
		enum icmp_errcode icmp, __u32 info);
verdict stolen(struct xlation *state, enum jool_stat_id stat);

#define xlation_is_siit(state) xlator_is_siit(&(state)->jool)
#define xlation_is_nat64(state) xlator_is_nat64(&(state)->jool)

#endif /* SRC_MOD_COMMON_TRANSLATION_STATE_H_ */
