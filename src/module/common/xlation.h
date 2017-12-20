#ifndef _JOOL_MOD_XLATION_H
#define _JOOL_MOD_XLATION_H

#include "xlator.h"
#include "packet.h"
#include "stats.h"
#include "nat64/bib/entry.h"

/**
 * The state of the current translation.
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

#define GLOBAL jool.global->cfg
};

void xlation_init(struct xlation *state, struct xlator *jool);
void xlation_put(struct xlation *state);

int breakdown(struct xlation *state, jstat_type stat, int error);
int eexist(struct xlation *state, jstat_type stat);
int einval(struct xlation *state, jstat_type stat);
int enomem(struct xlation *state);
int enospc(struct xlation *state, jstat_type stat);
int eperm(struct xlation *state, jstat_type stat);
int esrch(struct xlation *state, jstat_type stat);
int eunknown4(struct xlation *state, int error);
int eunknown6(struct xlation *state, int error);
int eunsupported(struct xlation *state, jstat_type stat);

#endif /* _JOOL_MOD_XLATION_H */
