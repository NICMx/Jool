#ifndef _JOOL_MOD_ATOMIC_CONFIG_H
#define _JOOL_MOD_ATOMIC_CONFIG_H

#include <linux/kref.h>
#include <linux/types.h>
#include <linux/timer.h>

/**
 * This represents the new configuration the user wants to apply to a certain
 * Jool instance.
 *
 * On account that the tables can hold any amount of entries, the configuration
 * can be quite big, so it is quite plausible it might not entirely fit in a
 * single Netlink message. So, in order to guarantee a configuration file is
 * loaded atomically, the values are stored in a separate container (a
 * "configuration candidate") as Netlink messages arrive. The running
 * configuration is then only replaced when the candidate has been completed and
 * validated.
 *
 * In an ideal world, a configuration candidate would be a plain struct xlator,
 * but because of the way basic data types and the kref are handled, the
 * candidate needs a slightly different layout.
 */
struct config_candidate {
	struct full_config *global;
	struct pool6 *pool6;
	union {
		struct {
			struct eam_table *eamt;
			struct addr4_pool *blacklist;
			struct addr4_pool *pool6791;
		} siit;
		struct {
			struct pool4 *pool4;
		} nat64;
	};

	/** Are we currently putting together configuration from userspace? */
	bool active;
	/** Last jiffy the user made an edit. */
	unsigned long update_time;
	/**
	 * Process ID of the client that is populating this candidate.
	 * Only valid if @active.
	 */
	pid_t pid;

	struct kref refcount;
};

struct xlator;

struct config_candidate *cfgcandidate_create(void);
void cfgcandidate_get(struct config_candidate *candidate);
void cfgcandidate_put(struct config_candidate *candidate);

int atomconfig_add(struct xlator *jool, void *config, size_t config_len);

void cfgcandidate_print_refcount(struct config_candidate *candidate);

#endif /* _JOOL_MOD_ATOMIC_CONFIG_H */
