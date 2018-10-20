#ifndef SRC_USR_COMMON_COMMAND_H_
#define SRC_USR_COMMON_COMMAND_H_

#include <stdbool.h>
#include "common/xlat.h"

/**
 * BTW: "cmd" (command) refers to the "jool" command. Eg.
 * `jool jool0 pool4 add 192.0.2.1`.
 */
struct cmd_option {
	/**
	 * Name this node is known by the userspace application interface.
	 * This being NULL signals the end of the array.
	 */
	char *label;
	xlator_type xt;
	/** Hide this option from the user? */
	bool hidden;

	/**
	 * Array of cmd_options available after this one.
	 * If this exists, then @child_builder and @handler.cb must be NULL.
	 */
	struct cmd_option *children;

	/**
	 * A function that returns cmd_options available after this one.
	 * If this exists, then @children and @handler.cb must be NULL.
	 */
	struct cmd_option *(*child_builder)(void);

	/**
	 * A function that will handle any arguments after this one.
	 * If this exists, then @children and @child_builder must be NULL.
	 */
	int (*handler)(char *iname, int argc, char **argv, void *args);
	void *args;
	/*
	 * Intended to print flags ("--foo"), not options.
	 * Used on autocomplete only.
	 */
	void (*print_opts)(char *prefix);

	/** Used by the code to chain temporarily correlated nodes at times. */
	struct cmd_option *next;
};

bool cmdopt_is_hidden(struct cmd_option *option);

#endif /* SRC_USR_COMMON_COMMAND_H_ */
