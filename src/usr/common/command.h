#ifndef SRC_USR_COMMON_COMMAND_H_
#define SRC_USR_COMMON_COMMAND_H_

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
	int (*handler)(char *instance, int argc, char **argv, void *args);
	void *args;
	void (*print_opts)(char *prefix);

	/** Used by the code to chain temporarily correlated nodes at times. */
	struct cmd_option *next;
};

#endif /* SRC_USR_COMMON_COMMAND_H_ */
