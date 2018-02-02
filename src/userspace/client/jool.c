/**
 * Main for the `jool` userspace application.
 * Handles the first arguments (often "mode" and "operation") and multiplexes
 * the rest of the work to the corresponding .c's.
 */

#include <argp.h>
#include <errno.h>
#include <string.h>

#include "log.h"
#include "argp/bib.h"
#include "argp/eamt.h"
#include "argp/file.h"
#include "argp/instance.h"
#include "argp/pool4.h"
#include "argp/global.h"
#include "argp/session.h"

#define DISPLAY "display"
#define ADD "add"
#define UPDATE "update"
#define RM "remove"
#define FLUSH "flush"

// TODO Improve this and give it some use. */
//const char *argp_program_version = JOOL_VERSION_STR;
//const char *argp_program_bug_address = "jool@nic.mx";

struct thingy {
	/**
	 * Name this node is known by the userspace application interface.
	 * This being NULL signals the end of the array.
	 */
	char *label;
	/** handler is only valid if children is NULL. */
	struct thingy *children;
	int (*handler)(int argc, char **argv);

	/** Used by the code to chain temporarily correlated nodes at times. */
	struct thingy *next;
};

static int handle_autocomplete(int argc, char **argv);

struct thingy instance_ops[] = {
		{ .label = ADD,     .handler = handle_instance_add, },
		{ .label = RM,      .handler = handle_instance_rm, },
		{ 0 },
};

struct thingy global_ops[] = {
		{ .label = DISPLAY, .handler = handle_global_display, },
		{ .label = UPDATE,  .handler = handle_global_update, },
		{ 0 },
};

struct thingy eamt_ops[] = {
		{ .label = DISPLAY, .handler = handle_eamt_display, },
		{ .label = ADD,     .handler = handle_eamt_add, },
		{ .label = RM,      .handler = handle_eamt_remove, },
		{ .label = FLUSH,   .handler = handle_eamt_flush, },
		{ 0 },
};

struct thingy pool4_ops[] = {
		{ .label = DISPLAY, .handler = handle_pool4_display, },
		{ .label = ADD,     .handler = handle_pool4_add, },
		{ .label = RM,      .handler = handle_pool4_rm, },
		{ .label = FLUSH,   .handler = handle_pool4_flush, },
		{ 0 },
};

struct thingy bib_ops[] = {
		{ .label = DISPLAY, .handler = handle_bib_display, },
		{ .label = ADD,     .handler = handle_bib_add, },
		{ .label = RM,      .handler = handle_bib_remove, },
		{ 0 },
};

struct thingy session_ops[] = {
		{ .label = DISPLAY, .handler = handle_session_display, },
		{ 0 },
};

/*
struct thingy file_ops[] = {
		{ .label = UPDATE,  .handler = handle_file_update, },
		{ 0 },
};
*/

struct thingy tree[] = {
		{ .label = "instance",     .children = instance_ops, },
		{ .label = "global",       .children = global_ops, },
		{ .label = "eamt",         .children = eamt_ops, },
		{ .label = "pool4",        .children = pool4_ops, },
		{ .label = "bib",          .children = bib_ops, },
		{ .label = "session",      .children = session_ops, },
		/* { .label = "file",         .children = file_ops, }, */
		{ .label = "autocomplete", .handler  = handle_autocomplete, },
		{ 0 },
};

/**
 * Returns the nodes from @iterator whose label start with @prefix.
 * (They will be chained via result->next.)
 * However, if there is a node whose entire label is @prefix, it returns that
 * one only.
 */
static struct thingy *find_matches(struct thingy *iterator, char *prefix)
{
	struct thingy *first = NULL;
	struct thingy *last = NULL;

	if (!iterator)
		return NULL;

	for (; iterator->label; iterator++) {
		if (memcmp(iterator->label, prefix, strlen(prefix)) == 0) {
			/*
			 * The labels never overlap like this so this isn't
			 * really useful right now.
			 * I'm including this only for the sake of correctness.
			 */
			if (strcmp(iterator->label, prefix) == 0)
				return iterator;

			if (first)
				last->next = iterator;
			else
				first = iterator;
			last = iterator;
			last->next = NULL;
		}
	}

	return first;
}

static int unexpected_token(struct thingy *nodes, char *token)
{
	fprintf(stderr, "Unexpected token: '%s'\n", token);
	fprintf(stderr, "Available options: ");
	for (; nodes->label; nodes++) {
		fprintf(stderr, "%s", nodes->label);
		if ((nodes + 1)->label)
			fprintf(stderr, ", ");
	}
	fprintf(stderr, "\n");
	return -EINVAL;
}

static int ambiguous_token(struct thingy *nodes, char *token)
{
	fprintf(stderr, "Ambiguous token: '%s'\n", token);
	fprintf(stderr, "Available options: ");
	for (; nodes; nodes = nodes->next) {
		fprintf(stderr, "%s", nodes->label);
		if (nodes->next)
			fprintf(stderr, ", ");
	}
	fprintf(stderr, "\n");
	return -EINVAL;
}

static int more_args_expected(struct thingy *nodes)
{
	fprintf(stderr, "More arguments expected.\n");
	fprintf(stderr, "Possible follow-ups: ");
	for (; nodes->label; nodes++) {
		fprintf(stderr, "%s", nodes->label);
		if ((nodes + 1)->label)
			fprintf(stderr, ", ");
	}
	fprintf(stderr, "\n");
	return -EINVAL;
}

int handle(int argc, char **argv)
{
	struct thingy *nodes = &tree[0];
	struct thingy *node = NULL;
	int i;

	if (argc == 0)
		return more_args_expected(nodes);

	for (i = 0; i < argc; i++) {
		node = find_matches(nodes, argv[i]);
		if (!node)
			return unexpected_token(nodes, argv[i]);
		if (node->next)
			return ambiguous_token(node, argv[i]);

		if (node->handler)
			return node->handler(argc - i, &argv[i]);
		nodes = node->children;
	}

	if (!node->handler)
		return more_args_expected(node->children);

	log_info("Calling handler 2");
	return node->handler(argc - i, &argv[i]);
}

/**
 * Never fails because there's no point yet.
 */
static int handle_autocomplete(int argc, char **argv)
{
	struct thingy *node = &tree[0];
	char *current_token = "";
	int i;

	if (argc != 0) {
		for (i = 0; i < argc - 1; i++) {
			node = find_matches(node, argv[i]);
			if (!node)
				return 0; /* Prefix does not exist. */
			if (node->next)
				return 0; /* Ambiguous prefix. */
			node = node->children;
		}
		current_token = argv[i];
	}

	for (node = find_matches(node, current_token); node; node = node->next)
		log_info("%s", node->label);

	return 0;
}

int main(int argc, char **argv)
{
	/*
	 * `argc - 1` and `argv + 1` remove the first argument, which is the
	 * program name.
	 */
	return handle(argc - 1, argv + 1);
}
