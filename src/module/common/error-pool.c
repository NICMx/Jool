#include "error-pool.h"

#include <stdarg.h>
#include <linux/string.h>
#include <linux/slab.h>
#include <linux/printk.h>
#include "types.h"
#include "wkmalloc.h"

/*
 * Gathers human-friendly error messages during userspace request handling
 * so they can be sent to userspace.
 *
 * This whole module assumes outside locking.
 * (see the caller of error_pool_activate() and error_pool_deactivate().
 *
 * TODO this whole module is race condition incarnate. Redesign it.
 */

struct error_node {
	char * msg;
	struct list_head prev_next;
};

static __u8 activated = 0;
static size_t msg_size = 0;
static struct list_head db;

void error_pool_init(void)
{
	INIT_LIST_HEAD(&db);
}

static void flush_list(void)
{
	struct error_node *node;

	while (!list_empty(&db)) {
		node = list_first_entry(&db, struct error_node, prev_next);
		list_del(&node->prev_next);
		__wkfree("error_code.msg", node->msg);
		wkfree(struct error_node, node);
	}
}

void error_pool_destroy(void)
{
	flush_list();
}

void error_pool_activate(void)
{
	activated = 1;
	msg_size = 0;
}

/**
 * len - length of message
 * fmt - template that, once filled with ..., will result in the message
 * ... - arguments to format fmt with.
 *
 * This function is not inteded to be used directly. Use log_err() instead.
 */
int error_pool_add_message(int len, const char *fmt, ...)
{
	struct error_node *node;
	va_list args;

	if (!activated)
		return 0;

	node = wkmalloc(struct error_node, GFP_ATOMIC);
	if (!node)
		return -ENOMEM;

	node->msg = __wkmalloc("error_code.msg", len + 1, GFP_ATOMIC);
	if (!node->msg) {
		wkfree(struct error_node, node);
		return -ENOMEM;
	}

	va_start(args, fmt);
	vsprintf(node->msg, fmt, args);
	va_end(args);

	list_add_tail(&node->prev_next, &db);
	msg_size += strlen(node->msg);
	return 0;
}

/**
 * Note: @msg_len includes the NULL chara.
 */
int error_pool_get_message(char **out_message, size_t *msg_len)
{
	struct error_node *node;
	char *buffer_pointer;

	if (!activated) {
		pr_err("error_pool_get_message() seems to have been called ouside of an userspace request handler.\n");
		return -EINVAL;
	}

	(*out_message) = __wkmalloc("Error msg out", msg_size + 1, GFP_KERNEL);
	if (!(*out_message)) {
		pr_err("Could not allocate the error pool message!\n") ;
		return -ENOMEM;
	}

	buffer_pointer = (*out_message);
	while (!list_empty(&db)) {
		node = list_first_entry(&db, struct error_node, prev_next);

		strcpy(buffer_pointer, node->msg);
		buffer_pointer += strlen(node->msg);
		list_del(&(node->prev_next));
		__wkfree("error_code.msg", node->msg);
		wkfree(struct error_node, node);
	}

	buffer_pointer[0] = '\0';

	(*msg_len) = msg_size + 1;
	msg_size = 0;

	return 0;
}

void error_pool_deactivate(void)
{
	flush_list();
	msg_size = 0;
	activated = 0;
}
