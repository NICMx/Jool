#include "error-pool.h"

#include "wkmalloc.h"

/*
 * Gathers human-friendly error messages during userspace request handling
 * so they can be sent to userspace.
 */

struct error_node {
	char *msg;
	struct list_head prev_next;
};

static DEFINE_MUTEX(lock);
static LIST_HEAD(db);

void errormsg_enable(void)
{
	mutex_lock(&lock);
}

/**
 * len - length of message
 * fmt - template that, once filled with ..., will result in the message
 * ... - arguments to format fmt with.
 *
 * This function is not inteded to be used directly. Use log_err() instead.
 */
void errormsg_add(int len, const char *fmt, ...)
{
	struct error_node *node;
	va_list args;
	/* int new_len; */

	/*
	 * If the mutex is not locked, this function was called outside of a
	 * valid "context" (ie. between errormsg_enable() and
	 * errormsg_disable()). Which is fine; log_err() still prints the error
	 * message in the those cases, and that is exactly what we want.
	 */
	if (!mutex_is_locked(&lock))
		return;

	node = wkmalloc(struct error_node, GFP_KERNEL);
	if (!node)
		return;

	/*
	 * I don't know if this happens with every kernel, but when I do
	 * `i = pr_something(whatever "\n")` in 4.4, the result of i does not
	 * include the last newline:
	 *
	 *     i = pr_err("la");       // i = 2
	 *     i = pr_err("la\n");     // i = 2
	 *     i = pr_err("la\n\n");   // i = 3
	 *     i = pr_err("la\n\n\n"); // i = 4
	 *
	 * I think this is due to some bullshit hack they have going on,
	 * probably in vkdb_printf().
	 * All errormsg_add() calls are expected to contain a newline, so...
	 * include it in the allocation.
	 *
	 * TODO I think this is a bug in printk() and maybe should be reported.
	 */
	len++;

	/* This + 1 is the terminating character. */
	node->msg = __wkmalloc("error_code.msg", len + 1, GFP_KERNEL);
	if (!node->msg) {
		wkfree(struct error_node, node);
		return;
	}

	va_start(args, fmt);
	/* Do not trust the result of the print functions for anything else. */
	/* new_len = */ vsprintf(node->msg, fmt, args);
	va_end(args);

	/*
	if (WARN(len != new_len, "Bug: errormsg_add(len) was wrong. Expected %d, got %d.",
			len, new_len)) {
		__wkfree("error_code.msg", node->msg);
		wkfree(struct error_node, node);
		return;
	}
	*/

	list_add_tail(&node->prev_next, &db);
}

/**
 * Note: @result_len includes the NULL chara.
 *
 * If there is no message, will return success and @result will be unmodified.
 *
 * This function destroys the stored strings; it can only be called once per
 * full error message.
 */
int errormsg_get(char **result, size_t *result_len)
{
	struct error_node *node;
	size_t total_len;
	char *msg;

	if (!mutex_is_locked(&lock)) {
		pr_err("error_pool_get_message() seems to have been called ouside of an userspace request handler.\n");
		return -EINVAL;
	}

	total_len = 1; /* Null chara */
	list_for_each_entry(node, &db, prev_next)
		total_len += strlen(node->msg);

	if (total_len == 1)
		return 0;

	msg = __wkmalloc("Error msg out", total_len, GFP_KERNEL);
	if (!msg) {
		pr_err("Could not allocate the error pool message!\n") ;
		return -ENOMEM;
	}

	*result = msg;
	*result_len = total_len;

	while (!list_empty(&db)) {
		node = list_first_entry(&db, struct error_node, prev_next);

		strcpy(msg, node->msg);
		msg += strlen(node->msg);
		list_del(&node->prev_next);
		__wkfree("error_code.msg", node->msg);
		wkfree(struct error_node, node);
	}

	return 0;
}

static void flush_list(void)
{
	struct error_node *node;

	do {
		node = list_first_entry(&db, struct error_node, prev_next);
		pr_warn("Message not sent to userspace: '%s'\n", node->msg);
		list_del(&node->prev_next);
		__wkfree("error_code.msg", node->msg);
		wkfree(struct error_node, node);
	} while (!list_empty(&db));
}

void errormsg_disable(void)
{
	if (WARN(!list_empty(&db), "Error message pool isn't empty."))
		flush_list();

	mutex_unlock(&lock);
}
