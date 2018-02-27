#include "nl/nl-core.h"

#include <linux/stddef.h>
#include <linux/types.h>
#include <linux/version.h>

#include "config.h"
#include "types.h"
#include "linux-version.h"
#include "wkmalloc.h"
#include "nl/nl-common.h"

static int respond_error(struct genl_info *info, int error_code)
{
	struct jnl_buffer buffer;
	int error;
	char *error_msg;
	size_t error_msg_size;

	error = errormsg_get(&error_msg, &error_msg_size);
	if (error)
		return error; /* Error msg already printed. */

	if (error_msg_size > NLBUFFER_MAX_PAYLOAD) {
		error_msg[NLBUFFER_MAX_PAYLOAD - 1] = '\0';
		error_msg_size = NLBUFFER_MAX_PAYLOAD;
	}

	error = jnlbuffer_init(&buffer, info, error_msg_size);
	if (error) {
		pr_err("Errcode %d while initializing a response to userspace.\n",
				error);
		goto end_simple;
	}

	jnlbuffer_set_errcode(&buffer, error_code);

	error = jnlbuffer_write(&buffer, error_msg, error_msg_size);
	if (error) {
		pr_err("Errcode %d while writing on a response to userspace.\n",
				error);
		goto end_full;
	}

	if (error_code)
		log_debug("Sending error code %d to userspace.", error_code);
	else
		log_debug("Sending ACK to userspace.");
	error = respond_single_msg(info, &buffer);
	/* Fall through. */

end_full:
	jnlbuffer_free(&buffer);
end_simple:
	__wkfree("Error msg out", error_msg);
	return error;
}

static int respond_ack(struct genl_info *info)
{
	int error;
	struct jnl_buffer buffer;

	error = jnlbuffer_init(&buffer, info, 0);
	if (error) {
		pr_err("Errcode %d while initializing a response to userspace.\n",
				error);
		return error;
	}

	error = respond_single_msg(info, &buffer);

	jnlbuffer_free(&buffer);
	return error;
}


int jnl_respond(struct genl_info *info, int error)
{
	return error ? respond_error(info, error) : respond_ack(info);
}

int jnl_respond_struct(struct genl_info *info, void *content,
		size_t content_len)
{
	struct jnl_buffer buffer;
	int error;

	error = jnlbuffer_init(&buffer, info, content_len);
	if (error) {
		pr_err("Errcode %d while initializing a response to userspace.\n",
				error);
		return respond_error(info, error);
	}

	error = jnlbuffer_write(&buffer, content, content_len);
	if (error < 0) {
		pr_err("Errcode %d while writing on a response to userspace.\n",
				error);
		return respond_error(info, error);
	}
	/*
	 * @content is supposed to be a statically-defined struct, and as such
	 * should be several orders smaller than the Netlink packet size limit.
	 */
	if (WARN(error > 0, "Content exceeds the maximum packet size."))
		return respond_error(info, -E2BIG);

	error = jnlbuffer_send(&buffer, info);
	jnlbuffer_free(&buffer);
	return error;
}
