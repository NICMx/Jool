#include "mod/common/nl/nl_common.h"

#include "mod/common/init.h"
#include "mod/common/xlator.h"
#include "mod/common/nl/attribute.h"
#include "mod/common/nl/nl_handler.h"

/*
 * Intent:
 *
 * - When a state object is not in the end of an arguments list, then it's a
 *   core feature of the function and must not be NULL.
 * - If the state object is at the end of an arguments list, then it's only
 *   used for logging (ie. akin to extack), and can be NULL.
 *
 * BUT DO NOT THINK OF THIS AS AN EXCUSE TO NOT LOG. NULL jnl_state IS INTENDED
 * FOR UNIT TESTS AND NOTHING ELSE.
 */
struct jnl_state {
	struct xlator __jool; /* Never access this directly. */
	struct xlator *jool; /* This usually points to __jool. */

	/* Request */
	struct genl_info *gnlinfo;

	/* Response if successful (packet to userspace) */
	struct sk_buff *skb;
	/*
	 * Quick access to @skb's Jool header
	 * Note, this is the outgoing packet's header, not the incoming one.
	 */
	struct joolnlhdr *jhdr;
	unsigned int initial_len;

	/* Response if error */
	char *error_msg;
};

/* This is just for unit tests. For real usage, use jnl_start(). */
struct jnl_state *jnls_create(struct xlator *jool)
{
	struct jnl_state *result;

	result = kmalloc(sizeof(*result), GFP_KERNEL);
	if (!result)
		return NULL;

	memset(result, 0, sizeof(*result));
	result->jool = jool;
	return result;
}
EXPORT_UNIT_SYMBOL(jnls_create)

/* This is just for unit tests. For real usage, use jnl_cancel(). */
void jnls_destroy(struct jnl_state *state)
{
	kfree(state);
}
EXPORT_UNIT_SYMBOL(jnls_destroy)


static int validate_stateness(struct jnl_state *state)
{
	switch (jnls_jhdr(state)->xt) {
	case XT_SIIT:
		if (is_siit_enabled())
			return 0;
		return jnls_err(state, "SIIT Jool has not been modprobed. (Try `modprobe jool_siit`)");
	case XT_NAT64:
		if (is_nat64_enabled())
			return 0;
		return jnls_err(state, "NAT64 Jool has not been modprobed. (Try `modprobe jool`)");
	case XT_MAPT:
		if (is_mapt_enabled())
			return 0;
		return jnls_err(state, "MAPT Jool has not been modprobed. (Try `modprobe jool_mapt`)");
	}

	return jnls_err(state, XT_VALIDATE_ERRMSG);
}

static int validate_version(struct jnl_state *state)
{
	__u32 hdr_version = ntohl(jnls_jhdr(state)->version);

	if (xlat_version() == hdr_version)
		return 0;

	return jnls_err(state, "Version mismatch. The userspace client's version is %u.%u.%u.%u,\n"
			"but the kernel module is %u.%u.%u.%u.\n"
			"Please update the %s.",
			hdr_version >> 24, (hdr_version >> 16) & 0xFFU,
			(hdr_version >> 8) & 0xFFU, hdr_version & 0xFFU,
			JOOL_VERSION_MAJOR, JOOL_VERSION_MINOR,
			JOOL_VERSION_REV, JOOL_VERSION_DEV,
			(xlat_version() > hdr_version)
					? "userspace client"
					: "kernel module");
}

static int init_response(struct jnl_state *state)
{
	struct joolnlhdr *jhdr;

	state->skb = genlmsg_new(GENLMSG_DEFAULT_SIZE, GFP_KERNEL);
	if (!state->skb) {
		pr_err("genlmsg_new() failed.\n");
		return -ENOMEM;
	}

	jhdr = genlmsg_put(state->skb, state->gnlinfo->snd_portid,
			state->gnlinfo->nlhdr->nlmsg_seq, jnl_family(), 0, 0);
	if (!jhdr) {
		pr_err("genlmsg_put() failed.\n");
		kfree_skb(state->skb);
		state->skb = NULL;
		return -ENOMEM;
	}

	memcpy(jhdr, jnls_jhdr(state), sizeof(*jhdr));
	jhdr->flags = 0;

	state->jhdr = jhdr;
	state->initial_len = state->skb->len;
	return 0;
}

/*
 * Use this function when you want jnl_start(), but there's no translator
 * instance associated with the request.
 */
int __jnl_start(struct jnl_state **_state, struct genl_info *info,
		xlator_type xt, bool require_net_admin)
{
	struct jnl_state *state;
	struct joolnlhdr *hdr;
	int error;

	state = kmalloc(sizeof(*state), GFP_KERNEL);
	if (!state)
		return -ENOMEM;

	memset(state, 0, sizeof(*state));
	state->gnlinfo = info;
	*_state = state;

	if (require_net_admin && !capable(CAP_NET_ADMIN)) {
		jnls_err(state, "CAP_NET_ADMIN capability required. (Maybe try su or sudo?)");
		return -EPERM;
	}

	if (!info->attrs)
		return jnls_err(state, "Userspace request lacks Netlink attributes.");

	hdr = jnls_jhdr(state);
	if (!hdr)
		return jnls_err(state, "Userspace request lacks a Jool header.");
	error = validate_stateness(state);
	if (error)
		return error;
	error = validate_version(state);
	if (error)
		return error;
	if (!(hdr->xt & xt)) {
		return jnls_err(state, "Command unsupported by %s translators.",
				xt2str(hdr->xt));
	}

	return init_response(state);
}

int jnl_start(struct jnl_state **_state, struct genl_info *info,
		xlator_type xt, bool require_net_admin)
{
	struct jnl_state *state;
	struct joolnlhdr const *jhdr;
	char const *iname;
	int error;

	error = __jnl_start(_state, info, xt, require_net_admin);
	if (error)
		return error;

	state = *_state;
	jhdr = jnls_jhdr(state);
	iname = (jhdr->iname[0] != 0) ? jhdr->iname : INAME_DEFAULT;

	error = xlator_find_current(iname, XF_ANY | jhdr->xt, &state->__jool,
			state);
	switch (error) {
	case 0:
		state->jool = &state->__jool;
		break;
	case -ESRCH:
		jnls_err(state, "This namespace lacks an instance named '%s'.",
				iname);
		break;
	}

	return error;
}

/*
 * Note: If you're working on this module, please keep in mind that there should
 * not be any jnls_err()s anywhere.
 *
 * If a preparation to send something to userspace failed, then trying to send
 * the error message (via jnls_err()) to userspace is a fairly lost cause.
 */

static int handle_error(struct jnl_state *state, int error_code)
{
	int error;

	if (error_code < 0)
		error_code = abs(error_code);
	else if (error_code > MAX_U16)
		error_code = MAX_U16;

	kfree_skb(state->skb);
	error = init_response(state);
	if (error)
		return error;

	state->jhdr->flags |= JOOLNLHDR_FLAGS_ERROR;
	error = nla_put_u16(state->skb, JNLAERR_CODE, error_code);
	if (error) {
		pr_err("Can't write error code: Packet too small.\n");
		return error;
	}
	if (state->error_msg) {
		error = nla_put_string(state->skb, JNLAERR_MSG, state->error_msg);
		if (error) {
			if (strlen(state->error_msg) <= 128)
				goto error_msg;
			state->error_msg[128] = '\0';
			error = nla_put_string(state->skb, JNLAERR_MSG, state->error_msg);
			if (error)
				goto error_msg;
		}
	}

	jnls_debug(state, "Sending error %d to userspace.", error_code);
	return 0;

error_msg:
	pr_err("Can't write error message: Packet too small.\n");
	return error;
}

int jnl_reply(struct jnl_state *state, int error_code)
{
	int error;

	if (error_code) {
		error = handle_error(state, error_code);
		if (error)
			goto end;
	}

	genlmsg_end(state->skb, state->jhdr);
	error = genlmsg_reply(state->skb, state->gnlinfo);
	if (error)
		pr_err("genlmsg_reply() failed. (errcode %d)\n", error);

end:
	jnl_cancel(state);
	return error;
}

int jnl_reply_array(struct jnl_state *state, int error)
{
	if (error < 0) {
		/*
		 * Note, this is somewhat brittle.
		 * The foreach functions should probably be the ones printing
		 * the error messages.
		 */
		if (error == -ESRCH)
			jnls_err(state, "Offset not found.");
		return jnl_reply(state, error);
	}

	/*
	 * Packet empty might happen when the last entry died between foreach
	 * requests.
	 */
	if (error > 0) {
		if (state->skb->len == state->initial_len) {
			report_put_failure(state);
			return jnl_reply(state, -EINVAL);
		}
		jnls_enable_m(state);
	}

	return jnl_reply(state, 0);
}

void jnl_cancel(struct jnl_state *state)
{
	if (state->jool)
		xlator_put(state->jool);
	if (state->error_msg)
		kfree(state->error_msg);
	kfree(state);
}

struct xlator *jnls_xlator(struct jnl_state *state)
{
	return state->jool;
}

struct sk_buff *jnls_skb(struct jnl_state *state)
{
	return state->skb;
}

struct joolnlhdr *jnls_jhdr(struct jnl_state *state)
{
	return state->gnlinfo->userhdr;
}

void jnls_set_xlator(struct jnl_state *state, struct xlator *jool)
{
	state->jool = jool;
}

void jnls_enable_m(struct jnl_state *state)
{
	state->jhdr->flags |= JOOLNLHDR_FLAGS_M;
}

int prefix4_validate(const struct ipv4_prefix *prefix, struct jnl_state *state)
{
	__u32 suffix_mask;

	if (unlikely(!prefix))
		return jnls_err(state, "Prefix is NULL.");

	if (prefix->len > 32) {
		return jnls_err(state, "Prefix length %u is too high.",
				prefix->len);
	}

	suffix_mask = ~get_prefix4_mask(prefix);
	if ((be32_to_cpu(prefix->addr.s_addr) & suffix_mask) != 0) {
		return jnls_err(state,
				"'%pI4/%u' seems to have a suffix; please fix.",
				&prefix->addr, prefix->len);
	}

	return 0;
}

int prefix6_validate(const struct ipv6_prefix *prefix, struct jnl_state *state)
{
	unsigned int i;

	if (unlikely(!prefix))
		return jnls_err(state, "Prefix is NULL.");

	if (prefix->len > 128) {
		return jnls_err(state, "Prefix length %u is too long.",
				prefix->len);
	}

	for (i = prefix->len; i < 128; i++) {
		if (addr6_get_bit(&prefix->addr, i)) {
			return jnls_err(state, "'%pI6c/%u' seems to have a suffix; please fix.",
					&prefix->addr, prefix->len);
		}
	}

	return 0;
}

int prefix4_validate_scope(struct ipv4_prefix *prefix, bool force,
		struct jnl_state *state)
{
	struct ipv4_prefix subnet;

	if (!force && prefix4_has_subnet_scope(prefix, &subnet)) {
		jnls_err(state, "Prefix %pI4/%u intersects with subnet scoped network %pI4/%u.",
				&prefix->addr, prefix->len,
				&subnet.addr, subnet.len);
		jnls_err(state, "Will cancel the operation. Use --force to ignore this validation.");
		return -EINVAL;
	}

	return 0;
}

void __jnls_debug(struct xlator *jool, const char *format, ...)
{
	va_list args;

	if (!jool) {
#ifdef DEBUG
		pr_info("Jool: ");
		va_start(args, format);
		vprintk(format, args);
		va_end(args);
#endif
		return;
	}

	if (!jool->globals.debug)
		return;

	pr_info("Jool %s/%p/%s: ", xt2str(xlator_get_type(jool)), jool->ns,
			jool->iname);
	va_start(args, format);
	vprintk(format, args);
	va_end(args);
}

int jnls_err(struct jnl_state *state, const char *fmt, ...)
{
	char *new_msg;
	size_t old_len;
	va_list args;

	if (!state)
		goto fallback;

	old_len = state->error_msg ? strlen(state->error_msg) : 0;
	state->error_msg = krealloc(state->error_msg, old_len + 256, GFP_KERNEL);
	if (!state->error_msg)
		goto fallback;

	new_msg = state->error_msg + old_len;

	/* Want to avoid vprintk because I can't append a level string to it. */
	va_start(args, fmt);
	vsnprintf(new_msg, 256, fmt, args);
	va_end(args);

	pr_err("Jool error: %s\n", new_msg);
	return -EINVAL;

fallback:
	/* Fall back to shitty print */
	va_start(args, fmt);
	vprintk(fmt, args);
	va_end(args);
	return -EINVAL;
}
