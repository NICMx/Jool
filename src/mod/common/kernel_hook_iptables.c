#include "mod/common/kernel_hook.h"

#include "mod/common/core.h"
#include "mod/common/linux_version.h"
#include "mod/common/log.h"

static verdict find_instance(struct net *ns, const struct target_info *info,
		struct xlator *result)
{
	int error;

	error = xlator_find(ns, XF_IPTABLES | info->type, info->iname, result);
	switch (error) {
	case 0:
		return VERDICT_CONTINUE;
	case -ESRCH:
		log_warn_once("Some iptables rule linked to Jool instance '%s' sent me a packet,\n"
				"but the instance does not exist.\n"
				"Have you created it yet?", info->iname);
		return VERDICT_UNTRANSLATABLE;
	case -EINVAL:
		/* Error message already printed. */
		return VERDICT_UNTRANSLATABLE;
	}

	WARN(true, "Unknown error code %d while trying to find iptables Jool instance '%s'.",
			error, info->iname);
	return VERDICT_UNTRANSLATABLE;
}

/**
 * This is the function that the kernel calls whenever the user inserts an
 * iptables/ip6tables rule that involves the Jool target.
 */
int target_checkentry(const struct xt_tgchk_param *param)
{
	struct target_info *info = param->targinfo;
	int error;

	error = iname_validate(info->iname, false);
	if (error) {
		log_err(INAME_VALIDATE_ERRMSG, INAME_MAX_LEN - 1);
		return error;
	}
	error = xt_validate(info->type);
	if (error) {
		log_err(XT_VALIDATE_ERRMSG);
		return error;
	}

	return 0;

	/*
	 * Probably don't need to check if the instance exists;
	 * it would just annoy the user.
	 * Also, I don't think that we can prevent a user from removing an
	 * instance while the rule exists so it would be pointless anyway.
	 */
}
EXPORT_SYMBOL_GPL(target_checkentry);

static struct net *action_param_net(const struct xt_action_param *param)
{
#if LINUX_VERSION_AT_LEAST(4, 10, 0, 8, 0)
	return param->state->net;
#elif LINUX_VERSION_AT_LEAST(4, 4, 0, 9999, 0)
	return param->net;
#else
	return dev_net(param->in);
#endif
}

static unsigned int verdict2iptables(verdict result)
{
	switch (result) {
	case VERDICT_STOLEN:
		return NF_STOLEN; /* This is the happy path. */
	case VERDICT_UNTRANSLATABLE:
		log_debug("Returning packet to the iptables chain.");
		return XT_CONTINUE;
	case VERDICT_DROP:
		log_debug("Dropping packet.");
		return NF_DROP;
	case VERDICT_CONTINUE:
		WARN(true, "At time of writing, Jool core is not supposed to return CONTINUE after the packet is handled.\n"
				"Please report this to the Jool devs.");
		return XT_CONTINUE; /* Hmmm... */
	}

	WARN(true, "Unknown verdict: %d", result);
	return NF_DROP;
}

/**
 * This is the function that the kernel calls whenever a packet reaches one of
 * Jool's ip6tables rules.
 */
unsigned int target_ipv6(struct sk_buff *skb,
		const struct xt_action_param *param)
{
	struct xlation *state;
	verdict result;

	state = xlation_create(NULL);
	if (!state)
		return NF_DROP;

	result = find_instance(action_param_net(param), param->targinfo,
			&state->jool);
	if (result != VERDICT_CONTINUE)
		goto end;

	result = core_6to4(skb, state);

	xlator_put(&state->jool);
end:	xlation_destroy(state);
	return verdict2iptables(result);
}
EXPORT_SYMBOL_GPL(target_ipv6);

/**
 * This is the function that the kernel calls whenever a packet reaches one of
 * Jool's iptables rules.
 */
unsigned int target_ipv4(struct sk_buff *skb,
		const struct xt_action_param *param)
{
	struct xlation *state;
	verdict result;

	state = xlation_create(NULL);
	if (!state)
		return NF_DROP;

	result = find_instance(action_param_net(param), param->targinfo,
			&state->jool);
	if (result != VERDICT_CONTINUE)
		goto end;

	result = core_4to6(skb, state);

	xlator_put(&state->jool);
end:	xlation_destroy(state);
	return verdict2iptables(result);
}
EXPORT_SYMBOL_GPL(target_ipv4);
