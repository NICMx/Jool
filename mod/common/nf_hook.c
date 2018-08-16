#include "nat64/mod/common/nf_hook.h"

#include "nat64/mod/common/core.h"
#include "nat64/mod/common/linux_version.h"

/**
 * This is the function that the kernel calls whenever a packet reaches Jool's
 * IPv6 Netfilter hook.
 */
NF_CALLBACK(hook_ipv6, skb)
{
	struct xlator jool;
	int error;

	error = xlator_find(dev_net(skb->dev), FW_NETFILTER, INAME_DEFAULT,
			&jool);
	if (error) {
		/*
		 * hook_ipv6() is called on every packet of every namespace,
		 * so not finding an instance here does not warrant an error
		 * message.
		 */
		return NF_ACCEPT;
	}

	error = core_6to4(skb, &jool);
	xlator_put(&jool);
	return error;
}

/**
 * This is the function that the kernel calls whenever a packet reaches Jool's
 * IPv4 Netfilter hook.
 */
NF_CALLBACK(hook_ipv4, skb)
{
	struct xlator jool;
	int error;

	error = xlator_find(dev_net(skb->dev), FW_NETFILTER, INAME_DEFAULT,
			&jool);
	if (error) {
		/*
		 * hook_ipv4() is called on every packet of every namespace,
		 * so not finding an instance here does not warrant an error
		 * message.
		 */
		return NF_ACCEPT;
	}

	error = core_4to6(skb, &jool);
	xlator_put(&jool);
	return error;
}

static int find_instance(struct net *ns, const struct target_info *info,
		struct xlator *result)
{
	int error;

	error = xlator_find(ns, FW_IPTABLES, info->iname, result);
	switch (error) {
	case 0:
		break;
	case -ESRCH:
		pr_err("This namespace does not have an iptables Jool instance named '%s'.\n",
				info->iname);
		break;
	default:
		pr_err("Unknown error code %d while trying to find iptables Jool instance '%s'.\n",
				error, info->iname);
		break;
	}

	return error;
}

/**
 * This is the function that the kernel calls whenever the user inserts an
 * iptables/ip6tables rule that involves the Jool target.
 */
int target_checkentry(const struct xt_tgchk_param *param)
{
	struct target_info *info = param->targinfo;
	return iname_validate(info->iname);

	/*
	 * Probably don't need to check if the instance exists;
	 * it would just annoy the user.
	 * Also, I don't think that we can prevent a user from removing an
	 * instance while the rule exists so it would be pointless anyway.
	 */
}

struct net *action_param_net(const struct xt_action_param *param)
{
#if LINUX_VERSION_AT_LEAST(4, 10, 0, 9999, 0)
	return param->state->net;
#elif LINUX_VERSION_AT_LEAST(4, 4, 0, 9999, 0)
	return param->net;
#else
	return dev_net(param->in);
#endif
}

/**
 * This is the function that the kernel calls whenever a packet reaches one of
 * Jool's ip6tables rules.
 */
unsigned int target_ipv6(struct sk_buff *skb,
		const struct xt_action_param *param)
{
	struct xlator jool;
	int error;

	error = find_instance(action_param_net(param), param->targinfo, &jool);
	if (error)
		return error;

	return core_6to4(skb, &jool);
}

/**
 * This is the function that the kernel calls whenever a packet reaches one of
 * Jool's iptables rules.
 */
unsigned int target_ipv4(struct sk_buff *skb,
		const struct xt_action_param *param)
{
	struct xlator jool;
	int error;

	error = find_instance(action_param_net(param), param->targinfo, &jool);
	if (error)
		return error;

	return core_4to6(skb, &jool);
}
