#include "mod/common/kernel_hook.h"

#include "mod/common/core.h"

static verdict find_instance(struct sk_buff *skb, struct xlator *result)
{
	int error;

	error = xlator_find(dev_net(skb->dev), FW_NETFILTER, NULL, result);
	switch (error) {
	case 0:
		return VERDICT_CONTINUE;
	case -ESRCH:
		/*
		 * The hook functions are called on every packet whenever they
		 * reach a namespace, so not finding an instance here is
		 * perfectly normal and does not warrant an error message.
		 */
		return VERDICT_UNTRANSLATABLE;
	case -EINVAL:
		WARN(true, "xlator_find() is not supposed to EINVAL when iname is NULL.");
		return VERDICT_UNTRANSLATABLE;
	}

	WARN(true, "Unknown error code %d while trying to find iptables a Jool instance.",
			error);
	return VERDICT_UNTRANSLATABLE;
}

static unsigned int verdict2netfilter(verdict result)
{
	switch (result) {
	case VERDICT_STOLEN:
		return NF_STOLEN; /* This is the happy path. */
	case VERDICT_UNTRANSLATABLE:
		log_debug("Returning the packet to the kernel.");
		return NF_ACCEPT;
	case VERDICT_DROP:
		log_debug("Dropping packet.");
		return NF_DROP;
	case VERDICT_CONTINUE:
		WARN(true, "At time of writing, Jool core is not supposed to return CONTINUE after the packet is handled.\n"
				"Please report this to the Jool devs.");
		return NF_ACCEPT; /* Hmmm... */
	}

	WARN(true, "Unknown verdict: %d", result);
	return NF_DROP;
}

/**
 * This is the function that the kernel calls whenever a packet reaches Jool's
 * IPv6 Netfilter hook.
 */
NF_CALLBACK(hook_ipv6, skb)
{
	struct xlator jool;
	verdict result;

	result = find_instance(skb, &jool);
	if (result != VERDICT_CONTINUE)
		return verdict2netfilter(result);

	result = core_6to4(skb, &jool);

	xlator_put(&jool);
	return verdict2netfilter(result);
}

/**
 * This is the function that the kernel calls whenever a packet reaches Jool's
 * IPv4 Netfilter hook.
 */
NF_CALLBACK(hook_ipv4, skb)
{
	struct xlator jool;
	verdict result;

	result = find_instance(skb, &jool);
	if (result != VERDICT_CONTINUE)
		return verdict2netfilter(result);

	result = core_4to6(skb, &jool);

	xlator_put(&jool);
	return verdict2netfilter(result);
}
