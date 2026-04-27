#include "mod/common/kernel_hook.h"

#include <linux/ip.h>
#include <linux/ipv6.h>
#include "mod/common/log.h"
#include "mod/common/core.h"

/* #pragma GCC diagnostic error "-Wframe-larger-than=1" */

static verdict find_instance(struct sk_buff *skb, xlator_type xt,
		struct xlator *result)
{
	int error;

	error = xlator_find_netfilter(dev_net(skb->dev), xt, result);
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

	WARN(true, "Unknown error code %d while trying to find a Jool instance.",
			error);
	return VERDICT_UNTRANSLATABLE;
}

/*
 * @jool: The active instance, or NULL when no instance was found. When NULL
 * no debug logging is emitted (there is no debug flag to consult and no
 * instance context to print).
 */
static unsigned int verdict2netfilter(verdict result, struct xlator *jool)
{
	switch (result) {
	case VERDICT_STOLEN:
		__log_debug(jool, "Packet stolen (translated successfully).");
		return NF_STOLEN; /* This is the happy path. */
	case VERDICT_UNTRANSLATABLE:
		__log_debug(jool, "Returning the packet to the kernel.");
		return NF_ACCEPT;
	case VERDICT_DROP:
		__log_debug(jool, "Dropping packet.");
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
unsigned int hook_ipv6(void *priv, struct sk_buff *skb,
		const struct nf_hook_state *nhs)
{
	struct xlation *state;
	verdict result;
	unsigned int nf_result;

	state = xlation_create(NULL);
	if (!state)
		return NF_DROP;

	{
		xlator_type xt = (xlator_type)(uintptr_t)priv;
		result = find_instance(skb, xt, &state->jool);
	}
	if (result != VERDICT_CONTINUE) {
		xlation_destroy(state);
		return verdict2netfilter(result, NULL);
	}

	log_debug(state,
			"hook_ipv6: src=%pI6c dst=%pI6c dev=%s",
			&ipv6_hdr(skb)->saddr,
			&ipv6_hdr(skb)->daddr,
			skb->dev ? skb->dev->name : "(none)");

	result = core_6to4(skb, state);

	nf_result = verdict2netfilter(result, &state->jool);
	xlator_put(&state->jool);
	xlation_destroy(state);
	return nf_result;
}
EXPORT_SYMBOL_GPL(hook_ipv6);

/**
 * This is the function that the kernel calls whenever a packet reaches Jool's
 * IPv4 Netfilter hook.
 */
unsigned int hook_ipv4(void *priv, struct sk_buff *skb,
		const struct nf_hook_state *nhs)
{
	struct xlation *state;
	verdict result;
	unsigned int nf_result;

	state = xlation_create(NULL);
	if (!state)
		return NF_DROP;

	{
		xlator_type xt = (xlator_type)(uintptr_t)priv;
		result = find_instance(skb, xt, &state->jool);
	}
	if (result != VERDICT_CONTINUE) {
		xlation_destroy(state);
		return verdict2netfilter(result, NULL);
	}

	log_debug(state,
			"hook_ipv4: src=%pI4 dst=%pI4 dev=%s",
			&ip_hdr(skb)->saddr,
			&ip_hdr(skb)->daddr,
			skb->dev ? skb->dev->name : "(none)");

	result = core_4to6(skb, state);

	nf_result = verdict2netfilter(result, &state->jool);
	xlator_put(&state->jool);
	xlation_destroy(state);
	return nf_result;
}
EXPORT_SYMBOL_GPL(hook_ipv4);
