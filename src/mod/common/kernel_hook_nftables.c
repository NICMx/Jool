#include "mod/common/kernel_hook.h"

#include <net/netfilter/nf_tables.h>
#include <net/netlink.h>

#include "mod/common/core.h"
#include "mod/common/log.h"
#include "mod/common/translation_state.h"

enum nft_jool_attributes {
	NFTA_JOOL_UNSPEC,
	NFTA_JOOL_TYPE,
	NFTA_JOOL_INSTANCE,
	__NFTA_JOOL_MAX
};
#define NFTA_JOOL_MAX (__NFTA_JOOL_MAX - 1)

const struct nla_policy nft_jool_policy[NFTA_JOOL_MAX + 1] = {
	[NFTA_JOOL_TYPE]		= { .type = NLA_U8 },
	[NFTA_JOOL_INSTANCE]		= { .type = NLA_STRING },
};

static unsigned int verdict2nftables(verdict result)
{
	switch (result) {
	case VERDICT_STOLEN:
		return NF_STOLEN; /* This is the happy path. */
	case VERDICT_UNTRANSLATABLE:
		log_debug("Returning packet to the nftables rule.");
		return NFT_CONTINUE;
	case VERDICT_DROP:
		log_debug("Dropping packet.");
		return NF_DROP;
	case VERDICT_CONTINUE:
		WARN(true, "At time of writing, Jool core is not supposed to return CONTINUE after the packet is handled.\n"
				"Please report this to the Jool devs.");
		return NFT_CONTINUE; /* Hmmm... */
	}

	WARN(true, "Unknown verdict: %d", result);
	return NF_DROP;
}

/**
 * This is the function that the kernel calls whenever a packet reaches one of
 * Jool's nftables rules.
 */
void nft_jool_inet_eval(const struct nft_expr *expr, struct nft_regs *regs,
		const struct nft_pktinfo *pkt)
{
	struct xlation *state;
	verdict result;

	state = xlation_create(NULL);
	if (!state) {
		regs->verdict.code = NF_DROP;
		return;
	}

	result = find_instance_tb(nft_net(pkt), nft_expr_priv(expr),
			&state->jool);
	if (result != VERDICT_CONTINUE)
		goto end;

	switch (nft_pf(pkt)) {
	case NFPROTO_IPV4:
		result = core_4to6(pkt->skb, state);
		break;
	case NFPROTO_IPV6:
		result = core_6to4(pkt->skb, state);
		break;
	default:
		regs->verdict.code = VERDICT_UNTRANSLATABLE;
		break;
	}

	xlator_put(&state->jool);
end:	xlation_destroy(state);
	regs->verdict.code = verdict2nftables(result);
}

static int nft_jool_inet_init(const struct nft_ctx *ctx,
		const struct nft_expr *expr, const struct nlattr *const tb[])
{
	struct target_info *priv;
	char *iname;
	int error;

	if (!tb[NFTA_JOOL_TYPE]) {
		log_err("nftables request lacks an xlator type parameter.");
		return -EINVAL;
	}
	if (!tb[NFTA_JOOL_INSTANCE]) {
		log_err("nftables request lacks an instance name parameter.");
		return -EINVAL;
	}

	iname = nla_data(tb[NFTA_JOOL_INSTANCE]);
	error = iname_validate(iname, false);
	if (error) {
		log_err(INAME_VALIDATE_ERRMSG, INAME_MAX_LEN - 1);
		return error;
	}

	priv = nft_expr_priv(expr);
	strcpy(priv->iname, iname);
	priv->type = nla_get_u8(tb[NFTA_JOOL_TYPE]);

	return 0;
}

int nft_jool_inet_dump(struct sk_buff *skb, const struct nft_expr *expr)
{
	const struct target_info *priv = nft_expr_priv(expr);
	int error;

	error = nla_put_u8(skb, NFTA_JOOL_TYPE, priv->type);
	if (error) {
		log_err("Can't dump the xlator type. Errcode is %d.", error);
		return error;
	}

	error = nla_put_string(skb, NFTA_JOOL_INSTANCE, priv->iname);
	if (error) {
		log_err("Can't dump the instance name. Errcode is %d.", error);
		return error;
	}

	return 0;
}

int nft_jool_validate(const struct nft_ctx *ctx, const struct nft_expr *expr,
		const struct nft_data **data)
{
	int error;

	error = nft_chain_validate_hooks(ctx->chain, 1 << NF_INET_PRE_ROUTING);
	if (error)
		log_err("nftables rule appears to be outside of prerouting.");

	return error;
}

static struct nft_expr_type nft_jool_inet_type;
static const struct nft_expr_ops nft_jool_inet_ops = {
	.type		= &nft_jool_inet_type,
	.size		= NFT_EXPR_SIZE(sizeof(struct target_info)),
	.eval		= nft_jool_inet_eval,
	.init		= nft_jool_inet_init,
	.dump		= nft_jool_inet_dump,
	.validate	= nft_jool_validate,
};

static struct nft_expr_type nft_jool_inet_type = {
	.family		= NFPROTO_INET,
	.name		= "jool",
	.ops		= &nft_jool_inet_ops,
	.policy		= nft_jool_policy,
	.maxattr	= NFTA_JOOL_MAX,
	.owner		= THIS_MODULE,
};

static atomic_t init_refs = ATOMIC_INIT(0);
static int init_error;

void nft_setup(void)
{
	if (atomic_inc_return(&init_refs) == 1) {
		init_error = nft_register_expr(&nft_jool_inet_type);
		if (init_error) {
			log_warn("Error code %d while trying to register the nftables expressions.\n"
					"nftables Jool will not be available.",
					init_error);
		} else {
			log_debug("nftables expression registered.");
		}
	}
}
EXPORT_SYMBOL_GPL(nft_setup);

void nft_teardown(void)
{
	if (atomic_dec_return(&init_refs) == 0) {
		if (!init_error) {
			nft_unregister_expr(&nft_jool_inet_type);
			log_debug("nftables expression unregistered.");
		}
	}
}
EXPORT_SYMBOL_GPL(nft_teardown);
