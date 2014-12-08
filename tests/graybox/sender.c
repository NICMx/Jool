#include <linux/module.h>
#include <linux/printk.h>

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Alberto Leiva Popper <aleiva@nic.mx>");
MODULE_DESCRIPTION("Packet sender for gray box tests.");

static __u64 id;
module_param(id, typeof(id), 0);
MODULE_PARM_DESC(id, "The identifier of the packet you want posted on the hook.");

static int yeah_whatever(struct sk_buff *skb)
{
	pr_debug("Reached the OK function.");
	return 0;
}

int init_module(void)
{
	struct sk_buff *skb;
	int error;

	log_debug("Received a request to post packet %u.", id);

	error = create_skb(id, &skb);
	if (error)
		return error;

	error = NF_HOOK(NFPROTO_IPV4, NF_INET_PRE_ROUTING, skb, NULL, NULL, yeah_whatever);
	log_bug("Hook ended with error code %d.", error);

	return 0;
}

void cleanup_module(void)
{
	/* No code. */
}
