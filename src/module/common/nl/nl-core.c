#include "nl/nl-core.h"

#include <net/genetlink.h>

#include "linux-version.h"
#include "nl-protocol.h"
#include "wkmalloc.h"
#include "nl/nl-common.h"

static struct genl_family *family;

void nlcore_init(struct genl_family *new_family)
{
	/*
	 * If this triggers, GENLMSG_DEFAULT_SIZE is too small.
	 * Sorry; I don't want to use BUILD_BUG_ON_MSG because old kernels don't
	 * have it.
	 */
	BUILD_BUG_ON(GENLMSG_DEFAULT_SIZE <= 256);
	family = new_family;
}

int jnl_wrap_instance(struct genl_info *info, jnl_handler handler)
{
	char *instance_name;
	struct xlator instance;
	int error;

	if (!jnla_get_instance_name(info, &instance_name)) {
		log_err("The instance name argument is mandatory.");
		return jnl_respond_error(info, error);
	}

	error = xlator_find(instance_name, &instance);
	if (error)
		return jnl_respond_error(info, error);

	error = handler(&instance, info);

	xlator_put(&instance);
	return error;
}

int jnla_put_l4proto(struct sk_buff *skb, l4_protocol proto)
{
	return nla_put_u8(skb, JNLA_L4PROTO, proto);
}

int jnla_put_addr6(struct sk_buff *skb, jool_nlattr type, struct in6_addr *addr)
{
	return nla_put(skb, type, sizeof(*addr), addr);
}

int jnla_put_addr4(struct sk_buff *skb, jool_nlattr type, struct in_addr *addr)
{
	return nla_put(skb, type, sizeof(*addr), addr);
}

static int jnla_put_taddr6(struct sk_buff *skb,
		struct ipv6_transport_addr *addr,
		jool_nlattr addrtype,
		jool_nlattr porttype)
{
	int error;

	error = jnla_put_addr6(skb, addrtype, &addr->l3);
	if (error)
		return error;

	return jnla_put_port(skb, porttype, addr->l4);
}

static int jnla_put_taddr4(struct sk_buff *skb,
		struct ipv4_transport_addr *addr,
		jool_nlattr addrtype,
		jool_nlattr porttype)
{
	int error;

	error = jnla_put_addr4(skb, addrtype, &addr->l3);
	if (error)
		return error;

	return jnla_put_port(skb, porttype, addr->l4);
}

int jnla_put_src_taddr6(struct sk_buff *skb, struct ipv6_transport_addr *addr)
{
	return jnla_put_taddr6(skb, addr, JNLA_SADDR6, JNLA_SPORT6);
}

int jnla_put_src_taddr4(struct sk_buff *skb, struct ipv4_transport_addr *addr)
{
	return jnla_put_taddr4(skb, addr, JNLA_SADDR4, JNLA_SPORT4);
}

int jnla_put_dst_taddr6(struct sk_buff *skb, struct ipv6_transport_addr *addr)
{
	return jnla_put_taddr6(skb, addr, JNLA_DADDR6, JNLA_DPORT6);
}

int jnla_put_dst_taddr4(struct sk_buff *skb, struct ipv4_transport_addr *addr)
{
	return jnla_put_taddr4(skb, addr, JNLA_DADDR4, JNLA_DPORT4);
}

int jnla_put_port(struct sk_buff *skb, jool_nlattr type, __u16 port)
{
	return nla_put_u16(skb, type, port);
}

static int nla_put_prefixlen(struct sk_buff *skb, jool_nlattr type, __u8 len)
{
	return nla_put_u8(skb, type, len);
}

int jnla_put_prefix6(struct sk_buff *skb, struct ipv6_prefix *prefix)
{
	int error;

	error = jnla_put_addr6(skb, JNLA_PREFIX6ADDR, &prefix->addr);
	if (error)
		return error;

	return nla_put_prefixlen(skb, JNLA_PREFIX6LEN, prefix->len);
}

int jnla_put_prefix4(struct sk_buff *skb, struct ipv4_prefix *prefix)
{
	int error;

	error = jnla_put_addr4(skb, JNLA_PREFIX4ADDR, &prefix->addr);
	if (error)
		return error;

	return nla_put_prefixlen(skb, JNLA_PREFIX4LEN, prefix->len);
}

int jnla_put_bool(struct sk_buff *skb, jool_nlattr type, bool value)
{
	return nla_put_u8(skb, type, value);
}

bool jnla_get_instance_name(struct genl_info *info, char **result)
{
	struct nlattr *attr;

	attr = info->attrs[JNLA_INSTANCE_NAME];
	if (!attr)
		return false;

	*result = nla_data(attr);
	return true;
}

bool jnla_get_l4proto(struct genl_info *info, l4_protocol *result)
{
	__u8 tmp;

	if (!jnla_get_u8(info, JNLA_L4PROTO, &tmp))
		return false;

	*result = tmp;
	return true;
}

static bool nla_get_addr6(struct genl_info *info, jool_nlattr type,
		struct in6_addr *result)
{
	struct nlattr *attr;

	attr = info->attrs[type];
	if (!attr)
		return false;

	memcpy(result, nla_data(attr), sizeof(*result));
	return true;
}

static bool nla_get_addr4(struct genl_info *info, jool_nlattr type,
		struct in_addr *result)
{
	struct nlattr *attr;

	attr = info->attrs[type];
	if (!attr)
		return false;
	/* TODO validate sizes? */

	memcpy(result, nla_data(attr), sizeof(*result));
	return true;
}

bool jnla_get_src_taddr6(struct genl_info *info,
		struct ipv6_transport_addr *result)
{
	if (!nla_get_addr6(info, JNLA_SADDR6, &result->l3))
		return false;

	return jnla_get_port(info, JNLA_SPORT6, &result->l4);
}

bool jnla_get_src_taddr4(struct genl_info *info,
		struct ipv4_transport_addr *result)
{
	if (!nla_get_addr4(info, JNLA_SADDR4, &result->l3))
		return false;

	return jnla_get_port(info, JNLA_SPORT4, &result->l4);
}

bool jnla_get_dst_taddr6(struct genl_info *info,
		struct ipv6_transport_addr *result)
{
	if (!nla_get_addr6(info, JNLA_DADDR6, &result->l3))
		return false;

	return jnla_get_port(info, JNLA_DPORT6, &result->l4);
}

bool jnla_get_dst_taddr4(struct genl_info *info,
		struct ipv4_transport_addr *result)
{
	if (!nla_get_addr4(info, JNLA_DADDR4, &result->l3))
		return false;

	return jnla_get_port(info, JNLA_DPORT4, &result->l4);
}

bool jnla_get_port(struct genl_info *info, jool_nlattr type, __u16 *result)
{
	struct nlattr *attr;

	attr = info->attrs[type];
	if (!attr)
		return false;

	*result = nla_get_u16(attr);
	return true;
}

static bool jnla_get_prefixlen(struct genl_info *info, jool_nlattr type,
		__u8 *result)
{
	struct nlattr *attr;

	attr = info->attrs[type];
	if (!attr)
		return false;

	*result = nla_get_u8(attr);
	return true;
}

bool jnla_get_prefix6(struct genl_info *info, struct ipv6_prefix *result)
{
	if (!nla_get_addr6(info, JNLA_PREFIX6ADDR, &result->addr))
		return false;

	return jnla_get_prefixlen(info, JNLA_PREFIX6LEN, &result->len);
}

bool jnla_get_prefix4(struct genl_info *info, struct ipv4_prefix *result)
{
	if (!nla_get_addr4(info, JNLA_PREFIX4ADDR, &result->addr))
		return false;

	return jnla_get_prefixlen(info, JNLA_PREFIX4LEN, &result->len);
}

bool jnla_get_u32(struct genl_info *info, jool_nlattr type, __u32 *result)
{
	struct nlattr *attr;

	attr = info->attrs[type];
	if (!attr)
		return false;

	*result = nla_get_u32(attr);
	return true;
}

bool jnla_get_u8(struct genl_info *info, jool_nlattr type, __u8 *result)
{
	struct nlattr *attr;

	attr = info->attrs[type];
	if (!attr)
		return false;

	*result = nla_get_u8(attr);
	return true;
}

bool jnla_get_bool(struct genl_info *info, jool_nlattr type, bool *result)
{
	__u8 tmp;

	if (!jnla_get_u8(info, type, &tmp))
		return false;

	*result = !!tmp;
	return true;
}

int jnl_init_pkt(struct genl_info *info, size_t len, struct jnl_packet *pkt)
{
	uint32_t portid;

	/*
	 * Note: genlmsg_new() does not account for Jool's header.
	 * It needs to be included in @len.
	 */
	pkt->skb = genlmsg_new(len, GFP_KERNEL);
	if (!pkt->skb)
		return -ENOMEM;

#if LINUX_VERSION_LOWER_THAN(3, 7, 0, 7, 0)
	portid = info->snd_pid;
#else
	portid = info->snd_portid;
#endif

	pkt->jhdr = genlmsg_put(pkt->skb, portid, info->nlhdr->nlmsg_seq,
			family, 0, info->genlhdr->cmd);
	if (!pkt->jhdr) {
		pr_err("genlmsg_put() failed.\n");
		kfree_skb(pkt->skb);
		return -ENOMEM;
	}
	/* I don't recall if I have to do this or not. Bite me. */
	memset(pkt->jhdr, 0, sizeof(*pkt->jhdr));

	return 0;
}

void jnl_destroy_pkt(struct jnl_packet *pkt)
{
	kfree_skb(pkt->skb);
	pkt->skb = NULL;
}

/**
 * Note: Like every other kernel packet dispatch function, this is a black hole
 * for @pkt. In other words, you should not call jnl_destroy_pkt() after this.
 */
int jnl_respond_pkt(struct genl_info *info, struct jnl_packet *pkt)
{
	int error;

	/* TODO
	if (buffer->len > JNLBUFFER_MAX_PAYLOAD) {
		pr_err("The response is too long; cannot send to userspace.\n");
		return -EINVAL;
	}
	*/

	genlmsg_end(pkt->skb, pkt->jhdr);

	error = genlmsg_reply(pkt->skb, info); /* Implicit kfree_skb here */
	if (error) {
		pr_err("genlmsg_reply() failed. (errcode %d)\n", error);
		return error;
	}

	return 0;
}

int jnl_respond_error(struct genl_info *info, int errcode)
{
	struct jnl_packet pkt;
	size_t payload_len;
	int error;
	char *error_msg = NULL;
	size_t error_msg_size = 0;

	if (errcode) {
		error = errormsg_get(&error_msg, &error_msg_size);
		if (error)
			return error; /* Error msg already printed. */
	}

	/* I'm assuming that the error message is never too long. */

	payload_len = JNL_HDR_LEN;
	payload_len += error_msg ? nla_total_size(error_msg_size) : 0;
	error = jnl_init_pkt(info, payload_len, &pkt);
	if (error)
		goto end;

	pkt.jhdr->error = errcode;

	if (error_msg) {
		error = nla_put_string(pkt.skb, JNLA_ERROR_MSG, error_msg);
		if (WARN(error, "Bug: Packet allocation size was not enough")) {
			jnl_destroy_pkt(&pkt);
			goto end;
		}
		__wkfree("Error msg out", error_msg);
	}

	if (errcode)
		log_debug("Sending error code %d to userspace.", errcode);
	else
		log_debug("Sending ACK to userspace.");
	return jnl_respond_pkt(info, &pkt); /* Implicit kfree_skb(skb) here */

end:
	if (error_msg)
		__wkfree("Error msg out", error_msg);
	return error;
}
