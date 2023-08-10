#include <linux/kernel.h>
#include <linux/module.h>

#include "framework/bib.h"
#include "framework/unit_test.h"
#include "mod/common/joold.c"

MODULE_LICENSE(JOOL_LICENSE);
MODULE_AUTHOR("Alberto Leiva");
MODULE_DESCRIPTION("joold test.");

static struct session_entry session1;
static struct session_entry session2;
static struct session_entry session3;

#define JOOLNL_HDRLEN NLMSG_ALIGN(sizeof(struct joolnlhdr))

/********************** Mocks **********************/

struct sk_buff *sent;

void sendpkt_multicast(struct xlator *jool, struct sk_buff *skb)
{
	sent = skb;
}

static struct genl_family family_mock = {
	.id = 1234,
	.hdrsize = sizeof(struct joolnlhdr),
	.version = 2,
	.module = THIS_MODULE,
};

struct genl_family *jnl_family(void)
{
	return &family_mock;
}

int bib_foreach_session(struct xlator *jool, l4_protocol proto,
		session_foreach_entry_cb cb, void *cb_arg,
		struct session_foreach_offset *offset)
{
	return -EINVAL;
}

int bib_add_session(struct xlator *jool,
		struct session_entry *session,
		struct collision_cb *cb)
{
	return -EINVAL;
}

/********************** Init **********************/

static void init_session(unsigned int index, struct session_entry *result)
{
	result->src6.l3.s6_addr32[0] = cpu_to_be32(0x20010db8);
	result->src6.l3.s6_addr32[1] = 0;
	result->src6.l3.s6_addr32[2] = 0;
	result->src6.l3.s6_addr32[3] = cpu_to_be32(index);
	result->src6.l4 = 3000;

	result->dst6.l3.s6_addr32[0] = cpu_to_be32(0x0064ff9b);
	result->dst6.l3.s6_addr32[1] = 0;
	result->dst6.l3.s6_addr32[2] = 0;
	result->dst6.l3.s6_addr32[3] = cpu_to_be32(0xc0000200 | index);
	result->dst6.l4 = 80;

	result->src4.l3.s_addr = cpu_to_be32(0xcb007100 | index);
	result->src4.l4 = 4000;

	result->dst4.l3.s_addr = result->dst6.l3.s6_addr32[3];
	result->dst4.l4 = result->dst6.l4;

	result->proto = L4PROTO_TCP;
	result->state = 0;
	result->timer_type = SESSION_TIMER_TRANS;
	result->update_time = jiffies;
	result->timeout = 5000;
	result->has_stored = false;
}


static int init_sessions(void)
{
	init_session(1, &session1);
	init_session(2, &session2);
	init_session(3, &session3);
	return 0;
}

static struct joold_queue *init_xlator(struct xlator *jool)
{
	jool->globals.nat64.joold.enabled = true;
	jool->globals.nat64.joold.flush_asap = false;
	jool->globals.nat64.joold.flush_deadline = 2000;
	jool->globals.nat64.joold.capacity = 4;
	jool->globals.nat64.joold.max_payload = 1500;
	jool->nat64.joold = joold_alloc();
	return jool->nat64.joold;
}

/********************** Helpers **********************/

static int compute_max_payload(struct xlator *jool, unsigned int nsessions)
{
	struct joold_pkt dummy_pkt;
	struct session_entry dummy_session;
	size_t basic_size; /* NL header, GNL header, Jool header, root attr */
	size_t session_size;
	size_t total_size;
	int error;

	error = joold_pkt_init(&dummy_pkt, jool);
	if (error)
		return error;

	basic_size = dummy_pkt.skb->len;

	memset(&dummy_session, 0, sizeof(dummy_session));
	error = jnla_put_session(dummy_pkt.skb, JNLAL_ENTRY, &dummy_session);
	if (error)
		goto end;

	session_size = dummy_pkt.skb->len - basic_size;
	total_size = NLMSG_ALIGN(sizeof(struct joolnlhdr)) + NLA_HDRLEN
			+ nsessions * session_size;

	log_info("session size: %zu", sizeof(dummy_session));
	log_info("serialized session size: %zu", session_size);
	log_info("total size: %zu", total_size);

	jool->globals.nat64.joold.max_payload = total_size;
end:	kfree_skb(dummy_pkt.skb);
	return error;
}

/********************** Asserts **********************/

static bool assert_deferred(struct joold_queue *joold, ...)
{
	struct session_entry *expected;
	struct deferred_session *actual;
	unsigned int count;
	va_list args;
	bool success = true;

	va_start(args, joold);

	count = 0;
	list_for_each_entry(actual, &joold->deferred.list, lh) {
		expected = va_arg(args, struct session_entry *);
		if (!expected) {
			log_err("Unexpected deferred session: " SEPP,
					SEPA(&actual->session));
			success = false;
			goto end;
		}

		success &= ASSERT_SESSION(expected, &actual->session, "a");
		count++;
	}

	expected = va_arg(args, struct session_entry *);
	if (expected != NULL) {
		log_err("Session missing from deferred: " SEPP, SEPA(expected));
		success = false;
		goto end;
	}

	success &= ASSERT_UINT(count, joold->deferred.count, "b");

end:	va_end(args);
	return success;
}

static bool assert_skb_sessions(struct sk_buff *skb, ...)
{
	struct session_entry *expected, actual;
	struct nlattr *root, *attr;
	struct bib_config bibcfg;
	int rem;
	va_list args;
	bool success;
	int error;

	if (!skb) {
		log_err("skb is NULL.");
		return false;
	}

	root = nlmsg_attrdata(nlmsg_hdr(skb), GENL_HDRLEN + JOOLNL_HDRLEN);
	success = ASSERT_UINT(JNLAR_SESSION_ENTRIES, nla_type(root), "achoo");

	memset(&bibcfg, 0, sizeof(bibcfg));
	bibcfg.ttl.tcp_est = 1000 * TCP_EST;
	bibcfg.ttl.tcp_trans = 1000 * TCP_TRANS;
	bibcfg.ttl.udp = 1000 * UDP_DEFAULT;
	bibcfg.ttl.icmp = 1000 * ICMP_DEFAULT;

	va_start(args, skb);

	nla_for_each_nested(attr, root, rem) {
		error = jnla_get_session(attr, "session", &bibcfg, &actual);
		if (error) {
			log_err("jnla_get_session: errcode %d", error);
			success = false;
			goto end;
		}

		expected = va_arg(args, struct session_entry *);
		if (!expected) {
			log_err("Unexpected packet session: " SEPP, SEPA(&actual));
			success = false;
			goto end;
		}

		success &= ASSERT_SESSION(expected, &actual, "a");
	}

	expected = va_arg(args, struct session_entry *);
	if (expected != NULL) {
		log_err("Session missing from packet: " SEPP, SEPA(expected));
		success = false;
	}

end:	va_end(args);
	return success;
}

/********************** Unit tests **********************/

static bool no_flush_asap(void)
{
	struct xlator jool;
	struct joold_queue *joold;
	bool success = true;

	joold = init_xlator(&jool);
	if (!joold)
		return false;
	if (compute_max_payload(&jool, 2))
		return false;

	joold_add(&jool, &session1);
	success &= ASSERT_UINT(JQF_ACK_RECEIVED, joold->flags, "flags1");
	success &= ASSERT_NOTNULL(joold->pkt.skb, "pkt1");
	success &= ASSERT_NOTNULL(joold->pkt.jhdr, "jhdr1");
	success &= ASSERT_NOTNULL(joold->pkt.root, "root1");
	success &= ASSERT_TRUE(joold->pkt.has_sessions, "has_sessions1");
	success &= ASSERT_FALSE(joold->pkt.full, "full1");
	success &= assert_deferred(joold, NULL);
	success &= ASSERT_NULL(sent, "sent1");
	if (!success)
		return false;

	joold_add(&jool, &session2);
	success &= ASSERT_UINT(JQF_ACK_RECEIVED, joold->flags, "flags2");
	success &= ASSERT_NOTNULL(joold->pkt.skb, "pkt2");
	success &= ASSERT_NOTNULL(joold->pkt.jhdr, "jhdr2");
	success &= ASSERT_NOTNULL(joold->pkt.root, "root2");
	success &= ASSERT_TRUE(joold->pkt.has_sessions, "has_sessions2");
	success &= ASSERT_FALSE(joold->pkt.full, "full2");
	success &= assert_deferred(joold, NULL);
	success &= ASSERT_NULL(sent, "sent2");
	if (!success)
		return false;

	joold_add(&jool, &session3);
	success &= ASSERT_UINT(0, joold->flags, "flags3");
	success &= ASSERT_NULL(joold->pkt.skb, "pkt3");
	success &= ASSERT_NULL(joold->pkt.jhdr, "jhdr3");
	success &= ASSERT_NULL(joold->pkt.root, "root3");
	success &= ASSERT_FALSE(joold->pkt.has_sessions, "has_sessions3");
	success &= ASSERT_FALSE(joold->pkt.full, "full3");
	success &= assert_deferred(joold, &session3, NULL);
	success &= assert_skb_sessions(sent, &session1, &session2, NULL);
	if (!success)
		return false;

	return true;
}

/********************** Hooks **********************/

int init_module(void)
{
	struct test_group test = {
		.name = "joold",
		.setup_fn = init_sessions,
	};

	if (test_group_begin(&test))
		return -EINVAL;
	test_group_test(&test, no_flush_asap, "ss-flush-asap disabled");
	return test_group_end(&test);
}

void cleanup_module(void)
{
	/* No code. */
}
