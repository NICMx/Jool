#include "nf_nat64_bib_session.h"

struct expiry_q expiry_base[NUM_EXPIRY_QUEUES] = {
//
        { { NULL, NULL }, UDP_DEFAULT_ }, //
        { { NULL, NULL }, TCP_TRANS_ }, //
        { { NULL, NULL }, TCP_EST_ }, //
        { { NULL, NULL }, TCP_INCOMING_SYN_ }, //
        { { NULL, NULL }, ICMP_DEFAULT_ } //
};

struct kmem_cache *st_cache;
struct kmem_cache *st_cacheTCP;
struct kmem_cache *st_cacheICMP;
struct kmem_cache *bib_cache;
struct kmem_cache *bib_cacheTCP;
struct kmem_cache *bib_cacheICMP;
struct hlist_head *hash6;
struct hlist_head *hash4;
unsigned int hash_size;

int nat64_create_bib_session_memory(void)
{
	if (nat64_allocate_hash(65536)) // FIXME: look in the kernel headers for the definition of this constant (size) and use it instead of this hardcoded value.
	{
		pr_warning("NAT64: Unable to allocate memmory for hash table.");
		goto hash_error;
	}

	st_cache = kmem_cache_create("nat64_st", sizeof(struct nat64_st_entry), 0,
	        0, NULL);
	st_cacheTCP = kmem_cache_create("nat64_stTCP",
	        sizeof(struct nat64_st_entry), 0, 0, NULL);

	st_cacheICMP = kmem_cache_create("nat64_stICMP",
	        sizeof(struct nat64_st_entry), 0, 0, NULL);

	if (!st_cache || !st_cacheTCP || !st_cacheICMP) {
		pr_warning("NAT64: Unable to create session table slab cache.");
		goto st_cache_error;
	}
	pr_debug("NAT64: The session table slab cache was succesfully created.\n");

	bib_cache = kmem_cache_create("nat64_bib", sizeof(struct nat64_bib_entry),
	        0, 0, NULL);
	bib_cacheTCP = kmem_cache_create("nat64_bibTCP",
	        sizeof(struct nat64_bib_entry), 0, 0, NULL);

	bib_cacheICMP = kmem_cache_create("nat64_bibICMP",
	        sizeof(struct nat64_bib_entry), 0, 0, NULL);
	if (!bib_cache || !bib_cacheTCP || !bib_cacheICMP) {
		pr_warning("NAT64: Unable to create bib table slab cache.");
		goto bib_cache_error;
	}

	return 0;

	hash_error: return -ENOMEM;
	st_cache_error: kmem_cache_destroy(st_cache);
	kmem_cache_destroy(st_cacheTCP);
	kmem_cache_destroy(st_cacheICMP);
	return -ENOMEM;
	bib_cache_error: kmem_cache_destroy(st_cache);
	kmem_cache_destroy(st_cacheTCP);
	kmem_cache_destroy(st_cacheICMP);
	kmem_cache_destroy(bib_cache);
	kmem_cache_destroy(bib_cacheTCP);
	kmem_cache_destroy(bib_cacheICMP);
	return -ENOMEM;
}

int nat64_destroy_bib_session_memory(void)
{

	kmem_cache_destroy(st_cache); // Line inherited from Julius Kriukas's nat64_exit function.
	kmem_cache_destroy(bib_cache); // Line inherited from Julius Kriukas's nat64_exit function.
	kmem_cache_destroy(st_cacheTCP);
	kmem_cache_destroy(bib_cacheTCP);
	kmem_cache_destroy(st_cacheICMP);
	kmem_cache_destroy(bib_cacheICMP);

	return 0;
}

__be16 nat64_hash4(__be32 addr, __be16 port)
{
	return port;
}

__be16 nat64_hash6(struct in6_addr addr6, __be16 port)
{
	__be32 addr4 = addr6.s6_addr32[1] ^ addr6.s6_addr32[2] ^ addr6.s6_addr32[3];
	return (addr4 >> 16) ^ addr4 ^ port;
}

void nat64_session_renew(struct nat64_st_entry *session, enum expiry_type type)
{
	list_del(&session->byexpiry);
	session->expires = jiffies + expiry_base[type].timeout * HZ;
	list_add_tail(&session->byexpiry, &expiry_base[type].queue);
	printk("NAT64: [session] Renewing session %pI4:%hu (timeout %u sec).\n",
	        &session->remote4_addr, ntohs(session->remote4_port),
	        expiry_base[type].timeout);
}

int nat64_tcp_timeout_fsm(struct nat64_st_entry *session)
{
	if (session->state == ESTABLISHED) {
		nat64_session_renew(session, TCP_TRANS);
		session->state = FOUR_MIN;
		return 1;
	}

	return 0;
}

void nat64_tcp4_fsm(struct nat64_st_entry *session, struct tcphdr *tcph)
{
	//	printk("nat64: [fsm4] Got packet state %d.\n", session->state);

	switch (session->state) {
		case CLOSED:
			break;
		case V6_SYN_RCV:
			if (tcph->syn) {
				nat64_session_renew(session, TCP_EST);
				session->state = ESTABLISHED;
			}
			break;
		case V4_SYN_RCV:
			//if(tcph->syn)
			//	session_renew(session, TCP_TRANS);
			break;
		case FOUR_MIN:
			if (!tcph->rst) {
				nat64_session_renew(session, TCP_EST);
				session->state = ESTABLISHED;
			}
			break;
		case ESTABLISHED:
			if (tcph->fin) {
				//session_renew(session, TCP_EST);
				session->state = V4_FIN_RCV;
			} else if (tcph->rst) {
				nat64_session_renew(session, TCP_TRANS);
				session->state = FOUR_MIN;
			} else {
				nat64_session_renew(session, TCP_EST);
			}
			break;
		case V6_FIN_RCV:
			if (tcph->fin) {
				nat64_session_renew(session, TCP_TRANS);
				session->state = V6_FIN_V4_FIN;
			} else {
				nat64_session_renew(session, TCP_EST);
			}
			break;
		case V4_FIN_RCV:
			nat64_session_renew(session, TCP_EST);
			break;
		case V6_FIN_V4_FIN:
			break;
	}
}

void nat64_tcp6_fsm(struct nat64_st_entry *session, struct tcphdr *tcph)
{
	//	printk("nat64: [fsm6] Got packet state %d.\n", session->state);

	switch (session->state) {
		case CLOSED:
			if (tcph->syn) {
				nat64_session_renew(session, TCP_TRANS);
				session->state = V6_SYN_RCV;
			}
			break;
		case V6_SYN_RCV:
			if (tcph->syn)
				nat64_session_renew(session, TCP_TRANS);
			break;
		case V4_SYN_RCV:
			if (tcph->syn) {
				nat64_session_renew(session, TCP_EST);
				session->state = ESTABLISHED;
			}
			break;
		case FOUR_MIN:
			if (!tcph->rst) {
				nat64_session_renew(session, TCP_EST);
				session->state = ESTABLISHED;
			}
			break;
		case ESTABLISHED:
			if (tcph->fin) {
				//session_renew(session, TCP_EST);
				session->state = V6_FIN_RCV;
			} else if (tcph->rst) {
				nat64_session_renew(session, TCP_TRANS);
				session->state = FOUR_MIN;
			} else {
				nat64_session_renew(session, TCP_EST);
			}
			break;
		case V6_FIN_RCV:
			nat64_session_renew(session, TCP_EST);
			break;
		case V4_FIN_RCV:
			if (tcph->fin) {
				nat64_session_renew(session, TCP_TRANS);
				session->state = V6_FIN_V4_FIN;
			} else {
				nat64_session_renew(session, TCP_EST);
			}
			break;
		case V6_FIN_V4_FIN:
			break;
	}
}

void nat64_clean_expired_sessions(struct list_head *queue, int expiry_type)
{
	struct list_head *pos;
	struct list_head *n;
	struct list_head *next_session;
	struct nat64_st_entry *session;
	struct nat64_bib_entry *bib;
	int i = 0;

	list_for_each_safe(pos, n, queue) {
		++i;
		session = list_entry(pos, struct nat64_st_entry, byexpiry);
		if (time_after(jiffies, session->expires)) {
			if (expiry_type >= 1 && expiry_type <= 3) {
				if (nat64_tcp_timeout_fsm(session))
					continue;
			}
			printk("NAT64: [garbage-collector] removing session %pI4:%hu\n",
			        &session->remote4_addr, ntohs(session->remote4_port));
			list_del(pos);
			next_session = session->list.next;
			list_del(&session->list);
			if (list_empty(next_session)) {
				bib = list_entry(next_session, struct nat64_bib_entry, sessions);
				printk(
				        "NAT64: [garbage-collector] removing bib %pI6c,%hu <--> %pI4:%hu\n",
				        &bib->remote6_addr, ntohs(bib->remote6_port),
				        &bib->local4_addr, ntohs(bib->local4_port));
				hlist_del(&bib->byremote);
				hlist_del(&bib->bylocal);
				if (expiry_type >= 1 && expiry_type <= 3) {
					kmem_cache_free(bib_cacheTCP, bib);
				} else if (expiry_type == 0) {
					kmem_cache_free(bib_cache, bib);
				} else if (expiry_type == 4) {
					kmem_cache_free(bib_cacheICMP, bib);
				}
			}
			if (expiry_type >= 1 && expiry_type <= 3) {
				kmem_cache_free(st_cacheTCP, session);
			} else if (expiry_type == 0) {
				kmem_cache_free(st_cache, session);
			} else if (expiry_type == 4) {
				kmem_cache_free(st_cacheICMP, session);
			}
		} else {
			break;
		}
	}
}

struct nat64_st_entry *nat64_session_ipv4_lookup(struct nat64_bib_entry *bib,
        __be32 remote4_addr, __be16 remote4_port)
{
	struct nat64_st_entry *session;
	struct list_head *pos;

	list_for_each(pos, &bib->sessions) {
		session = list_entry(pos, struct nat64_st_entry, list);
		if (session->remote4_addr == remote4_addr && session->remote4_port
		        == remote4_port)
			return session;
	}

	return NULL;
}

struct nat64_st_entry *nat64_session_ipv4_hairpin_lookup(
        struct nat64_bib_entry *bib, __be32 local4_addr, __be16 local4_port)
{
	struct nat64_st_entry *session;
	struct list_head *pos;

	list_for_each(pos, &bib->sessions) {
		session = list_entry(pos, struct nat64_st_entry, list);
		if (session->local4_addr == local4_addr && session->local4_port
		        == local4_port)
			return session;
	}

	return NULL;
}

struct nat64_st_entry *nat64_session_create(struct nat64_bib_entry *bib,
        struct in6_addr *in6_daddr, __be32 addr, __be16 port,
        enum expiry_type type)
{
	struct nat64_st_entry *s;

	s = kmem_cache_zalloc(st_cache, GFP_ATOMIC);
	if (!s) {
		printk(
		        "NAT64: [session] Unable to allocate memory for new session entry.\n");
		return NULL;
	}
	s->state = CLOSED;

	s->remote6_addr = bib->remote6_addr; // X' addr
	s->embedded6_addr = *(in6_daddr); // Y' addr
	s->local4_addr = bib->local4_addr; // T' addr
	s->remote4_addr = addr; // Z' addr

	s->remote6_port = bib->remote6_port; // x port
	s->embedded6_port = port; // y port
	s->local4_port = bib->local4_port; // t port
	s->remote4_port = port; // z port

	list_add(&s->list, &bib->sessions);

	s->expires = jiffies + expiry_base[type].timeout * HZ;
	list_add_tail(&s->byexpiry, &expiry_base[type].queue);

	printk("NAT64: [session] New session (timeout %u sec).\n",
	        expiry_base[type].timeout);
	printk("NAT64: [session] x:%hu \tX':%pI6c.\n", ntohs(s->remote6_port),
	        &s->remote6_addr);
	printk("NAT64: [session] y:%hu \tY':%pI6c.\n", ntohs(s->embedded6_port),
	        &s->embedded6_addr);
	printk("NAT64: [session] t:%hu \tT:%pI4.\n", ntohs(s->local4_port),
	        &s->local4_addr);
	printk("NAT64: [session] z:%hu \tZ(Y'):%pI4.\n", ntohs(s->remote4_port),
	        &s->remote4_addr);

	return s;
}

struct nat64_st_entry *nat64_session_create_icmp(struct nat64_bib_entry *bib,
        struct in6_addr *in6_daddr, __be32 addr, __be16 port,
        enum expiry_type type)
{
	struct nat64_st_entry *s;

	s = kmem_cache_zalloc(st_cacheICMP, GFP_ATOMIC);
	if (!s) {
		printk(
		        "NAT64: [session] Unable to allocate memory for new session entry.\n");
		return NULL;
	}
	s->state = CLOSED;

	s->remote6_addr = bib->remote6_addr; // X' addr
	s->embedded6_addr = *(in6_daddr); // Y' addr
	s->local4_addr = bib->local4_addr; // T' addr
	s->remote4_addr = addr; // Z' addr

	s->remote6_port = bib->remote6_port; // x port
	s->embedded6_port = port; // y port
	s->local4_port = bib->local4_port; // t port
	s->remote4_port = port; // z port

	list_add(&s->list, &bib->sessions);

	s->expires = jiffies + expiry_base[type].timeout * HZ;
	list_add_tail(&s->byexpiry, &expiry_base[type].queue);

	printk("NAT64: [session] New session (timeout %u sec).\n",
	        expiry_base[type].timeout);
	printk("NAT64: [session] x:%hu \tX':%pI6c.\n", ntohs(s->remote6_port),
	        &s->remote6_addr);
	printk("NAT64: [session] y:%hu \tY':%pI6c.\n", ntohs(s->embedded6_port),
	        &s->embedded6_addr);
	printk("NAT64: [session] t:%hu \tT:%pI4.\n", ntohs(s->local4_port),
	        &s->local4_addr);
	printk("NAT64: [session] z:%hu \tZ(Y'):%pI4.\n", ntohs(s->remote4_port),
	        &s->remote4_addr);

	return s;
}

struct nat64_st_entry *nat64_session_create_tcp(struct nat64_bib_entry *bib,
        struct in6_addr *in6_daddr, __be32 addr, __be16 port,
        enum expiry_type type)
{
	struct nat64_st_entry *s;

	s = kmem_cache_zalloc(st_cacheTCP, GFP_ATOMIC);
	if (!s) {
		printk(
		        "NAT64: [session] Unable to allocate memory for new session entry.\n");
		return NULL;
	}
	s->state = CLOSED;

	s->remote6_addr = bib->remote6_addr; // X' addr
	s->embedded6_addr = *(in6_daddr); // Y' addr
	s->local4_addr = bib->local4_addr; // T' addr
	s->remote4_addr = addr; // Z' addr

	s->remote6_port = bib->remote6_port; // x port
	s->embedded6_port = port; // y port
	s->local4_port = bib->local4_port; // t port
	s->remote4_port = port; // z port

	list_add(&s->list, &bib->sessions);

	s->expires = jiffies + expiry_base[type].timeout * HZ;
	list_add_tail(&s->byexpiry, &expiry_base[type].queue);

	pr_debug("NAT64: [session] New session (timeout %u sec).",
	        expiry_base[type].timeout);
	pr_debug("NAT64: [session] x:%hu\tX':%pI6c.", ntohs(s->remote6_port),
	        &s->remote6_addr);
	pr_debug("NAT64: [session] y:%hu\tY':%pI6c.", ntohs(s->embedded6_port),
	        &s->embedded6_addr);
	pr_debug("NAT64: [session] t:%hu\tT':%pI4.", ntohs(s->local4_port),
	        &s->local4_addr);
	pr_debug("NAT64: [session] z:%hu\tZ':%pI4.", ntohs(s->remote4_port),
	        &s->remote4_addr);

	return s;
}

struct nat64_bib_entry *nat64_bib_ipv4_lookup(__be32 local_addr,
        __be16 local_port, int type)
{
	struct hlist_node *pos;
	struct nat64_bib_entry *bib;
	__be16 h = nat64_hash4(local_addr, local_port);
	struct hlist_head *hlist = &hash4[h];

	hlist_for_each(pos, hlist) {
		bib = hlist_entry(pos, struct nat64_bib_entry, bylocal);
		if (bib->type == type && bib->local4_addr == local_addr
		        && bib->local4_port == local_port)
			return bib;
	}

	//return (pos ? bib : NULL);
	return NULL;
}

struct nat64_bib_entry *nat64_bib_ipv6_lookup(struct in6_addr *remote_addr,
        __be16 remote_port, int type)
{
	struct hlist_node *pos;
	struct nat64_bib_entry *bib;
	__be16 h = nat64_hash6(*remote_addr, remote_port);
	struct hlist_head *hlist = &hash6[h];

	hlist_for_each(pos, hlist) {
		bib = hlist_entry(pos, struct nat64_bib_entry, byremote);
		if (bib->type == type && bib->remote6_port == remote_port && memcmp(
		        &bib->remote6_addr, remote_addr, sizeof(*remote_addr)) == 0)
			return bib;
	}

	//return (pos ? bib : NULL);
	return NULL;
}

__be16 nat64_bib_allocate_local4_port(__be16 port, int type)
{
	// FIXME: This should give a different port than the one it originally came from.
	struct hlist_node *node;
	struct nat64_bib_entry *entry;
	__be16 min, max, i;
	int flag = 0;
	port = ntohs(port);
	min = port < 1024 ? 0 : 1024;
	max = port < 1024 ? 1023 : 65535;

	for (i = port; i <= max; i += 2, flag = 0) {
		hlist_for_each(node, &hash4[htons(i)]) {
			entry = hlist_entry(node, struct nat64_bib_entry, bylocal);
			if (entry->type == type) {
				flag = 1;
				break;
			}
		}
		if (!flag)
			return htons(i);
	}

	flag = 0;
	for (i = port - 2; i >= min; i -= 2, flag = 0) {
		hlist_for_each(node, &hash4[htons(i)]) {
			entry = hlist_entry(node, struct nat64_bib_entry, bylocal);
			if (entry->type == type) {
				flag = 1;
				break;
			}
		}
		if (!flag)
			return htons(i);
	}

	return -1;
}

struct nat64_bib_entry *nat64_bib_create(struct in6_addr *remote6_addr,
        __be16 remote6_port, __be32 local4_addr, __be16 local4_port, int type)
{
	struct nat64_bib_entry *bib;

	bib = kmem_cache_zalloc(bib_cache, GFP_ATOMIC);
	if (!bib) {
		printk("NAT64: [bib] Unable to allocate memory for new bib entry.\n");
		return NULL;
	}

	bib->type = type;
	memcpy(&bib->remote6_addr, remote6_addr, sizeof(struct in6_addr));
	bib->local4_addr = local4_addr;
	bib->remote6_port = remote6_port;
	bib->local4_port = local4_port; // FIXME: Should be different than the remote6_port.
	INIT_LIST_HEAD(&bib->sessions);
	pr_debug("NAT64: [bib] New bib %pI6c,%hu <--> %pI4:%hu.\n", remote6_addr,
	        ntohs(remote6_port), &local4_addr, ntohs(local4_port));

	return bib;
}

struct nat64_bib_entry *nat64_bib_create_icmp(struct in6_addr *remote6_addr,
        __be16 remote6_port, __be32 local4_addr, __be16 local4_port, int type)
{
	struct nat64_bib_entry *bib;

	bib = kmem_cache_zalloc(bib_cacheICMP, GFP_ATOMIC);
	if (!bib) {
		printk("NAT64: [bib] Unable to allocate memory for new bib entry.\n");
		return NULL;
	}

	bib->type = type;
	memcpy(&bib->remote6_addr, remote6_addr, sizeof(struct in6_addr));
	bib->local4_addr = local4_addr;
	bib->remote6_port = remote6_port;
	bib->local4_port = local4_port; // FIXME: Should be different than the remote6_port.
	INIT_LIST_HEAD(&bib->sessions);
	pr_debug("NAT64: [bib] New bib %pI6c,%hu <--> %pI4:%hu.\n", remote6_addr,
	        ntohs(remote6_port), &local4_addr, ntohs(local4_port));

	return bib;
}

struct nat64_bib_entry *nat64_bib_create_tcp(struct in6_addr *remote6_addr,
        __be16 remote6_port, __be32 local4_addr, __be16 local4_port, int type)
{
	struct nat64_bib_entry *bib;

	bib = kmem_cache_zalloc(bib_cacheTCP, GFP_ATOMIC);
	if (!bib) {
		printk(
		        "NAT64: [bib] Unable to allocate memory for new TCP bib entry.\n");
		return NULL;
	}

	bib->type = type;
	memcpy(&bib->remote6_addr, remote6_addr, sizeof(struct in6_addr));
	bib->local4_addr = local4_addr;
	bib->remote6_port = remote6_port;
	bib->local4_port = local4_port; // FIXME: Should be different than the remote6_port.
	INIT_LIST_HEAD(&bib->sessions);
	pr_debug("NAT64: [bib] New TCP bib %pI6c,%hu <--> %pI4:%hu.", remote6_addr,
	        ntohs(remote6_port), &local4_addr, ntohs(local4_port));

	return bib;
}

struct nat64_bib_entry *nat64_bib_session_create(struct in6_addr *saddr,
        struct in6_addr *in6_daddr, __be32 daddr, __be16 sport, __be16 dport,
        int protocol, enum expiry_type type)
{
	struct nat64_bib_entry *bib;
	struct nat64_st_entry *session;
	__be16 local4_port;
	__be32 local4_addr;

	//local4_port = bib_allocate_local4_port(sport, protocol); // FIXME: Should be different than sport
	struct transport_addr_struct *transport_addr;
	transport_addr = get_udp_transport_addr();

	if (transport_addr == NULL) {
		printk("pool out of ipv4 address\n");
		local4_port = -1;
		local4_addr = -1;
	} else {
		INIT_LIST_HEAD(&transport_addr->list);
		if (type == ICMP_DEFAULT) {
			local4_port = sport;

		} else {
			local4_port = ntohs(transport_addr->port);
		}
		in4_pton(transport_addr->address, -1, (u8 *) &local4_addr, '\x0', NULL);
		pr_debug("NAT: IPv4 Pool: using address %s and port %u.\n",
		        transport_addr->address, transport_addr->port);
	}

	if (local4_port < 0) {
		pr_debug(
		        "NAT64: [bib] Unable to allocate new local IPv4 port. Dropping connection.\n");
		return NULL;
	}

	//bib = bib_create(saddr, sport, ipv4_addr, local4_port, protocol);
	bib = nat64_bib_create(saddr, sport, local4_addr, local4_port, protocol);

	if (!bib)
		return NULL;

	hlist_add_head(&bib->byremote, &hash6[nat64_hash6(*saddr, sport)]);
	hlist_add_head(&bib->bylocal, &hash4[local4_port]);
	//	hlist_add_head(&bib->bylocal, &hash4[sport]);

	session = nat64_session_create(bib, in6_daddr, daddr, dport, type);
	if (!session) {
		kmem_cache_free(bib_cache, bib);
		return NULL;
	}

	return bib;
}

struct nat64_bib_entry *nat64_bib_session_create_icmp(struct in6_addr *saddr,
        struct in6_addr *in6_daddr, __be32 daddr, __be16 sport, __be16 dport,
        int protocol, enum expiry_type type)
{
	struct nat64_bib_entry *bib;
	struct nat64_st_entry *session;
	__be16 local4_port;
	__be32 local4_addr;

	//local4_port = bib_allocate_local4_port(sport, protocol); // FIXME: Should be different than sport
	struct transport_addr_struct *transport_addr;
	transport_addr = get_udp_transport_addr();

	if (transport_addr == NULL) {
		printk("pool out of ipv4 address\n");
		local4_port = -1;
		local4_addr = -1;
	} else {
		INIT_LIST_HEAD(&transport_addr->list);
		if (type == ICMP_DEFAULT) {
			local4_port = sport;

		} else {
			local4_port = ntohs(transport_addr->port);
		}
		in4_pton(transport_addr->address, -1, (u8 *) &local4_addr, '\x0', NULL);
		pr_debug("NAT: IPv4 Pool: using address %s and port %u.\n",
		        transport_addr->address, transport_addr->port);
	}

	if (local4_port < 0) {
		pr_debug(
		        "NAT64: [bib] Unable to allocate new local IPv4 port. Dropping connection.\n");
		return NULL;
	}

	//bib = bib_create(saddr, sport, ipv4_addr, local4_port, protocol);
	bib = nat64_bib_create_icmp(saddr, sport, local4_addr, local4_port,
	        protocol);

	if (!bib)
		return NULL;

	hlist_add_head(&bib->byremote, &hash6[nat64_hash6(*saddr, sport)]);
	hlist_add_head(&bib->bylocal, &hash4[local4_port]);
	//	hlist_add_head(&bib->bylocal, &hash4[sport]);

	session = nat64_session_create(bib, in6_daddr, daddr, dport, type);
	if (!session) {
		kmem_cache_free(bib_cacheICMP, bib);
		return NULL;
	}

	return bib;
}

struct nat64_bib_entry *nat64_bib_session_create_tcp(struct in6_addr *saddr,
        struct in6_addr *in6_daddr, __be32 daddr, __be16 sport, __be16 dport,
        int protocol, enum expiry_type type)
{
	struct nat64_bib_entry *bib;
	struct nat64_st_entry *session;
	struct transport_addr_struct *transport_addr;
	__be16 local4_port;
	__be32 local4_addr;

	pr_debug("NAT64: [bib1] source PORT %hu .\n", ntohs(sport));
	// local4_port = bib_allocate_local4_port(sport, protocol); // FIXME: Should be different than sport


	transport_addr = get_tcp_transport_addr();

	if (transport_addr == NULL) {
		printk("pool out of ipv4 address\n");
		local4_port = -1;
		local4_addr = -1;
	} else {
		INIT_LIST_HEAD(&transport_addr->list);
		local4_port = ntohs(transport_addr->port);
		in4_pton(transport_addr->address, -1, (u8 *) &local4_addr, '\x0', NULL);
		pr_debug("NAT: IPv4 Pool: using address %s and port %u.\n",
		        transport_addr->address, transport_addr->port);
	}

	if (local4_port < 0) {
		pr_debug(
		        "NAT64: [bib] Unable to allocate new local IPv4 port. Dropping connection.");
		return NULL;
	}
	pr_debug("NAT64: [bib2] destination PORT %hu .\n", ntohs(dport));

	bib
	        = nat64_bib_create_tcp(saddr, sport, local4_addr, local4_port,
	                protocol);
	if (!bib)
		return NULL;

	hlist_add_head(&bib->byremote, &hash6[nat64_hash6(*saddr, sport)]);
	hlist_add_head(&bib->bylocal, &hash4[local4_port]);

	session = nat64_session_create_tcp(bib, in6_daddr, daddr, dport, type);
	if (!session) {
		kmem_cache_free(bib_cacheTCP, bib);
		return NULL;
	}

	return bib;
}

/*
 * Julius Kriukas's code. Allocates the hash6 and hash4 global variables.
 */
int nat64_allocate_hash(unsigned int size)
{
	int i;

	size = roundup(size, PAGE_SIZE / sizeof(struct hlist_head));
	hash_size = size;

	hash4 = (void *) __get_free_pages(GFP_KERNEL | __GFP_NOWARN, get_order(
	        sizeof(struct hlist_head) * size));

	if (!hash4) {
		pr_warning("NAT64: Unable to allocate memory for hash4 via GFP.");
		return -1;
	}

	hash6 = (void *) __get_free_pages(GFP_KERNEL | __GFP_NOWARN, get_order(
	        sizeof(struct hlist_head) * size));
	if (!hash6) {
		pr_warning("NAT64: Unable to allocate memory for hash6 via gfp X(.");
		free_pages((unsigned long) hash4, get_order(sizeof(struct hlist_head)
		        * hash_size));
		return -1;
	}

	for (i = 0; i < size; i++) {
		INIT_HLIST_HEAD(&hash4[i]);
		INIT_HLIST_HEAD(&hash6[i]);
	}

	for (i = 0; i < NUM_EXPIRY_QUEUES; i++)
		INIT_LIST_HEAD(&expiry_base[i].queue);

	return 0;
}
