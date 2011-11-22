#ifndef _nat64_filtering_n_updating_h
#define _nat64_filtering_n_updating_h

#define UDP_DEFAULT_ 5*60
#define ICMP_DEFAULT_ 1*60
#define BIB_ICMP 3
#define	NUM_EXPIRY_QUEUES 5

enum expiry_type {
	UDP_DEFAULT = 0,
	TCP_TRANS,
	TCP_EST,
	TCP_INCOMING_SYN,
	ICMP_DEFAULT
};

enum state_type {
	CLOSED = 0,
	V6_SYN_RCV,
	V4_SYN_RCV,
	FOUR_MIN,
	ESTABLISHED,
	V6_FIN_RCV,
	V4_FIN_RCV,
	V6_FIN_V4_FIN,
};

struct expiry_q
{
	struct list_head	queue;
	int			timeout;
};

struct nat64_bib_entry
{
	struct hlist_node	byremote;
	struct hlist_node	bylocal;

	int			type;
	struct in6_addr		remote6_addr;
	__be32			local4_addr;

	__be16			remote6_port;
	__be16			local4_port;

	struct list_head	sessions;
};

struct nat64_st_entry
{
	struct list_head	list;
	struct list_head	byexpiry;
	unsigned long		expires;
	int			state;
	__be32			remote4_addr;
	__be16			remote4_port;
};

extern struct expiry_q expiry_base[NUM_EXPIRY_QUEUES];
extern struct kmem_cache *st_cache;
extern struct kmem_cache *bib_cache;
extern struct hlist_head *hash6;
extern struct hlist_head *hash4;
extern __be32 ipv4_addr;

static inline __be16 nat64_hash4(__be32 addr, __be16 port)
{
	return port;
}

static inline __be16 nat64_hash6(struct in6_addr addr6, __be16 port)
{
	__be32 addr4 = addr6.s6_addr32[1] ^ addr6.s6_addr32[2] ^ addr6.s6_addr32[3];
	return (addr4 >> 16) ^ addr4 ^ port;
}

void session_renew(struct nat64_st_entry *session, enum expiry_type type)
{
	list_del(&session->byexpiry);
	session->expires = jiffies + expiry_base[type].timeout*HZ;
	list_add_tail(&session->byexpiry, &expiry_base[type].queue);
	printk("NAT64: [session] Renewing session %pI4:%hu (timeout %u sec).\n", &session->remote4_addr, ntohs(session->remote4_port), expiry_base[type].timeout);
}

int tcp_timeout_fsm(struct nat64_st_entry *session)
{
	if(session->state == ESTABLISHED) {
		session_renew(session, TCP_TRANS);
		session->state = FOUR_MIN;
		return 1;
	}

	return 0;
}

void tcp4_fsm(struct nat64_st_entry *session, struct tcphdr *tcph)
{
//	printk("nat64: [fsm4] Got packet state %d.\n", session->state);

	switch(session->state) {
	case CLOSED:
		break;
	case V6_SYN_RCV:
		if(tcph->syn) {
			session_renew(session, TCP_EST);
			session->state = ESTABLISHED;
		}
		break;
	case V4_SYN_RCV:
		//if(tcph->syn)
		//	session_renew(session, TCP_TRANS);
		break;
	case FOUR_MIN:
		if(!tcph->rst) {
			session_renew(session, TCP_EST);
			session->state = ESTABLISHED;
		}
		break;
	case ESTABLISHED:
		if(tcph->fin) {
			//session_renew(session, TCP_EST);
			session->state = V4_FIN_RCV;
		} else if(tcph->rst) {
			session_renew(session, TCP_TRANS);
			session->state = FOUR_MIN;
		} else {
			session_renew(session, TCP_EST);
		}
		break;
	case V6_FIN_RCV:
		if(tcph->fin) {
			session_renew(session, TCP_TRANS);
			session->state = V6_FIN_V4_FIN;
		} else {
			session_renew(session, TCP_EST);
		}
		break;
	case V4_FIN_RCV:
		session_renew(session, TCP_EST);
		break;
	case V6_FIN_V4_FIN:
		break;
	}
}

void tcp6_fsm(struct nat64_st_entry *session, struct tcphdr *tcph)
{
//	printk("nat64: [fsm6] Got packet state %d.\n", session->state);

	switch(session->state) {
	case CLOSED:
		if(tcph->syn) {
			session_renew(session, TCP_TRANS);
			session->state = V6_SYN_RCV;
		}
		break;
	case V6_SYN_RCV:
		if(tcph->syn)
			session_renew(session, TCP_TRANS);
		break;
	case V4_SYN_RCV:
		if(tcph->syn) {
			session_renew(session, TCP_EST);
			session->state = ESTABLISHED;
		}
		break;
	case FOUR_MIN:
		if(!tcph->rst) {
			session_renew(session, TCP_EST);
			session->state = ESTABLISHED;
		}
		break;
	case ESTABLISHED:
		if(tcph->fin) {
			//session_renew(session, TCP_EST);
			session->state = V6_FIN_RCV;
		} else if(tcph->rst) {
			session_renew(session, TCP_TRANS);
			session->state = FOUR_MIN;
		} else {
			session_renew(session, TCP_EST);
		}
		break;
	case V6_FIN_RCV:
		session_renew(session, TCP_EST);
		break;
	case V4_FIN_RCV:
		if(tcph->fin) {
			session_renew(session, TCP_TRANS);
			session->state = V6_FIN_V4_FIN;
		} else {
			session_renew(session, TCP_EST);
		}
		break;
	case V6_FIN_V4_FIN:
		break;
	}
}

static void clean_expired_sessions(struct list_head *queue)
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
		if(time_after(jiffies, session->expires)) {
			if(tcp_timeout_fsm(session))
				continue;
			printk("NAT64: [garbage-collector] removing session %pI4:%hu\n", &session->remote4_addr, ntohs(session->remote4_port));
			list_del(pos);
			next_session = session->list.next;
			list_del(&session->list);
			if(list_empty(next_session)) {
				bib = list_entry(next_session, struct nat64_bib_entry, sessions);
				printk("NAT64: [garbage-collector] removing bib %pI6c,%hu <--> %pI4:%hu\n", &bib->remote6_addr, ntohs(bib->remote6_port), &bib->local4_addr, ntohs(bib->local4_port));
				hlist_del(&bib->byremote);
				hlist_del(&bib->bylocal);
				kmem_cache_free(bib_cache, bib);
			}
			kmem_cache_free(st_cache, session);
		}
		else
			break;
	}
}

struct nat64_st_entry *session_ipv4_lookup(struct nat64_bib_entry *bib, __be32 remote4_addr, __be16 remote4_port)
{
	struct nat64_st_entry	*session;
	struct list_head	*pos;

	list_for_each(pos, &bib->sessions) {
		session = list_entry(pos, struct nat64_st_entry, list);
		if(session->remote4_addr == remote4_addr && session->remote4_port == remote4_port)
			return session;
	}

	return NULL;
}

struct nat64_st_entry *session_create(struct nat64_bib_entry *bib, __be32 addr, __be16 port, enum expiry_type type)
{
	struct nat64_st_entry *s;

	s = kmem_cache_zalloc(st_cache, GFP_ATOMIC);
	if(!s) {
		printk("NAT64: [session] Unable to allocate memory for new session entry.\n");
		return NULL;
	}
	s->state = CLOSED;
	s->remote4_addr = addr;
	s->remote4_port = port;
	list_add(&s->list, &bib->sessions);

	s->expires = jiffies + expiry_base[type].timeout*HZ;
	list_add_tail(&s->byexpiry, &expiry_base[type].queue);

	printk("NAT64: [session] New session %pI4:%hu (timeout %u sec).\n", &s->remote4_addr, ntohs(s->remote4_port), expiry_base[type].timeout);
	
	return s;	
}

struct nat64_bib_entry *bib_ipv6_lookup(struct in6_addr *remote_addr, __be16 remote_port, int type)
{
	struct hlist_node	*pos;
	struct nat64_bib_entry	*bib;
	__be16 			h = nat64_hash6(*remote_addr, remote_port);
	struct hlist_head	*hlist = &hash6[h];

	hlist_for_each(pos, hlist) {
		bib = hlist_entry(pos, struct nat64_bib_entry, byremote);
		if(bib->type == type && bib->remote6_port == remote_port && memcmp(&bib->remote6_addr, remote_addr, sizeof(*remote_addr)) == 0)
			return bib;
	}

	//return (pos ? bib : NULL);
	return NULL;
}

static inline int bib_allocate_local4_port(__be16 port, int type)
{

	struct hlist_node *node;
	struct nat64_bib_entry *entry;
	int min, max, i;
	int flag = 0;
	port = ntohs(port);
	min = port < 1024 ? 0 : 1024;
	max = port < 1024 ? 1023 : 65535;

	for (i = port; i <= max; i += 2, flag = 0) {
		hlist_for_each(node, &hash4[htons(i)]) {
			entry = hlist_entry(node, struct nat64_bib_entry, bylocal);
			if(entry->type == type) {
				flag = 1;
				break;
			}
		}
		if(!flag)
			return htons(i);
	}

	flag = 0;
	for (i = port - 2; i >= min; i -=2, flag = 0) {
		hlist_for_each(node, &hash4[htons(i)]) {
			entry = hlist_entry(node, struct nat64_bib_entry, bylocal);
			if(entry->type == type) {
				flag = 1;
				break;
			}
		}
		if(!flag)
			return htons(i);
	}

	return -1;
}

struct nat64_bib_entry *bib_create(struct in6_addr *remote6_addr, __be16 remote6_port,
			     __be32 local4_addr, __be16 local4_port, int type)
{
	struct nat64_bib_entry *bib;

	bib = kmem_cache_zalloc(bib_cache, GFP_ATOMIC);
	if (!bib) {
		printk("NAT64: [bib] Unable to allocate memory for new bib entry X(.\n");
		return NULL;
	}

	bib->type = type;
	memcpy(&bib->remote6_addr, remote6_addr, sizeof(struct in6_addr));
	bib->local4_addr = local4_addr;
	bib->remote6_port = remote6_port;
	bib->local4_port = local4_port;
	INIT_LIST_HEAD(&bib->sessions);
	printk("NAT64: [bib] New bib %pI6c,%hu <--> %pI4:%hu.\n", remote6_addr, ntohs(remote6_port), &local4_addr, ntohs(local4_port));

	return bib;
}

struct nat64_bib_entry *bib_session_create(struct in6_addr *saddr, __be32 daddr, __be16 sport, __be16 dport, int protocol, enum expiry_type type)
{
	struct nat64_bib_entry *bib;
	struct nat64_st_entry *session;
	int local4_port;

	local4_port = bib_allocate_local4_port(sport, protocol);
	if (local4_port < 0) {
		printk("NAT64: [bib] Unable to allocate new local IPv4 port. Dropping connection.\n");
		return NULL;
	}

	bib = bib_create(saddr, sport, ipv4_addr, local4_port, protocol);
	if (!bib)
		return NULL;

	hlist_add_head(&bib->byremote, &hash6[nat64_hash6(*saddr, sport)]);
	hlist_add_head(&bib->bylocal, &hash4[local4_port]);
	
	session = session_create(bib, daddr, dport, type);
	if(!session) {
		kmem_cache_free(bib_cache, bib);
		return NULL;
	}

	return bib;
}

#endif
