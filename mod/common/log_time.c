#ifdef BENCHMARK
#include "nat64/mod/common/log_time.h"
#include "nat64/mod/common/wkmalloc.h"

struct log_time_db {
	struct list_head list;
	spinlock_t lock;
};

static struct log_time_db logs_ipv6_tcp;
static struct log_time_db logs_ipv6_udp;
static struct log_time_db logs_ipv6_icmp;
static struct log_time_db logs_ipv4_tcp;
static struct log_time_db logs_ipv4_udp;
static struct log_time_db logs_ipv4_icmp;

/** Cache for struct log_node, for efficient allocation. */
static struct kmem_cache *entry_cache;

#ifndef NSEC_PER_SEC
#define NSEC_PER_SEC 1000000000L
#endif

/**
 * Init the struct of log_node.
 */
static int logtime_create_node(struct log_node **node)
{
	struct log_node *tmp_node;

	tmp_node = wkmem_cache_alloc("logging node", entry_cache, GFP_ATOMIC);
	if (!tmp_node) {
		log_err("Allocation of IPv6 pool node failed.");
		return -ENOMEM;
	}

	INIT_LIST_HEAD(&tmp_node->list_hook);
	*node = tmp_node;
	return 0;
}

/**
 * An spinlock must be hold.
 */
static void logtime_delete_node(struct log_node *node) {
	list_del(&node->list_hook);
	wkmem_cache_free("logging node", entry_cache, node);
}

static void logtime_get_db(struct log_time_db **log_db, l3_protocol l3_proto, l4_protocol l4_proto)
{
	switch (l3_proto) {
	case L3PROTO_IPV6:
		switch (l4_proto) {
		case L4PROTO_TCP:
			*log_db = &logs_ipv6_tcp;
			return;
		case L4PROTO_UDP:
			*log_db = &logs_ipv6_udp;
			return;
		case L4PROTO_ICMP:
			*log_db = &logs_ipv6_icmp;
			return;
		case L4PROTO_OTHER:
			break;
		}
		break;
	case L3PROTO_IPV4:
		switch (l4_proto) {
		case L4PROTO_TCP:
			*log_db = &logs_ipv4_tcp;
			return;
		case L4PROTO_UDP:
			*log_db = &logs_ipv4_udp;
			return;
		case L4PROTO_ICMP:
			*log_db = &logs_ipv4_icmp;
			return;
		case L4PROTO_OTHER:
			break;
		}
		break;
	}
	*log_db = NULL;
}

static void subtract_timespec(struct timespec *start, struct timespec *end,
		struct log_node *node)
{
	if (start->tv_nsec > end->tv_nsec) {
		end->tv_nsec += NSEC_PER_SEC; /* Add one second (in ns 1,000,000,000) to the minuend. */
		start->tv_sec += 1L; /* Add one second to the subtrahend. */
	}
	node->time.tv_sec = end->tv_sec - start->tv_sec;
	node->time.tv_nsec = end->tv_nsec - start->tv_nsec;
	log_debug("Translation time: %ld.%9ld", node->time.tv_sec, node->time.tv_nsec);

}

static void logtime_db_add(struct log_time_db *log_db, struct log_node *node)
{
	spin_lock_bh(&log_db->lock);
	list_add_tail(&node->list_hook, &log_db->list);
	spin_unlock_bh(&log_db->lock);
}

/**
 * Increases the counter of the structure and add to the sum delta time registered.
 */
void logtime(struct packet *pkt)
{
	struct log_time_db *log_db;
	struct log_node *log_node;
	struct timespec end_time;

	getnstimeofday(&end_time);

	logtime_get_db(&log_db, pkt_l3_proto(pkt), pkt_l4_proto(pkt));
	if (!log_db) {
		log_err("Invalid L3 or L4 protocol.");
		return;
	}

	if (logtime_create_node(&log_node))
		return; /* Error message already printed. */

	subtract_timespec(&pkt->start_time, &end_time, log_node);
	logtime_db_add(log_db, log_node);
}

int logtime_iterate_and_delete(l3_protocol l3_proto, l4_protocol l4_proto,
		int (*func)(struct log_node *, void *), void *arg)
{
	struct list_head *current_hook, *next_hook;
	struct log_node *node;
	struct log_time_db *log_db;
	int error;

	logtime_get_db(&log_db, l3_proto, l4_proto);
	if (!log_db) {
		log_err("Invalid L3 or L4 protocol.");
		return -EINVAL;
	}

	spin_lock_bh(&log_db->lock);
	list_for_each_safe(current_hook, next_hook, &log_db->list) {
		node = list_entry(current_hook, struct log_node, list_hook);
		error = func(node, arg);
		if (error) {
			spin_unlock_bh(&log_db->lock);
			return error;
		}
		logtime_delete_node(node);
	}
	spin_unlock_bh(&log_db->lock);

	return 0;
}

int logtime_init(void)
{
	int i;
	struct log_time_db *logs_db[] = { &logs_ipv6_tcp, &logs_ipv6_udp, &logs_ipv6_icmp,
			&logs_ipv4_tcp, &logs_ipv4_udp, &logs_ipv4_icmp	};

	for (i = 0; i < ARRAY_SIZE(logs_db); i++) {
		spin_lock_init(&logs_db[i]->lock);
		INIT_LIST_HEAD(&logs_db[i]->list);
	}

	entry_cache = kmem_cache_create("jool_logtime_nodes", sizeof(struct log_node), 0, 0, NULL);
	if (!entry_cache) {
		log_err("Could not allocate the BIB entry cache.");
		return -ENOMEM;
	}

	return 0;
}

static void destroy_aux(struct log_time_db *db)
{
	struct list_head *current_hook, *next_hook;
	struct log_node *node;

	list_for_each_safe(current_hook, next_hook, &db->list) {
		node = list_entry(current_hook, struct log_node, list_hook);
		logtime_delete_node(node);
	}
}

void logtime_destroy(void)
{
	int i;
	struct log_time_db *logs_db[] = { &logs_ipv6_tcp, &logs_ipv6_udp, &logs_ipv6_icmp,
			&logs_ipv4_tcp, &logs_ipv4_udp, &logs_ipv4_icmp	};

	for (i = 0; i < ARRAY_SIZE(logs_db); i++) {
		destroy_aux(logs_db[i]);
	}

	kmem_cache_destroy(entry_cache);
}

#endif /* BENCHMARK */
