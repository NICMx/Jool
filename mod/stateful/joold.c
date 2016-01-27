#include "nat64/mod/stateful/joold.h"

#include <linux/netlink.h>
#include <linux/version.h>
#include <net/genetlink.h>
#include <linux/list.h>
#include <linux/spinlock_types.h>
#include <linux/time.h>
#include <linux/jiffies.h>
#include "nat64/common/genetlink.h"
#include "nat64/common/config.h"
#include "nat64/common/session.h"
#include "nat64/common/joold/joold_config.h"
#include "nat64/mod/common/types.h"
#include "nat64/mod/common/config.h"
#include "nat64/mod/stateful/session/entry.h"
#include "nat64/mod/stateful/session/db.h"
#include "nat64/mod/stateful/bib/db.h"
#include "nat64/mod/common/nl/nl_core2.h"

static DEFINE_SPINLOCK(lock_send);
static DEFINE_SPINLOCK(lock_receive);

static bool enabled = false;

/** Sessions so far listed to be sent to the daemon. */
static struct list_head session_elements;
/** Length of the @sessions list. */
static unsigned int session_list_elem_num;

/**
 * If @session_num exceeds this number, @sessions will be flushed to userspace
 * immediately.
 */
static unsigned int session_limit;
/**
 * This will continuously flush listed sessions to userspace every now and then.
 */
static struct timer_list updater_timer;
/** @updater_timer will flush sessions every @timer_period jiffies. */
static unsigned long timer_period;

/**
 * Only sessions older than this will be sent to userspace.
 *
 * "In order to limit the amount of state replication traffic, another idea
 * could be to only synchronize long-lived sessions (as it's usually not a
 * problem if short-lived HTTP requests and such get interrupted half-way
 * through)."
 * https://github.com/NICMx/Jool/issues/113#issuecomment-64077194
 */
static unsigned long tcp_sync_threshold;
static unsigned long udp_sync_threshold;
static unsigned long icmp_sync_threshold;

/** Group of nodes that want to listen to our sessions. */
struct genl_multicast_group mc_group;

/*
 * TODO I don't think this should be called "session_element".
 * It doesn't tell the difference between a "session entry" and a
 * "session element".
 */
struct session_element {
	struct ipv6_transport_addr remote6;
	struct ipv6_transport_addr local6;
	struct ipv4_transport_addr local4;
	struct ipv4_transport_addr remote4;
	__be64 update_time;
	__be64 creation_time;
	__u8 l4_proto;
	__u8 state;
};

struct joold_entry {
	struct session_element element;
	struct list_head nextprev;
};

static int send_msg(void *payload, size_t payload_len)
{
	int error = 0;
	struct nl_core_buffer *buffer;
	log_debug("Sending multicast message!");

	error = nl_core_new_core_buffer(&buffer, payload_len);
	if (error) {
		log_err("Couldn't initialize buffer!");
		return error;
	}

	error = nl_core_write_to_buffer(buffer, payload, payload_len);
	if (error) {
		log_err("Couldn't write data to buffer!");
		return error;
	}

	error = nl_core_send_multicast_message(buffer);
	if (error) {
		log_err("Couldn't send multicast msg!");
		return error;
	}

	log_debug("Multicast message sent!");
	return 0;
}

static int joold_send_to_userspace(struct list_head *list, int elem_num)
{
	struct request_hdr *hdr;
	struct joold_entry * entry;
	size_t total_size;
	size_t payload_size;
	void *payload;

	payload_size = sizeof(struct session_element) * elem_num;
	total_size = sizeof(struct request_hdr) + payload_size;

	hdr = kmalloc(total_size, GFP_ATOMIC);
	if (!hdr) {
		log_debug("Couldn't allocate memory for entries payload!");
		return -ENOMEM;
	}
	payload = hdr + 1;
	init_request_hdr(hdr, payload_size, MODE_JOOLD, 0);

	while (!list_empty(list)) {
		entry = list_first_entry(list, struct joold_entry, nextprev);

		memcpy(payload, &entry->element, sizeof(entry->element));

		list_del(&entry->nextprev);
		kfree(entry);

		payload += sizeof(struct session_element);
	}

	/*
	 * TODO Here's the deal:
	 *
	 * The list is being copied into buffer 1.
	 * Buffer 1 is then copied into buffer 2.
	 * Buffer 2 is then copied into buffer 3 (the skb).
	 * Then the code sends the skb.
	 *
	 * Especially since this can happen during packet translations, the
	 * kernel really doesn't have time to be allocating and doing all this.
	 * Refactor into dumping the list directly into the skb.
	 */
	/* TODO ignoring return value. */
	send_msg(hdr, total_size);

	return 0;
}

static void copy_elements(struct list_head *list_copy, int *out_element_num)
{
	struct joold_entry *entry;
	(*out_element_num) = 0;

	while (!list_empty(&session_elements)) {
		entry = list_first_entry(&session_elements, struct joold_entry, nextprev);
		list_del(&entry->nextprev);
		list_add(&entry->nextprev, list_copy);
		(*out_element_num)++;
	}

	session_list_elem_num = 0;
}

static void send_to_userspace_wrapper(void)
{
	struct list_head list;
	int element_num = 0;

	INIT_LIST_HEAD(&list);

	spin_lock_bh(&lock_send);
	/* TODO a list_splice_init() probably suffices. */
	copy_elements(&list, &element_num);
	spin_unlock_bh(&lock_send);

	if (element_num > 0)
		joold_send_to_userspace(&list, element_num);
}

static void send_to_userspace_timeout(unsigned long parameter)
{
	send_to_userspace_wrapper();

	if (enabled)
		mod_timer(&updater_timer, jiffies + msecs_to_jiffies(timer_period));
}

int joold_init(void)
{
	enabled = 0;

	INIT_LIST_HEAD(&session_elements);

	setup_timer(&updater_timer, send_to_userspace_timeout, 0);

	return 0;
}

/*
 * TODO needs more config?
 */
void joold_update_config(unsigned long period)
{
	spin_lock_bh(&lock_send);

	/*
	 * TODO perhaps the conversion should be the config module's
	 * responsibility.
	 */
	timer_period = msecs_to_jiffies(period);
	if (enabled)
		mod_timer(&updater_timer, jiffies + timer_period);

	spin_unlock_bh(&lock_send);
}

void joold_start(void)
{
	spin_lock_bh(&lock_send);
	enabled = 1;
	spin_unlock_bh(&lock_send);
}

void joold_stop(void)
{
	spin_lock_bh(&lock_send);
	enabled = 0;
	spin_unlock_bh(&lock_send);
}

void joold_destroy(void)
{
	if (enabled)
		del_timer_sync(&updater_timer);
}

int joold_add_session_element(struct session_entry *entry)
{
	unsigned long threshold = 0;
	struct joold_entry *entry_copy;
	__u64 update_time;
	__u64 creation_time;
	bool flush;

	if (!enabled)
		return 0;

	switch (entry->l4_proto) {
	case L4PROTO_TCP:
		threshold = tcp_sync_threshold;
		break;
	case L4PROTO_UDP:
		threshold = udp_sync_threshold;
		break;
	case L4PROTO_ICMP:
		threshold = icmp_sync_threshold;
		break;
	case L4PROTO_OTHER: /* Welp */
		WARN(true, "Unknown protocol in session: %d", entry->l4_proto);
		return -EINVAL;
	}

	if (jiffies - entry->creation_time < threshold)
		return 0;

	/* TODO this is begging for a cache. */
	entry_copy = kmalloc(sizeof(*entry_copy), GFP_ATOMIC);
	if (!entry_copy) {
		log_err("Couldn't allocate memory for session element.");
		return -ENOMEM;
	}

	entry_copy->element.l4_proto = entry->l4_proto;
	entry_copy->element.local4 = entry->local4;
	entry_copy->element.local6 = entry->local6;
	entry_copy->element.remote4 = entry->remote4;
	entry_copy->element.remote6 = entry->remote6;
	entry_copy->element.state = entry->state;

	update_time = jiffies_to_msecs(jiffies - entry->update_time);
	entry_copy->element.update_time = cpu_to_be64(update_time);
	creation_time = jiffies_to_msecs(jiffies - entry->creation_time);
	entry_copy->element.creation_time = cpu_to_be64(creation_time);

	spin_lock_bh(&lock_send);

	list_add(&entry_copy->nextprev, &session_elements);
	session_list_elem_num++;
	flush = session_limit <= session_list_elem_num;

	spin_unlock_bh(&lock_send);

	if (flush)
		send_to_userspace_wrapper();

	return 0;
}

/*
 * Notes:
 * - pool4 and static BIB entries have to be synchronized manually.
 * - Apparently, users do not actually need to keep clocks in sync.
 */

static int add_new_bib(struct bib *db, struct session_element *new,
		struct bib_entry **result)
{
	struct bib_entry *bib;
	int error;

	do {
		error = bibdb_find6(db, &new->remote6, new->l4_proto, &bib);
		if (!error) {
			if (ipv4_transport_addr_equals(&new->local4, &bib->ipv4))
				goto success; /* Rare happy path. */

			/*
			 * Well, shit.
			 * Two packets of the same connection were routed via
			 * different NAT64s and they chose different masks
			 * before synchronization.
			 * The game is lost.
			 */
			bibentry_put(bib);
			/* TODO increase a stat counter and report to the user. */
			return -EINVAL; /* Rare unhappy path. */

		} else if (error != -ESRCH) {
			log_err("bibdb_find() threw errcode %d.", error);
			return error; /* Very rare or impossible. */
		}

		/* error == -ESRCH. */

		bib = bibentry_create(&new->local4, &new->remote6, false,
				new->l4_proto);
		if (!bib) {
			log_err("Couldn't allocate bib entry!");
			return -ENOMEM;
		}

		error = bibdb_add(db, bib);
		if (!error)
			goto success; /* Normal happy path. */

		bibentry_put(bib);

		if (error != -EEXIST)
			return error;
		/* error == -EEXIST. */

		/*
		 * TODO instead of trying again, bibdb_add() should return the
		 * already existing entry, FFS.
		 * We're tree-iterating too much.
		 */
	} while (true);

success:
	*result = bib;
	return 0;
}

/**
 * FIXME
 * I feel I'm tweaking too much for a merge, so I'll defer what's missing to the
 * next commit.
 * This code is somewht slow and racy. This needs to be done:
 * sessiondb_add() and bibdb_add() need to receive a callback for stuff to do
 * to the bib/session pre-spinlock-release in case the caller is trying to add
 * something but the entry already exists in the database.
 */
static int add_new_session(struct xlator *jool, struct session_element *element,
		struct tuple *tuple, bool is_established)
{
	int error;
	struct bib_entry *bib;
	struct session_entry *session;

	log_debug("creating session!");

	error = add_new_bib(jool->nat64.bib, element, &bib);
	if (error)
		return error;

	session = session_create(&element->remote6, &element->local6,
			&element->local4, &element->remote4,
			element->l4_proto, bib);
	if (!session) {
		bibentry_put(bib);
		return -ENOMEM;
	}

	error = sessiondb_add(jool->nat64.session, session, is_established, true);
	if (error) {
		log_err("couldn't add session entry to the database!");
		session_return(session);
		return error;
	}

	return 0;
}


//static struct session_entry *initialize_session_entry(
//		struct session_element *element)
//{
//	struct session_entry *new;
//	__u8 state;
//	__u64 update_time;
//	__u64 creation_time;
//
//	new = session_create(&element->remote6, &element->local6,
//			&element->local4, &element->remote4,
//			element->l4_proto, NULL);
//	if (!new)
//		return NULL;
//
//	update_time = be64_to_cpu(element->update_time);
//	update_time = jiffies - msecs_to_jiffies(update_time);
//	creation_time = be64_to_cpu(element->creation_time);
//	creation_time = jiffies - msecs_to_jiffies(creation_time);
//
//	new->state = element->state;
//	new->update_time = update_time;
//	new->creation_time = creation_time;
//
//	return new;
//}


static unsigned long element_to_session_time(struct session_element *element)
{
	return jiffies - msecs_to_jiffies(be64_to_cpu(element->update_time));
}


static int update_session(struct xlator *jool, struct session_element *new,
		int num_elements)
{
	struct session_entry *old;
	struct tuple tuple;
	bool is_established;

	int error;
	int i;

	for (i = 0; i < num_elements; i++, new++) {
		if (new->l4_proto == L4PROTO_TCP) {
			is_established = new->state == ESTABLISHED;
		} else {
			is_established = true;
		}

		tuple.dst.addr6 = new->local6;
		tuple.src.addr6 = new->remote6;
		tuple.l4_proto = new->l4_proto;
		tuple.l3_proto = L3PROTO_IPV6;

		error = sessiondb_find(jool->nat64.session, &tuple, 0, 0, &old);
		switch (error) {
		case 0: /* Found. */
			old->update_time = element_to_session_time(new);
			old->state = new->state;

			/* TODO what's protecting this from simultaneous session edits? */
			if (sessiondb_set_session_timer(jool->nat64.session, old, is_established))
				log_err("Could not set session's timer!");

			session_return(old);
			break;

		case -ESRCH: /* Not found. */
			add_new_session(jool, new, &tuple, is_established);
			break;

		default: /* Unknown errors. */
			log_err("unexpected error!");
		}
	}

	return 0;
}

int joold_sync_entries(struct xlator *jool, void *data, __u32 data_len)
{
	int num_elements;

	if (!enabled)
		return 0;

	if (data_len == 0 || data_len % sizeof(struct session_element) != 0) {
		log_err("Inconsistent data detected while synchronizing SESSION.");
		return -EINVAL;
	}

	num_elements = data_len / sizeof(struct session_element);

	/*
	 * TODO is this really BH context?
	 * TODO This spinlock is actually redundant, likely.
	 * (You still need to worry about BH context because the BIB and session
	 * locks currently assume it.)
	 */
	spin_lock_bh(&lock_receive);
	update_session(jool, data, num_elements);
	spin_unlock_bh(&lock_receive);

	return 0;
}

