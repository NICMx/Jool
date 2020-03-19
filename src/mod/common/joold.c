#include "mod/common/joold.h"

#include <linux/inet.h>
#include <net/genetlink.h>

#include "common/constants.h"
#include "mod/common/log.h"
#include "mod/common/wkmalloc.h"
#include "mod/common/xlator.h"
#include "mod/common/nl/attribute.h"
#include "mod/common/nl/nl_core.h"
#include "mod/common/nl/nl_handler.h"
#include "mod/common/db/bib/db.h"

#define GLOBALS(xlator) (xlator->globals.nat64.joold)

/*
 * Remember to include in the user documentation:
 *
 * - pool4 and static BIB entries have to be synchronized manually.
 * - Apparently, users do not actually need to keep clocks in sync.
 */

struct joold_queue {
	/* The packet we're accumulating the sessions in. */
	struct sk_buff *skb;
	void *msg_head;
	struct nlattr *root;
	bool skb_full;

	/** Additional sessions we've queued but don't fit in @skb yet. */
	struct list_head sessions;
	/** Number of nodes in @sessions. */
	unsigned int count;
	/** Number of advertisement nodes in @sessions. */
	unsigned int advertisement_count;

	/**
	 * Can we send a packet?
	 * We need to wait for ACKs because the kernel can't handle too many
	 * Netlink messages at once.
	 */
	bool ack_received;
	/**
	 * Jiffy at which the last batch of sessions was sent.
	 * If the ACK was lost for some reason, this should get us back on
	 * track.
	 */
	unsigned long last_flush_time;

	/** Namespace where the sessions will be multicasted. */
	struct net *ns;

	spinlock_t lock;
	struct kref refs;
};

/**
 * A session or group of sessions that need to be transmitted to other Jool
 * instances in the near future.
 */
struct joold_node {
	/**
	 * true - @group below is valid.
	 * false - @single below is valid.
	 */
	bool is_group;
	union {
		/**
		 * If @single is valid, this node represents a lone session.
		 * These are added whenever a translating packet updates a
		 * session.
		 */
		struct session_entry single;
		/**
		 * If @group is valid, the user issued an --advertise.
		 * The whole database needs to be transmitted.
		 * Unfortunately, a typical table won't fit in a single
		 * packet so this node might stick for several iterations and
		 * keep track of what is yet to be sent.
		 */
		struct {
			/** IPv4 ID of the session sent in the last packet. */
			struct taddr4_tuple offset;
			/**
			 * true - @offset above is valid.
			 * false - @no sessions from this node have been sent.
			 */
			bool offset_set;
			/** Protocol table this group belongs to. */
			l4_protocol proto;
		} group;
	};

	/** List hook to joold_queue.sessions.  */
	struct list_head nextprev;
};

struct write_status {
	bool is_full;
	unsigned int entries_written;
};

struct joold_advertise_struct {
	struct sk_buff *skb;
	struct joold_node *node;
	struct write_status *status;
};

static struct kmem_cache *node_cache;

static int joold_setup(void)
{
	node_cache = kmem_cache_create("jool_joold_nodes",
			sizeof(struct joold_node), 0, 0, NULL);
	return node_cache ? 0 : -EINVAL;
}

void joold_teardown(void)
{
	if (node_cache) {
		kmem_cache_destroy(node_cache);
		node_cache = NULL;
	}
}

int allocate_joold_skb(struct xlator *jool)
{
	struct joold_queue *queue = jool->nat64.joold;

	queue->skb = genlmsg_new(GLOBALS(jool).max_payload, GFP_ATOMIC);
	if (!queue->skb)
		return -ENOMEM;

	queue->msg_head = genlmsg_put(queue->skb, 0, 0, jnl_family(), 0, 0);
	if (!queue->msg_head) {
		pr_err("genlmsg_put() returned NULL.\n");
		goto kill_packet;
	}

	queue->root = nla_nest_start(queue->skb, JNLAR_SESSION_ENTRIES);
	if (!queue->root) {
		pr_err("Joold packets cannot contain any sessions.\n");
		queue->msg_head = NULL;
		goto kill_packet;
	}

	return 0;

kill_packet:
	kfree_skb(queue->skb);
	queue->skb = NULL;
	return -ENOMEM;
}

static bool should_send(struct xlator *jool)
{
	struct joold_queue *queue;
	unsigned long deadline;

	queue = jool->nat64.joold;
	if (!queue->skb)
		return false;

	deadline = msecs_to_jiffies(GLOBALS(jool).flush_deadline);
	if (time_before(queue->last_flush_time + deadline, jiffies))
		return true;

	if (!queue->ack_received)
		return false;

	if (GLOBALS(jool).flush_asap)
		return true;

	if (queue->advertisement_count > 0)
		return true;

	return queue->skb_full;
}

/**
 * Assumes the lock is held.
 * If this returns a packet, you have to send it via send_to_userspace() after
 * releasing the spinlock.
 */
static struct sk_buff *send_to_userspace_prepare(struct xlator *jool)
{
	struct joold_queue *queue;
	struct sk_buff *skb;

	if (!should_send(jool))
		return NULL;

	queue = jool->nat64.joold;

	skb = queue->skb;
	nla_nest_end(skb, queue->root);
	genlmsg_end(skb, queue->msg_head);

	/*
	 * BTW: This sucks.
	 * We're assuming that the nlcore_send_multicast_message() during
	 * send_to_userspace() is going to succeed.
	 * But the alternative is to do the nlcore_send_multicast_message()
	 * with the lock held, and I don't have the stomach for that.
	 */
	queue->skb = NULL;
	queue->msg_head = NULL;
	queue->root = NULL;
	queue->ack_received = false;
	queue->last_flush_time = jiffies;
	return skb;
}

static void send_to_userspace(struct sk_buff *skb, struct net *ns)
{
	int error;

	if (!skb)
		return;

	log_debug("Sending multicast message.");
#if LINUX_VERSION_LOWER_THAN(3, 13, 0, 7, 1)
	error = genlmsg_multicast_netns(ns, skb, 0, jnl_gid(), GFP_ATOMIC);
#else
	/*
	 * Note: Starting from kernel 3.13, all groups of a common family share
	 * a group offset (from a common pool), and they are numbered
	 * monotonically from there. That means if all we have is one group,
	 * its id will always be zero.
	 *
	 * That's the reason why so many callers of this function stopped
	 * providing a group when the API started forcing them to provide a
	 * family.
	 */
	error = genlmsg_multicast_netns(jnl_family(), ns, skb, 0, 0, GFP_ATOMIC);
#endif
	if (error) {
		log_warn_once("Looks like nobody received my multicast message. Is the joold daemon really active? (errcode %d)",
				error);
	} else {
		log_debug("Multicast message sent.");
	}
}

/**
 * joold_create - Constructor for joold_queue structs.
 */
struct joold_queue *joold_alloc(struct net *ns)
{
	struct joold_queue *queue;
	bool cache_created;

	cache_created = false;
	if (!node_cache) {
		if (joold_setup())
			return NULL;
		cache_created = true;
	}

	queue = wkmalloc(struct joold_queue, GFP_KERNEL);
	if (!queue) {
		if (cache_created)
			joold_teardown();
		return NULL;
	}

	queue->skb = NULL;
	queue->msg_head = NULL;
	queue->root = NULL;
	queue->skb_full = false;
	INIT_LIST_HEAD(&queue->sessions);
	queue->count = 0;
	queue->advertisement_count = 0;
	queue->ack_received = true;
	queue->last_flush_time = jiffies;
	queue->ns = ns;

	spin_lock_init(&queue->lock);
	kref_init(&queue->refs);

	return queue;
}

void joold_get(struct joold_queue *queue)
{
	kref_get(&queue->refs);
}

static void purge_sessions(struct joold_queue *queue)
{
	struct joold_node *node;

	while (!list_empty(&queue->sessions)) {
		node = list_first_entry(&queue->sessions, struct joold_node,
				nextprev);
		list_del(&node->nextprev);
		wkmem_cache_free("joold node", node_cache, node);
	}

	queue->count = 0;
	queue->advertisement_count = 0;
	queue->ack_received = true;
	queue->last_flush_time = jiffies;
}

static void joold_release(struct kref *refs)
{
	struct joold_queue *queue;
	queue = container_of(refs, struct joold_queue, refs);

	purge_sessions(queue);
	wkfree(struct joold_queue, queue);
}

void joold_put(struct joold_queue *queue)
{
	kref_put(&queue->refs, joold_release);
}

/**
 * joold_add - Add the @entry session to @queue.
 *
 * This is the function that gets called whenever a packet translation
 * successfully triggers the creation of a session entry. @entry will be sent
 * to the joold daemon.
 */
void joold_add(struct xlator *jool, struct session_entry *entry)
{
	struct joold_queue *queue;
	struct joold_node *copy;
	struct sk_buff *skb;

	if (!GLOBALS(jool).enabled)
		return;

	queue = jool->nat64.joold;

	spin_lock_bh(&queue->lock);

	if (!queue->skb && allocate_joold_skb(jool)) {
		spin_lock_bh(&queue->lock);
		return;
	}

	queue->skb_full = jnla_put_session(queue->skb, JNLAL_ENTRY, entry);
	if (queue->skb_full) {
		copy = wkmem_cache_alloc("joold node", node_cache, GFP_ATOMIC);
		if (copy) {
			copy->is_group = false;
			copy->single = *entry;
			list_add_tail(&copy->nextprev, &queue->sessions);
			queue->count++;
		} /* Else discard it; can't do anything. */
	}

	skb = send_to_userspace_prepare(jool);

	spin_unlock_bh(&queue->lock);

	send_to_userspace(skb, jool->ns);
}

struct add_params {
	struct session_entry new;
	bool success;
};

static enum session_fate collision_cb(struct session_entry *old, void *arg)
{
	struct add_params *params = arg;
	struct session_entry *new = &params->new;

	if (session_equals(old, new)) { /* It's the same session; update it. */
		old->state = new->state;
		old->timer_type = new->timer_type;
		old->update_time = new->update_time;
		params->success = true;
		return FATE_TIMER_SLOW;
	}

	log_err("We're out of sync: Incoming %s session entry %pI6c#%u|%pI6c#%u|%pI4#%u|%pI4#%u collides with DB entry %pI6c#%u|%pI6c#%u|%pI4#%u|%pI4#%u.",
			l4proto_to_string(new->proto),
			&new->src6.l3, new->src6.l4,
			&new->dst6.l3, new->dst6.l4,
			&new->src4.l3, new->src4.l4,
			&new->dst4.l3, new->dst4.l4,
			&old->src6.l3, old->src6.l4,
			&old->dst6.l3, old->dst6.l4,
			&old->src4.l3, old->src4.l4,
			&old->dst4.l3, old->dst4.l4);
	params->success = false;
	return FATE_PRESERVE;
}

static bool add_new_session(struct xlator *jool, struct nlattr *attr)
{
	struct add_params params;
	struct collision_cb cb;
	int error;

	log_debug("Adding session!");

	error = jnla_get_session(attr, "Joold session",
			&jool->globals.nat64.bib, &params.new);
	if (error)
		return false;

	params.success = true;
	cb.cb = collision_cb;
	cb.arg = &params;

	error = bib_add_session(jool, &params.new, &cb);
	if (error == -EEXIST)
		return params.success;
	if (error) {
		log_err("sessiondb_add() threw unknown error code %d.", error);
		return false;
	}

	return true;
}

static int validate_enabled(struct xlator *jool)
{
	if (!GLOBALS(jool).enabled) {
		log_err("Session sync is disabled on this instance.");
		return -EINVAL;
	}

	return 0;
}

/**
 * joold_sync - Parses a bunch of sessions out of @data and adds them to @jool's
 * session database.
 *
 * This is the function that gets called whenever the jool daemon sends data to
 * the @jool Jool instance.
 */
int joold_sync(struct xlator *jool, struct nlattr *root)
{
	struct nlattr *attr;
	int rem;
	int error;
	bool success;

	error = validate_enabled(jool);
	if (error)
		return error;

	success = true;
	nla_for_each_nested(attr, root, rem)
		success &= add_new_session(jool, attr);

	log_debug("Done.");
	return success ? 0 : -EINVAL;
}

static int add_advertise_node(struct joold_queue *queue, l4_protocol proto)
{
	struct joold_node *node;

	node = wkmem_cache_alloc("joold node", node_cache, GFP_ATOMIC);
	if (!node)
		return -ENOMEM;

	node->is_group = true;
	memset(&node->group.offset, 0, sizeof(node->group.offset));
	node->group.offset_set = false;
	node->group.proto = proto;

	list_add_tail(&node->nextprev, &queue->sessions);
	queue->count++;
	queue->advertisement_count++;

	return 0;
}

static int prepare_advertisement(struct joold_queue *queue)
{
	int error;

	error = add_advertise_node(queue, L4PROTO_TCP);
	if (error)
		return error;

	error = add_advertise_node(queue, L4PROTO_UDP);
	if (error)
		return error;

	return add_advertise_node(queue, L4PROTO_ICMP);
}

int joold_advertise(struct xlator *jool)
{
	struct joold_queue *queue;
	struct sk_buff *skb;
	int error;

	error = validate_enabled(jool);
	if (error)
		return error;

	queue = jool->nat64.joold;

	spin_lock_bh(&queue->lock);

	error = prepare_advertisement(queue);
	skb = error ? NULL : send_to_userspace_prepare(jool);

	spin_unlock_bh(&queue->lock);

	send_to_userspace(skb, jool->ns);
	return error;
}

void joold_ack(struct xlator *jool)
{
	struct joold_queue *queue;
	struct sk_buff *skb;

	if (validate_enabled(jool))
		return;

	queue = jool->nat64.joold;

	spin_lock_bh(&queue->lock);

	queue->ack_received = true;
	skb = send_to_userspace_prepare(jool);

	spin_unlock_bh(&queue->lock);

	send_to_userspace(skb, jool->ns);
}

/**
 * Called every now and then to flush the queue in case nodes have been queued,
 * the deadline is in the past and no new packets have triggered a flush.
 * It's just a last-resort attempt to prevent nodes from lingering here for too
 * long that's generally only useful in non-flush-asap mode.
 */
void joold_clean(struct xlator *jool)
{
	spinlock_t *lock;
	struct sk_buff *skb;

	if (!GLOBALS(jool).enabled)
		return;

	lock = &jool->nat64.joold->lock;

	spin_lock_bh(lock);

	skb = send_to_userspace_prepare(jool);

	spin_unlock_bh(lock);

	send_to_userspace(skb, jool->ns);
}
