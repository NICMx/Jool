#include "mod/common/joold.h"

#include <linux/inet.h>

#include "common/constants.h"
#include "mod/common/log.h"
#include "mod/common/wkmalloc.h"
#include "mod/common/xlator.h"
#include "mod/common/nl/attribute.h"
#include "mod/common/nl/nl_core.h"
#include "mod/common/nl/nl_handler.h"
#include "mod/common/db/bib/db.h"
#include "mod/common/steps/send_packet.h"

#define GLOBALS(xlator) (xlator->globals.nat64.joold)

/*
 * Remember to include in the user documentation:
 *
 * - pool4 and static BIB entries have to be synchronized manually.
 * - Apparently, users do not actually need to keep clocks in sync.
 */

struct joold_pkt {
	struct sk_buff *skb; /** The packet we'll send to other Jools */
	struct joolnlhdr *jhdr; /** Quick pointer to @skb's Jool header */
	struct nlattr *root; /** Quick pointer to @skb's first attribute */
	bool has_sessions; /* Has at least one session been inserted to @skb? */
	bool full; /** Are we unable to insert more sessions into @skb? */
};

/**
 * Can we send our packet yet?
 * (We need to wait for ACKs because the kernel can't handle too many
 * Netlink messages at once.)
 */
#define JQF_ACK_RECEIVED (1 << 0)
#define JQF_AD_ONGOING (1 << 1) /** Advertisement requested by user? */
#define JQF_OFFSET_SET (1 << 2) /** ad.offset set? */

struct joold_queue {
	unsigned int flags; /* JQF */

	/** The packet we'll send to the other Jools. */
	struct joold_pkt pkt;

	struct {
		/** Additional sessions that don't fit in @pkt yet. */
		struct list_head list;
		/** Number of nodes in @list. */
		unsigned int count;
	} deferred;

	struct {
		/** IPv4 ID of the session sent in the last packet. */
		struct taddr4_tuple offset;
		/** Protocol of the session sent in the last packet. */
		l4_protocol proto;
	} ad; /* Advertisement; only if @flags & JQF_AD_ONGOING. */

	/**
	 * Jiffy at which the last batch of sessions was sent.
	 * If the ACK was lost for some reason, this should get us back on
	 * track.
	 */
	unsigned long last_flush_time;

	/**
	 * Length in bytes of a packeted session. Needed to enforce
	 * ss-max-payload.
	 */
	size_t session_size;

	spinlock_t lock;
	struct kref refs;
};

/**
 * A session or group of sessions that need to be transmitted to other Jool
 * instances in the near future.
 */
struct deferred_session {
	struct session_entry session;
	/** List hook to joold_queue.deferred.  */
	struct list_head lh;
};

static struct kmem_cache *deferred_cache;

#define ALLOC_DEFERRED \
	wkmem_cache_alloc("joold deferred", deferred_cache, GFP_ATOMIC)
#define FREE_DEFERRED(deferred) \
	wkmem_cache_free("joold deferred", deferred_cache, deferred)

static struct deferred_session *first_deferred(struct joold_queue *queue)
{
	return list_first_entry(&queue->deferred.list, struct deferred_session,
			lh);
}

static int joold_setup(void)
{
	deferred_cache = kmem_cache_create("joold_deferred",
			sizeof(struct deferred_session), 0, 0, NULL);
	return deferred_cache ? 0 : -EINVAL;
}

void joold_teardown(void)
{
	if (deferred_cache) {
		kmem_cache_destroy(deferred_cache);
		deferred_cache = NULL;
	}
}

static int joold_pkt_init(struct joold_pkt *pkt, struct xlator *jool)
{
	pkt->skb = genlmsg_new(GLOBALS(jool).max_payload, GFP_ATOMIC);
	if (!pkt->skb)
		return -ENOMEM;

	pkt->jhdr = genlmsg_put(pkt->skb, 0, 0, jnl_family(), 0, 0);
	if (!pkt->jhdr) {
		pr_err("genlmsg_put() returned NULL.\n");
		goto kill_packet;
	}

	memset(pkt->jhdr, 0, sizeof(*pkt->jhdr));
	memmove(pkt->jhdr->magic, JOOLNL_HDR_MAGIC, JOOLNL_HDR_MAGIC_LEN);
	pkt->jhdr->version = cpu_to_be32(xlat_version());
	pkt->jhdr->xt = XT_NAT64;
	memcpy(pkt->jhdr->iname, jool->iname, INAME_MAX_SIZE);

	pkt->root = nla_nest_start(pkt->skb, JNLAR_SESSION_ENTRIES);
	if (!pkt->root) {
		pr_err("Joold packets cannot contain any sessions.\n");
		pkt->jhdr = NULL;
		goto kill_packet;
	}

	pkt->has_sessions = false;
	pkt->full = false;
	return 0;

kill_packet:
	kfree_skb(pkt->skb);
	pkt->skb = NULL;
	return -ENOMEM;
}

/* Returns true if the session was inserted, false if it didn't fit. */
static bool put_session(struct xlator *jool, struct session_entry const *session)
{
	struct joold_queue *queue;
	struct joold_pkt *pkt;
	size_t room;
	size_t len_before_put;
	int error;

	queue = jool->nat64.joold;
	pkt = &queue->pkt;
	room = nlmsg_total_size(genlmsg_total_size(GLOBALS(jool).max_payload));

	/*
	 * Big pain.
	 * The kernel sometimes allocates extra room in the skb tail area.
	 * So we can't trust the nla_put functions to respect max_payload.
	 * So we have to validate it ourselves.
	 */
	if (pkt->skb->len + queue->session_size > room)
		goto full;

	len_before_put = pkt->skb->len;
	error = jnla_put_session(pkt->skb, JNLAL_ENTRY, session);
	if (WARN(error, "Ran out of skb room before the allocated limit"))
		goto full;

	if (queue->session_size) {
		WARN(queue->session_size != pkt->skb->len - len_before_put,
				"session size changed: %zu -> %zu",
				queue->session_size,
				pkt->skb->len - len_before_put);
	} else {
		queue->session_size = pkt->skb->len - len_before_put;
	}

	pkt->has_sessions = true;
	return pkt->full;

full:
	pkt->full = true;
	return true;
}

/* "advertise session," not "add session." Although we're adding it too. */
static int ad_session(struct session_entry const *session, void *arg)
{
	struct xlator *jool;
	struct joold_queue *queue;

	jool = arg;
	if (put_session(jool, session)) {
		queue = jool->nat64.joold;
		queue->flags |= JQF_OFFSET_SET;
		queue->ad.offset.src = session->src4;
		queue->ad.offset.dst = session->dst4;
		return 1;
	}

	return 0;
}

/* "advertise sessions," not "add sessions." Although we're adding them too. */
static void ad_sessions(struct xlator *jool)
{
	struct joold_queue *queue;
	struct session_foreach_offset offset, *offset_ptr;
	int error;

	queue = jool->nat64.joold;
	if (!(queue->flags & JQF_AD_ONGOING))
		return;

	if (queue->flags & JQF_OFFSET_SET) {
		offset.offset = queue->ad.offset;
		offset.include_offset = true;
		offset_ptr = &offset;
	} else {
		offset_ptr = NULL;
	}

	for (; queue->ad.proto <= L4PROTO_ICMP; queue->ad.proto++) {
		error = bib_foreach_session(jool, queue->ad.proto, ad_session,
				jool, offset_ptr);
		if (error > 0)
			return;
		if (error < 0) {
			/* No need to rate-limit; we'll disable the ad. */
			log_warn("joold advertisement interrupted.");
			queue->flags &= ~JQF_AD_ONGOING;
			return;
		}

		queue->flags &= ~JQF_OFFSET_SET;
		offset_ptr = NULL;
	}

	log_info("joold advertisement done.");
	queue->flags &= ~JQF_AD_ONGOING;
}

static void add_deferred(struct xlator *jool)
{
	struct joold_queue *queue;
	struct deferred_session *node;

	queue = jool->nat64.joold;
	while (!list_empty(&queue->deferred.list)) {
		node = first_deferred(queue);
		if (put_session(jool, &node->session))
			return;
		list_del(&node->lh);
		FREE_DEFERRED(node);
		queue->deferred.count--;
	}
}

static void add_session(struct xlator *jool, struct session_entry *session)
{
	struct joold_queue *queue;
	struct deferred_session *node;

	if (put_session(jool, session)) {
		queue = jool->nat64.joold;
		if (queue->deferred.count >= GLOBALS(jool).capacity) {
			log_warn_once("Joold: Too many sessions deferred! I need to drop some; sorry.");
			return;
		}

		node = ALLOC_DEFERRED;
		if (node) {
			node->session = *session;
			list_add_tail(&node->lh, &queue->deferred.list);
			queue->deferred.count++;
		} /* Else discard it; can't do anything. */
	}
}

static bool should_send(struct xlator *jool)
{
	struct joold_queue *queue;
	unsigned long deadline;

	queue = jool->nat64.joold;
	if (!queue->pkt.skb)
		return false;
	if (!queue->pkt.has_sessions)
		return false;

	deadline = msecs_to_jiffies(GLOBALS(jool).flush_deadline);
	if (time_before(queue->last_flush_time + deadline, jiffies))
		return true;

	if (!(queue->flags & JQF_ACK_RECEIVED))
		return false;

	if (queue->flags & JQF_AD_ONGOING)
		return true;

	if (GLOBALS(jool).flush_asap)
		return true;

	return queue->pkt.full;
}

/**
 * Assumes the lock is held.
 * You have to send_to_userspace(@jool, @prepared) after releasing the spinlock.
 */
static void send_to_userspace_prepare(struct xlator *jool,
		struct session_entry *new_session,
		struct joold_pkt *prepared)
{
	struct joold_queue *queue;

	queue = jool->nat64.joold;
	if (!queue->pkt.skb && joold_pkt_init(&queue->pkt, jool)) {
		log_warn_once("joold packet allocation failure. ");
		return;
	}

	ad_sessions(jool);
	add_deferred(jool);
	add_session(jool, new_session);

	if (!should_send(jool)) {
		prepared->skb = NULL;
		return;
	}

	*prepared = queue->pkt;

	/*
	 * BTW: This sucks.
	 * We're assuming that the nlcore_send_multicast_message() during
	 * send_to_userspace() is going to succeed.
	 * But the alternative is to do the nlcore_send_multicast_message()
	 * with the lock held, and I don't have the stomach for that.
	 */
	memset(&queue->pkt, 0, sizeof(queue->pkt));
	queue->flags &= ~JQF_ACK_RECEIVED;
	queue->last_flush_time = jiffies;
}

/*
 * Swallows ownership of @pkt->skb.
 */
static void send_to_userspace(struct xlator *jool, struct joold_pkt *pkt)
{
	if (pkt->skb) {
		nla_nest_end(pkt->skb, pkt->root);
		genlmsg_end(pkt->skb, pkt->jhdr);
		sendpkt_multicast(jool, pkt->skb);
	}
}

/**
 * joold_create - Constructor for joold_queue structs.
 */
struct joold_queue *joold_alloc(void)
{
	struct joold_queue *queue;
	bool cache_created;

	cache_created = false;
	if (!deferred_cache) {
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

	queue->flags = JQF_ACK_RECEIVED;
	memset(&queue->pkt, 0, sizeof(queue->pkt));
	INIT_LIST_HEAD(&queue->deferred.list);
	queue->deferred.count = 0;
	queue->last_flush_time = jiffies;
	queue->session_size = 0;
	spin_lock_init(&queue->lock);
	kref_init(&queue->refs);

	return queue;
}

void joold_get(struct joold_queue *queue)
{
	kref_get(&queue->refs);
}

static void joold_release(struct kref *refs)
{
	struct joold_queue *queue;
	struct deferred_session *deferred;

	queue = container_of(refs, struct joold_queue, refs);

	while (!list_empty(&queue->deferred.list)) {
		deferred = first_deferred(queue);
		list_del(&deferred->lh);
		FREE_DEFERRED(deferred);
	}

	wkfree(struct joold_queue, queue);
}

void joold_put(struct joold_queue *queue)
{
	kref_put(&queue->refs, joold_release);
}

/**
 * joold_add - Add @session to @jool->nat64.joold.
 *
 * This is the function that gets called whenever a packet translation
 * successfully triggers the creation of a session entry. @session will be sent
 * to the joold daemon.
 */
void joold_add(struct xlator *jool, struct session_entry *session)
{
	struct joold_queue *queue;
	struct joold_pkt prepared;

	if (!GLOBALS(jool).enabled)
		return;

	queue = jool->nat64.joold;

	spin_lock_bh(&queue->lock);
	send_to_userspace_prepare(jool, session, &prepared);
	spin_unlock_bh(&queue->lock);

	send_to_userspace(jool, &prepared);
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

	log_err("We're out of sync: Incoming session entry " SEPP
			" collides with DB entry " SEPP ".",
			SEPA(new), SEPA(old));
	params->success = false;
	return FATE_PRESERVE;
}

static bool add_new_session(struct xlator *jool, struct nlattr *attr)
{
	struct add_params params;
	struct collision_cb cb;
	int error;

	__log_debug(jool, "Adding session!");

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

static bool joold_disabled(struct xlator *jool)
{
	if (!GLOBALS(jool).enabled) {
		log_err("Session sync is disabled on this instance.");
		return true;
	}

	return false;
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
	bool success;

	if (joold_disabled(jool))
		return -EINVAL;

	success = true;
	nla_for_each_nested(attr, root, rem)
		success &= add_new_session(jool, attr);

	__log_debug(jool, "Done.");
	return success ? 0 : -EINVAL;
}

int joold_advertise(struct xlator *jool)
{
	struct joold_queue *queue;
	struct joold_pkt pkt;

	if (joold_disabled(jool))
		return -EINVAL;

	queue = jool->nat64.joold;

	spin_lock_bh(&queue->lock);

	if (queue->flags & JQF_AD_ONGOING) {
		log_err("joold advertisement already in progress.");
		spin_unlock_bh(&queue->lock);
		return -EINVAL;
	}

	queue->flags |= JQF_AD_ONGOING;
	queue->flags &= ~JQF_OFFSET_SET;
	queue->ad.proto = L4PROTO_TCP;
	send_to_userspace_prepare(jool, NULL, &pkt);

	spin_unlock_bh(&queue->lock);

	send_to_userspace(jool, &pkt);
	return 0;
}

void joold_ack(struct xlator *jool)
{
	struct joold_queue *queue;
	struct joold_pkt pkt;

	if (joold_disabled(jool))
		return;

	queue = jool->nat64.joold;

	spin_lock_bh(&queue->lock);
	queue->flags |= JQF_ACK_RECEIVED;
	send_to_userspace_prepare(jool, NULL, &pkt);
	spin_unlock_bh(&queue->lock);

	send_to_userspace(jool, &pkt);
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
	struct joold_pkt pkt;

	if (!GLOBALS(jool).enabled)
		return;

	lock = &jool->nat64.joold->lock;

	spin_lock_bh(lock);
	send_to_userspace_prepare(jool, NULL, &pkt);
	spin_unlock_bh(lock);

	send_to_userspace(jool, &pkt);
}
