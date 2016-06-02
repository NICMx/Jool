#include "nat64/mod/stateful/joold.h"

#include "nat64/common/constants.h"
#include "nat64/common/session.h"
#include "nat64/common/str_utils.h"
#include "nat64/mod/common/wkmalloc.h"
#include "nat64/common/joold/joold_config.h"
#include "nat64/mod/common/nl/nl_core2.h"
#include "nat64/mod/stateful/session/db.h"
#include "nat64/mod/stateful/bib/db.h"
#include "nat64/mod/common/xlator.h"

#include <linux/inet.h>

struct joold_offset {
	struct ipv4_transport_addr local;
	struct ipv4_transport_addr remote;
};

struct joold_advertise_struct {
	struct joold_offset offset;
	struct nlcore_buffer *buffer;
};

/*
 * Remember to include in the user documentation:
 *
 * - pool4 and static BIB entries have to be synchronized manually.
 * - Apparently, users do not actually need to keep clocks in sync.
 */

struct joold_queue {
	/**
	 * Sessions so far listed to be sent to the daemon.
	 *
	 * TODO (performance) this might be slightly optimizable, but I don't
	 * care enough at the moment.
	 * Sessions are accumulated in this list. When the module decides it
	 * needs to send them, it copies them to a buffer (so they can be fed to
	 * the nl core module), and then nl core copies that into an skb.
	 * Instead of adding to a list, we should probably build the buffer
	 * directly (or the skb).
	 * On the downside, this might mean the spinlock would need to be held
	 * for longer times (as the list splicing is very fast and cheap
	 * currently).
	 */
	struct list_head sessions;
	/** Length of the @sessions list. */
	unsigned int count;

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

	/* User-defined values (--global). */
	struct joold_config config;

	/** Namespace where the sessions will be multicasted. */
	struct net *ns;

	spinlock_t lock;
	struct kref refs;
};

/**
 * Subset of fields from struct session_entry which need to be synchronized
 * across Jool instances.
 */
struct joold_session {
	struct ipv6_transport_addr src6;
	struct ipv6_transport_addr dst6;
	struct ipv4_transport_addr src4;
	struct ipv4_transport_addr dst4;
	__be64 update_time;
	__be64 creation_time;
	__u8 l4_proto;
	__u8 state;
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
		struct {
			/** The session to be transmitted. */
			struct joold_session session;
		} single;
		/**
		 * If @group is valid, the user issued an --advertise.
		 * The whole database needs to be transmitted.
		 * Unfortunately, a typical table won't fit in a single
		 * packet so this node might stick for several iterations and
		 * keep track of what is yet to be sent.
		 */
		struct {
			/** IPv4 ID of the session sent in the last packet. */
			struct joold_offset offset;
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

static struct kmem_cache *node_cache;


/**
 * joold_init - Initializes this module. Make sure you call this before other
 * joold_ functions.
 */
int joold_init(void)
{
	node_cache = kmem_cache_create("jool_joold_nodes",
			sizeof(struct joold_node), 0, 0, NULL);
	if (!node_cache) {
		log_err("Could not allocate the Joold node cache.");
		return -ENOMEM;
	}

	return 0;
}

/**
 * joold_terminate - Reverts joold_init().
 */
void joold_terminate(void)
{
	kmem_cache_destroy(node_cache);
}

static int foreach_cb(struct session_entry *entry, void *arg)
{
	int status;
	struct joold_advertise_struct *adv = arg;
	struct joold_session session;
	__u64 update_time;
	__u64 creation_time;

	session.l4_proto = entry->l4_proto;
	session.src4 = entry->src4;
	session.dst6 = entry->dst6;
	session.dst4 = entry->dst4;
	session.src6 = entry->src6;
	session.state = entry->state;

	update_time = jiffies_to_msecs(jiffies - entry->update_time);
	session.update_time = cpu_to_be64(update_time);

	creation_time = jiffies_to_msecs(jiffies - entry->creation_time);
	session.creation_time = cpu_to_be64(creation_time);

	status = nlbuffer_write(adv->buffer, &session, sizeof(session));
	if (status) {
		adv->offset.local = entry->src4;
		adv->offset.remote = entry->dst4;
	}

	return status;
}

static int write_node(struct joold_node *node, struct nlcore_buffer *buffer,
		struct sessiondb *sdb)
{
	struct joold_advertise_struct arg;
	struct ipv4_transport_addr *remote;
	struct ipv4_transport_addr *local;
	int error;

	if (!node->is_group) {
		return nlbuffer_write(buffer, &node->single.session,
				sizeof(node->single.session));
	}

	arg.buffer = buffer;
	if (node->group.offset_set) {
		remote = &node->group.offset.remote;
		local = &node->group.offset.local;
	} else {
		remote = local = NULL;
	}

	error = sessiondb_foreach(sdb, node->group.proto, foreach_cb, &arg,
			remote, local, true);
	if (error > 0) {
		memcpy(&node->group.offset, &arg.offset, sizeof(arg.offset));
		node->group.offset_set = true;
	}

	return error;
}

static void purge_sessions(struct joold_queue *queue)
{
	struct joold_node *node;

	while (!list_empty(&queue->sessions)) {
		node = list_first_entry(&queue->sessions, typeof(*node),
				nextprev);
		list_del(&node->nextprev);
		kmem_cache_free(node_cache, node);
	}

	queue->count = 0;
	queue->ack_received = true;
	queue->last_flush_time = jiffies;
}


/**
 * Builds an nl-core-compatible buffer out of @sessions.
 */
static int build_buffer(struct nlcore_buffer *buffer, struct joold_queue *queue,
		struct sessiondb *sdb)
{
	struct request_hdr jool_hdr;
	struct joold_node *node;
	int error;

	init_request_hdr(&jool_hdr, MODE_JOOLD, OP_ADD);
	jool_hdr.castness = 'm';

	error = nlbuffer_init_request(buffer, &jool_hdr,
			JOOLD_MAX_PAYLOAD - sizeof(jool_hdr));
	if (error) {
		log_debug("nlbuffer_init_request() threw error %d.", error);
		return error;
	}

	while (!list_empty(&queue->sessions)) {
		node = list_first_entry(&queue->sessions, struct joold_node,
				nextprev);
		error = write_node(node, buffer, sdb);
		if (error > 0) {
			return 0;
		} else if (error) {
			nlbuffer_free(buffer);
			return error;
		}

		list_del(&node->nextprev);
		kmem_cache_free(node_cache, node);

		queue->count -= 1;
	}

	return 0;

}

/*
 * Assumes the lock is held.
 *
 * Note: This would probably be 100x better if you could think of a way to move
 * nlcore_send_multicast_message() out of the spinlock. (The main obstacle is
 * last queue->'s.)
 *
 * (nlbuffer_free() also doesn't need the spinlock but shouldn't be that
 * influential.)
 */
static void send_to_userspace(struct joold_queue *queue, struct sessiondb *sdb)
{
	struct nlcore_buffer buffer;
	bool force_flush;
	int error;

	if (queue->count == 0)
		return;

	if (!queue->ack_received) {
		force_flush = time_before(queue->last_flush_time + queue->config.flush_limit, jiffies);
		if (!force_flush)
			return;
	}

	if (build_buffer(&buffer, queue, sdb))
		return;

	log_debug("Sending multicast message.");
	error = nlcore_send_multicast_message(queue->ns, &buffer);
	if (error) {
		log_debug("nl_core_send_multicast_message() threw errcode %d.",
				error);
		return;
	}
	log_debug("Multicast message sent.");

	queue->ack_received = false;
	queue->last_flush_time = jiffies;
	nlbuffer_free(&buffer);
}

/**
 * joold_create - Constructor for joold_queue structs.
 */
struct joold_queue *joold_create(struct net *ns)
{
	struct joold_queue *queue;

	queue = wkmalloc(struct joold_queue, GFP_KERNEL);
	if (!queue)
		return NULL;

	INIT_LIST_HEAD(&queue->sessions);
	queue->count = 0;
	queue->ack_received = true;
	queue->config.enabled = DEFAULT_JOOLD_ENABLED;
	queue->config.flush_asap = DEFAULT_JOOLD_FLUSH_ASAP;
	queue->config.flush_limit = DEFAULT_JOOLD_FLUSH_LIMIT;
	queue->config.capacity = DEFAULT_JOOLD_CAPACITY;

	queue->ns = ns;
	get_net(ns);

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
	queue = container_of(refs, struct joold_queue, refs);

	put_net(queue->ns);
	purge_sessions(queue);
	wkfree(struct joold_queue, queue);
}

void joold_put(struct joold_queue *queue)
{
	kref_put(&queue->refs, joold_release);
}

void joold_config_copy(struct joold_queue *queue, struct joold_config *config)
{
	spin_lock_bh(&queue->lock);
	memcpy(config, &queue->config, sizeof(queue->config));
	spin_unlock_bh(&queue->lock);
}

void joold_config_set(struct joold_queue *queue, struct joold_config *config)
{
	spin_lock_bh(&queue->lock);
	memcpy(&queue->config, config, sizeof(*config));
	spin_unlock_bh(&queue->lock);
}

/**
 * joold_update_config - Override @queue's configuration.
 *
 * Gets called whenever the user tweaks this module's configuration by means of
 * --global userspace application commands.
 */
void joold_update_config(struct joold_queue *queue,
		struct joold_config *new_config)
{
	spin_lock_bh(&queue->lock);
	memcpy(&queue->config, new_config, sizeof(*new_config));
	spin_unlock_bh(&queue->lock);
}

/**
 * joold_add_session - Add the @entry session to @queue.
 *
 * This is the function that gets called whenever a packet translation
 * successfully triggers the creation of a session entry. @entry will be sent
 * to the joold daemon.
 */
void joold_add_session(struct joold_queue *queue, struct session_entry *entry,
		struct sessiondb *sdb)
{
	struct joold_node *entry_copy;
	__u64 update_time;
	__u64 creation_time;

	spin_lock_bh(&queue->lock);

	if (!queue->config.enabled) {
		spin_unlock_bh(&queue->lock);
		return;
	}

	entry_copy = kmem_cache_alloc(node_cache, GFP_ATOMIC);
	if (!entry_copy) {
		spin_unlock_bh(&queue->lock);
		return;
	}

	entry_copy->is_group = false;
	entry_copy->single.session.l4_proto = entry->l4_proto;
	entry_copy->single.session.src4 = entry->src4;
	entry_copy->single.session.dst6 = entry->dst6;
	entry_copy->single.session.dst4 = entry->dst4;
	entry_copy->single.session.src6 = entry->src6;
	entry_copy->single.session.state = entry->state;

	update_time = jiffies_to_msecs(jiffies - entry->update_time);
	entry_copy->single.session.update_time = cpu_to_be64(update_time);
	creation_time = jiffies_to_msecs(jiffies - entry->creation_time);
	entry_copy->single.session.creation_time = cpu_to_be64(creation_time);

	list_add_tail(&entry_copy->nextprev, &queue->sessions);
	queue->count++;

	if (queue->count > queue->config.capacity) {
		log_warn_once("Too many sessions are queuing up!\n"
				"Cannot synchronize fast enough; I will have to drop some sessions.\n"
				"Sorry.");
		purge_sessions(queue);
	} else if (queue->config.flush_asap
			|| queue->count >= JOOLD_MAX_SESSIONS) {
		send_to_userspace(queue, sdb);
	}

	spin_unlock_bh(&queue->lock);
}

static int add_new_bib(struct bib *db, struct joold_session *session,
		struct bib_entry **result)
{
	struct bib_entry *new; /* The one we're trying to add. */
	struct bib_entry *old; /* The one that was already in the database. */
	int error;

	new = bibentry_create(&session->src4, &session->src6, false,
			session->l4_proto);
	if (!new) {
		log_err("Couldn't allocate BIB entry.");
		return -ENOMEM;
	}

	error = bibdb_add(db, new, &old);
	if (!error) {
		/* @new was successfully inserted, @old is unset. */
		*result = new;
		return 0; /* Happy path. */
	}

	if (error != -EEXIST) {
		/* Unexpected errors. @new was rejected, @old is unset. */
		log_err("bibdb_add() threw unknown error code %d.", error);
		bibentry_put_thread(new, true);
		return error;
	}

	if (bibentry_equals(new, old)) {
		/*
		 * @new was rejected because the BIB already had an identical
		 * entry.
		 */
		bibentry_put_thread(new, true);
		*result = old;
		return 0; /* Slightly less likely happy path. */
	}

	/*
	 * @new was rejected because an incompatible entry was already there.
	 *
	 * This happens when two packets of the same connection were routed via
	 * different NAT64s and they chose different masks before
	 * synchronization.
	 */
	log_err("We're out of sync: Incoming %s BIB entry %pI6c#%u|%pI4#%u collides with DB entry %pI6c#%u|%pI4#%u.",
			l4proto_to_string(new->l4_proto),
			&new->ipv6.l3, new->ipv6.l4,
			&new->ipv4.l3, new->ipv4.l4,
			&old->ipv6.l3, old->ipv6.l4,
			&old->ipv4.l3, old->ipv4.l4);
	bibentry_put_thread(new, true);
	bibentry_put_thread(old, false);
	return -EEXIST;
}

static struct session_entry *init_session_entry(struct joold_session *in,
		struct bib_entry *bib)
{
	struct session_entry *out;
	__u64 update_time;
	__u64 creation_time;

	out = session_create(&in->src6, &in->dst6, &in->src4,
			&in->dst4, in->l4_proto, bib);
	if (!out)
		return NULL;

	update_time = be64_to_cpu(in->update_time);
	update_time = jiffies - msecs_to_jiffies(update_time);
	creation_time = be64_to_cpu(in->creation_time);
	creation_time = jiffies - msecs_to_jiffies(creation_time);

	out->state = in->state;
	out->update_time = update_time;
	out->creation_time = creation_time;

	return out;
}

struct add_params {
	struct session_entry *new;
	bool success;
};

static enum session_fate collision_cb(struct session_entry *old, void *arg)
{
	struct add_params *params = arg;
	struct session_entry *new = params->new;

	if (session_equals(old, new)) {
		/* It's the same session; update it. */
		old->state = new->state;
		params->success = true;
		if (old->l4_proto != L4PROTO_TCP || old->state == ESTABLISHED)
			return FATE_TIMER_EST;
		else
			return FATE_TIMER_TRANS;
	}

	log_err("We're out of sync: Incoming %s session entry %pI6c#%u|%pI6c#%u|%pI4#%u|%pI4#%u collides with DB entry %pI6c#%u|%pI6c#%u|%pI4#%u|%pI4#%u.",
			l4proto_to_string(new->l4_proto),
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

static bool add_new_session(struct xlator *jool, struct joold_session *in)
{
	struct session_entry *new;
	struct bib_entry *bib = 0;
	struct add_params params;
	int error;

	log_debug("Adding session!");

	if (add_new_bib(jool->nat64.bib, in, &bib))
		return false;

	new = init_session_entry(in, bib);
	if (!new) {
		log_err("Couldn't allocate session.");
		bibentry_put_thread(bib, false);
		return false;
	}

	params.new = new;
	error = sessiondb_add(jool->nat64.session, new, collision_cb, &params);
	if (error == -EEXIST) {
		session_put(new, true);
		return params.success;
	}
	if (error) {
		log_err("sessiondb_add() threw unknown error code %d.", error);
		session_put(new, true);
		return false;
	}

	session_put(new, false);
	return true;
}

static int __validate_enabled(struct joold_queue *queue)
{
	if (!queue->config.enabled) {
		log_err("Session sync is disabled on this instance.");
		return -EINVAL;
	}

	return 0;
}

static int validate_enabled(struct xlator *jool)
{
	struct joold_queue *queue = jool->nat64.joold;
	int enabled;

	/* TODO (final) Review BH contextness. */
	spin_lock_bh(&queue->lock);
	enabled = __validate_enabled(queue);
	spin_unlock_bh(&queue->lock);

	return enabled;
}

/**
 * joold_sync_entries - Parses a bunch of sessions out of @data and adds them
 * to @jool's session database.
 *
 * This is the function that gets called whenever the jool daemon sends data to
 * the @jool Jool instance.
 */
int joold_sync(struct xlator *jool, void *data, __u32 data_len)
{
	struct joold_session *session;
	unsigned int num_sessions;
	unsigned int i;
	int error;
	bool success;

	error = validate_enabled(jool);
	if (error)
		return error;

	if (data_len % sizeof(struct joold_session) != 0) {
		log_err("The Netlink packet seems corrupted.");
		return -EINVAL;
	}

	session = data;
	num_sessions = data_len / sizeof(struct joold_session);

	success = true;
	for (i = 0; i < num_sessions; i++, session++)
		success &= add_new_session(jool, session);

	log_debug("Added %u sessions.", i);
	return success ? 0 : -EINVAL;
}

int joold_test(struct xlator *jool)
{
	struct nlcore_buffer buffer;
	struct request_hdr hdr;
	int error;

	error = validate_enabled(jool);
	if (error)
		return error;

	init_request_hdr(&hdr, MODE_JOOLD, OP_ADD);
	hdr.castness = 'm';

	error = nlbuffer_init_request(&buffer, &hdr, 0);
	if (error)
		return error;

	error = nlcore_send_multicast_message(jool->ns, &buffer);
	nlbuffer_free(&buffer);
	return error;
}


static int add_advertise_node(struct joold_queue *queue, l4_protocol proto)
{
	struct joold_node *node;

	node = kmem_cache_alloc(node_cache, GFP_ATOMIC);
	if (!node) {
		log_err("Out of memory.");
		return -ENOMEM;
	}

	node->is_group = true;
	memset(&node->group.offset, 0, sizeof(node->group.offset));
	node->group.offset_set = false;
	node->group.proto = proto;

	list_add_tail(&node->nextprev, &queue->sessions);
	queue->count++;

	return 0;
}

static int advertise(struct joold_queue *queue)
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
	struct joold_queue *queue = jool->nat64.joold;
	int error;

	spin_lock_bh(&queue->lock);

	error = __validate_enabled(queue);
	if (error)
		goto end;

	error = advertise(queue);
	if (error)
		goto end;

	send_to_userspace(queue, jool->nat64.session);
	/* Fall through */

end:
	spin_unlock_bh(&queue->lock);
	return error;
}

void joold_ack(struct xlator *jool)
{
	struct joold_queue *queue = jool->nat64.joold;

	spin_lock_bh(&queue->lock);

	if (__validate_enabled(queue))
		goto end;

	queue->ack_received = true;
	send_to_userspace(queue, jool->nat64.session);
	/* Fall through */

end:
	spin_unlock_bh(&queue->lock);
}
