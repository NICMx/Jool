#include "nat64/mod/stateful/joold.h"

#include "nat64/common/constants.h"
#include "nat64/common/str_utils.h"
#include "nat64/mod/common/wkmalloc.h"
#include "nat64/mod/common/xlator.h"
#include "nat64/mod/common/nl/nl_core2.h"
#include "nat64/mod/stateful/bib/db.h"

#include <linux/inet.h>

struct joold_advertise_struct {
	struct taddr4_tuple offset;
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
 *
 * Note: Careful with the layout of this structure! It's currently padded and
 * packed to fit in exactly 64 bytes.
 * http://www.catb.org/esr/structure-packing/
 */
struct joold_session {

	/**
	 * This is not actually the same as session_entry->update_time.
	 * session_entry->update_time is the time at which the session was last
	 * updated.
	 * This update_time is the age of the session's last update.
	 * We do this so we don't have to ask the user to synchronize clocks.
	 * (We're assuming the session will travel to the other Jools
	 * instantaneously.)
	 *
	 * Also, session->entry->update time is measured in jiffies.
	 * This one is measured in milliseconds.
	 */
	__be64 update_time;

	/* Exactly 8 bytes so far. */

	struct in6_addr src6_addr;
	struct in6_addr dst6_addr;
	struct in_addr src4_addr;
	struct in_addr dst4_addr;
	__be16 src6_port;
	__be16 dst6_port;
	__be16 src4_port;
	__be16 dst4_port;

	/*
	 * Exactly 56 bytes so far.
	 * Notice that the following can be compressed further but there's no
	 * point currently.
	 */

	__u8 l4_proto;
	__u8 state;
	/* See session_timer_type. */
	__u8 timer_type;

	/* Exactly 59 bytes so far. */

	/**
	 * Forces sizeof(struct joold_session) to be exacly 64 bytes.
	 * If not present, sizeof yields me 60 in a 32-bit machine and 64 in a
	 * 64-bit machine, which breaks compatibility.
	 */
	__u8 padding[5];
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
		struct joold_session single;
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

static bool should_send(struct joold_queue *queue)
{
	unsigned long deadline;
	unsigned int max_sessions;

	if (queue->count == 0)
		return false;

	deadline = queue->config.flush_deadline;
	if (time_before(queue->last_flush_time + deadline, jiffies))
		return true;

	if (!queue->ack_received)
		return false;

	if (queue->config.flush_asap)
		return true;

	if (queue->advertisement_count > 0)
		return true;

	max_sessions = queue->config.max_payload / sizeof(struct joold_session);
	return queue->count >= max_sessions;
}

static int write_single_node(struct joold_node *node,
		struct nlcore_buffer *buffer)
{
	__be64 old;
	__u64 time;
	int full;

	old = node->single.update_time;

	time = be64_to_cpu(node->single.update_time);
	time = jiffies_to_msecs(jiffies - time);
	node->single.update_time = cpu_to_be64(time);

	full = nlbuffer_write(buffer, &node->single, sizeof(node->single));
	if (full) {
		/* We'll convert the time again in the next flush, so revert. */
		node->single.update_time = old;
	}

	return full;
}

static int foreach_cb(struct session_entry *entry, void *arg)
{
	int status;
	struct joold_advertise_struct *adv = arg;
	struct joold_session session;
	__u64 update_time;

	update_time = jiffies_to_msecs(jiffies - entry->update_time);
	session.update_time = cpu_to_be64(update_time);

	session.src6_addr = entry->src6.l3;
	session.dst6_addr = entry->dst6.l3;
	session.src4_addr = entry->src4.l3;
	session.dst4_addr = entry->dst4.l3;
	session.src6_port = cpu_to_be16(entry->src6.l4);
	session.dst6_port = cpu_to_be16(entry->dst6.l4);
	session.src4_port = cpu_to_be16(entry->src4.l4);
	session.dst4_port = cpu_to_be16(entry->dst4.l4);

	session.l4_proto = entry->proto;
	session.state = entry->state;
	session.timer_type = entry->timer_type;
	memset(session.padding, 0, sizeof(session.padding));

	status = nlbuffer_write(adv->buffer, &session, sizeof(session));
	if (status) {
		adv->offset.src = entry->src4;
		adv->offset.dst = entry->dst4;
	}

	return status;
}

static int write_group_node(struct joold_node *node,
		struct nlcore_buffer *buffer,
		struct bib *bib)
{
	struct joold_advertise_struct arg;
	struct session_foreach_func func = {
		.cb = foreach_cb,
		.arg = &arg,
	};
	struct session_foreach_offset offset_struct;
	struct session_foreach_offset *offset = NULL;
	int error;

	arg.buffer = buffer;
	if (node->group.offset_set) {
		offset_struct.offset = node->group.offset;
		offset_struct.include_offset = true;
		offset = &offset_struct;
	}

	error = bib_foreach_session(bib, node->group.proto, &func, offset);
	if (error > 0) {
		node->group.offset = arg.offset;
		node->group.offset_set = true;
	}

	return error;
}

/**
 * Builds an nl-core-compatible buffer out of @sessions.
 */
static int build_buffer(struct nlcore_buffer *buffer, struct joold_queue *queue,
		struct bib *bib)
{
	struct request_hdr jool_hdr;
	struct joold_node *node;
	int error;

	init_request_hdr(&jool_hdr, MODE_JOOLD, OP_ADD);
	jool_hdr.castness = 'm';

	error = nlbuffer_init_request(buffer, &jool_hdr,
			queue->config.max_payload - sizeof(jool_hdr));
	if (error) {
		log_debug("nlbuffer_init_request() threw error %d.", error);
		return error;
	}

	while (!list_empty(&queue->sessions)) {
		node = list_first_entry(&queue->sessions, struct joold_node,
				nextprev);
		error = (node->is_group)
				? write_group_node(node, buffer, bib)
				: write_single_node(node, buffer);
		if (error > 0) {
			return 0;
		} else if (error) {
			nlbuffer_free(buffer);
			return error;
		}

		queue->count--;
		if (node->is_group)
			queue->advertisement_count--;

		list_del(&node->nextprev);
		wkmem_cache_free("joold node", node_cache, node);
	}

	/*
	 * This can happen when the list only had group nodes and the session
	 * database was empty.
	 */
	if (sizeof(jool_hdr) == buffer->len) {
		log_debug("There was nothing to send after all.");
		nlbuffer_free(buffer);
		return -ENOENT;
	}

	return 0;
}

struct joold_buffer {
	struct nlcore_buffer buffer;
	struct net *ns;
	bool initialized;
};

#define JOOLD_BUFFER_INIT { .initialized = false }

/**
 * Assumes the lock is held.
 * YOU HAVE TO CALL send_to_userspace() AFTER YOU RELEASE THE SPINLOCK!!!
 */
static void send_to_userspace_prepare(struct joold_queue *queue,
		struct bib *bib, struct joold_buffer *buffer)
{
	if (!should_send(queue))
		return;

	if (build_buffer(&buffer->buffer, queue, bib))
		return;

	buffer->initialized = true;
	/*
	 * Caller has a reference and the buffer is not going to outlive it so
	 * this should be alright.
	 */
	buffer->ns = queue->ns;

	/*
	 * BTW: This sucks.
	 * We're assuming that the nlcore_send_multicast_message() during
	 * send_to_userspace() is going to succeed.
	 * But the alternative is to do the nlcore_send_multicast_message()
	 * with the lock held, and I don't have the stomach for that.
	 */
	queue->ack_received = false;
	queue->last_flush_time = jiffies;
}

static void send_to_userspace(struct joold_buffer *buffer)
{
	int error;

	if (!buffer->initialized)
		return;

	log_debug("Sending multicast message.");
	error = nlcore_send_multicast_message(buffer->ns, &buffer->buffer);
	if (!error)
		log_debug("Multicast message sent.");

	nlbuffer_free(&buffer->buffer);
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
	queue->advertisement_count = 0;
	queue->ack_received = true;
	queue->last_flush_time = jiffies;
	queue->config.enabled = DEFAULT_JOOLD_ENABLED;
	queue->config.flush_asap = DEFAULT_JOOLD_FLUSH_ASAP;
	queue->config.flush_deadline = DEFAULT_JOOLD_DEADLINE;
	queue->config.capacity = DEFAULT_JOOLD_CAPACITY;
	queue->config.max_payload = DEFAULT_JOOLD_MAX_PAYLOAD;

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
 * joold_add - Add the @entry session to @queue.
 *
 * This is the function that gets called whenever a packet translation
 * successfully triggers the creation of a session entry. @entry will be sent
 * to the joold daemon.
 */
void joold_add(struct joold_queue *queue, struct session_entry *entry,
		struct bib *bib)
{
	struct joold_node *copy;
	struct joold_buffer buffer = JOOLD_BUFFER_INIT;

	spin_lock_bh(&queue->lock);

	if (!queue->config.enabled) {
		spin_unlock_bh(&queue->lock);
		return;
	}

	copy = wkmem_cache_alloc("joold node", node_cache, GFP_ATOMIC);
	if (!copy) {
		spin_unlock_bh(&queue->lock);
		return;
	}

	copy->is_group = false;
	/*
	 * Do not convert the time yet; if the session is queued for a long
	 * time, these will be horribly inaccurate.
	 */
	copy->single.update_time = cpu_to_be64(entry->update_time);
	copy->single.src6_addr = entry->src6.l3;
	copy->single.dst6_addr = entry->dst6.l3;
	copy->single.src4_addr = entry->src4.l3;
	copy->single.dst4_addr = entry->dst4.l3;
	copy->single.src6_port = cpu_to_be16(entry->src6.l4);
	copy->single.dst6_port = cpu_to_be16(entry->dst6.l4);
	copy->single.src4_port = cpu_to_be16(entry->src4.l4);
	copy->single.dst4_port = cpu_to_be16(entry->dst4.l4);
	copy->single.l4_proto = entry->proto;
	copy->single.state = entry->state;
	copy->single.timer_type = entry->timer_type;
	memset(copy->single.padding, 0, sizeof(copy->single.padding));

	list_add_tail(&copy->nextprev, &queue->sessions);
	queue->count++;

	if (queue->count > queue->config.capacity) {
		log_warn_once("Too many sessions are queuing up!\n"
				"Cannot synchronize fast enough; I will have to drop some sessions.\n"
				"Sorry.");
		purge_sessions(queue);
	} else {
		send_to_userspace_prepare(queue, bib, &buffer);
	}

	spin_unlock_bh(&queue->lock);

	send_to_userspace(&buffer);
}

static void init_session_entry(struct joold_session *in,
		struct session_entry *out)
{
	__u64 update_time;

	out->src6.l3 = in->src6_addr;
	out->src6.l4 = be16_to_cpu(in->src6_port);
	out->dst6.l3 = in->dst6_addr;
	out->dst6.l4 = be16_to_cpu(in->dst6_port);
	out->src4.l3 = in->src4_addr;
	out->src4.l4 = be16_to_cpu(in->src4_port);
	out->dst4.l3 = in->dst4_addr;
	out->dst4.l4 = be16_to_cpu(in->dst4_port);
	out->proto = in->l4_proto;
	out->state = in->state;
	out->timer_type = in->timer_type;
	update_time = be64_to_cpu(in->update_time);
	update_time = jiffies - msecs_to_jiffies(update_time);
	out->update_time = update_time;
	out->has_stored = false;
}

struct add_params {
	struct session_entry new;
	struct joold_session *newd;
	bool success;
};

static enum session_fate collision_cb(struct session_entry *old, void *arg)
{
	struct add_params *params = arg;
	struct session_entry *new = &params->new;

	if (session_equals(old, new)) { /* It's the same session; update it. */
		old->state = new->state;
		old->timer_type = params->newd->timer_type;
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

static bool add_new_session(struct xlator *jool, struct joold_session *in)
{
	struct add_params params;
	struct collision_cb cb = {
			.cb = collision_cb,
			.arg = &params,
	};
	int error;

	log_debug("Adding session!");

	init_session_entry(in, &params.new);
	params.newd = in;
	error = bib_add_session(jool->nat64.bib, &params.new, &cb);
	if (error == -EEXIST)
		return params.success;
	if (error) {
		log_err("sessiondb_add() threw unknown error code %d.", error);
		return false;
	}

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

	spin_lock_bh(&queue->lock);
	enabled = __validate_enabled(queue);
	spin_unlock_bh(&queue->lock);

	return enabled;
}

/**
 * joold_sync - Parses a bunch of sessions out of @data and adds them to @jool's
 * session database.
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

	node = wkmem_cache_alloc("joold node", node_cache, GFP_ATOMIC);
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
	struct joold_queue *queue = jool->nat64.joold;
	struct joold_buffer buffer = JOOLD_BUFFER_INIT;
	int error;

	spin_lock_bh(&queue->lock);

	error = __validate_enabled(queue);
	if (error)
		goto end;

	error = prepare_advertisement(queue);
	if (error)
		goto end;

	send_to_userspace_prepare(queue, jool->nat64.bib, &buffer);
	/* Fall through */

end:
	spin_unlock_bh(&queue->lock);
	send_to_userspace(&buffer);
	return error;
}

void joold_ack(struct xlator *jool)
{
	struct joold_queue *queue = jool->nat64.joold;
	struct joold_buffer buffer = JOOLD_BUFFER_INIT;

	spin_lock_bh(&queue->lock);

	if (__validate_enabled(queue))
		goto end;

	queue->ack_received = true;
	send_to_userspace_prepare(queue, jool->nat64.bib, &buffer);
	/* Fall through */

end:
	spin_unlock_bh(&queue->lock);
	send_to_userspace(&buffer);
}

/**
 * Called every now and then to flush the queue in case nodes have been queued,
 * the deadline is in the past and no new packets have triggered a flush.
 * It's just a last-resort attempt to prevent nodes from lingering here for too
 * long that's generally only useful in non-flush-asap mode.
 */
void joold_clean(struct joold_queue *queue, struct bib *bib)
{
	struct joold_buffer buffer = JOOLD_BUFFER_INIT;

	spin_lock_bh(&queue->lock);

	if (!queue->config.enabled)
		goto end;

	send_to_userspace_prepare(queue, bib, &buffer);
	/* Fall through */

end:
	spin_unlock_bh(&queue->lock);
	send_to_userspace(&buffer);
}
