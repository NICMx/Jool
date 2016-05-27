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

#include<linux/inet.h>

struct joold_offset {
	struct ipv4_transport_addr local_offset;
	struct ipv4_transport_addr remote_offset;
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
	 * This will continuously fetch listed sessions to userspace every now
	 * and then.
	 */
	struct timer_list timer;

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
	struct ipv6_transport_addr remote6;
	struct ipv6_transport_addr local6;
	struct ipv4_transport_addr local4;
	struct ipv4_transport_addr remote4;
	__be64 update_time;
	__be64 creation_time;
	__u8 l4_proto;
	__u8 state;
};

/**
 * List elements in struct joold_queue->sessions.
 */
struct joold_node {
	/** S - in case of a single session **/
	/** A - in case of advertising tcp sessions **/
	/** B - in case of advertising udp sessions **/
	/** C - in case of advertising icmp sessions **/
	char type;
	struct joold_offset offset;
	struct sessiondb *db;
	struct joold_session session;
	struct list_head nextprev;
};

static struct kmem_cache *node_cache;
static volatile __u8 can_send;


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

	can_send = 1;

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

	int error = 0;
	struct joold_advertise_struct *adv_struct = arg;
	struct joold_session session;
	__u64 update_time;
	__u64 creation_time;

	session.l4_proto = entry->l4_proto;
	session.local4 = entry->src4;
	session.local6 = entry->dst6;
	session.remote4 = entry->dst4;
	session.remote6 = entry->src6;
	session.state = entry->state;

	update_time = jiffies_to_msecs(jiffies - entry->update_time);
	session.update_time = cpu_to_be64(update_time);

	creation_time = jiffies_to_msecs(jiffies - entry->creation_time);
	session.creation_time = cpu_to_be64(creation_time);

	error = nlbuffer_write(adv_struct->buffer, &session, sizeof(session));

	if (!error) {

		adv_struct->offset.local_offset = entry->src4;
		adv_struct->offset.remote_offset = entry->dst4;

	}


	return error;
}


static int write_special_node(struct joold_node *node, struct nlcore_buffer *buffer)
{
	int error = 0;
	struct joold_advertise_struct adv_struct;

	struct ipv4_transport_addr addr_local = node->offset.local_offset;
	struct ipv4_transport_addr addr_remote = node->offset.remote_offset;


	adv_struct.buffer = buffer;

	switch (node->type) {
		case 'A':
				error = sessiondb_foreach(node->db, L4PROTO_TCP, foreach_cb, &adv_struct, &addr_remote, &addr_local);
			break;
		case 'B':
				error = sessiondb_foreach(node->db, L4PROTO_UDP, foreach_cb, &adv_struct, &addr_remote, &addr_local);
			break;
		case 'C':
				error = sessiondb_foreach(node->db, L4PROTO_ICMP, foreach_cb, &adv_struct, &addr_remote, &addr_local);
			break;
	}

	if (error) {

		node->offset.local_offset = adv_struct.offset.local_offset;
		node->offset.remote_offset = adv_struct.offset.remote_offset;

	}

	return error;
}

static void free_list(struct list_head *list)
{
	struct joold_node *node;
	while (!list_empty(list)) {
		node = list_first_entry(list, typeof(*node), nextprev);
		list_del(&node->nextprev);
		kmem_cache_free(node_cache, node);
	}
}


/**
 * Builds an nl-core-compatible buffer out of @sessions.
 */
static int build_buffer(struct nlcore_buffer *buffer, struct joold_queue *queue)
{
	struct request_hdr jool_hdr;
	struct joold_node *node;
	int error;

	init_request_hdr(&jool_hdr, MODE_JOOLD, OP_ADD);
	jool_hdr.castness = 'm';

	error = nlbuffer_init_request(buffer, &jool_hdr, JOOLD_PACKET_SIZE - sizeof(jool_hdr));

	if (error) {
		log_debug("nlbuffer_init_request() threw error %d.", error);
		return error;
	}

	while(!list_empty(&queue->sessions)) {

		node = list_first_entry(&queue->sessions, struct joold_node, nextprev);

		if (node->type == 'S') {

			error = nlbuffer_write(buffer, &node->session,
					sizeof(node->session));

		} else {

			error = write_special_node(node, buffer);
		}

		if (!error) {
			list_del(&node->nextprev);
			queue->count -= 1;
		} else {
			return 0;
		}

	}

	return 0;

}

static void send_buffer(struct net *ns, struct nlcore_buffer *buffer)
{
	int error;

	log_debug("Sending multicast message.");

	error = nlcore_send_multicast_message(ns, buffer);
	if (error) {
		log_debug("nl_core_send_multicast_message() threw errcode %d.",
				error);
	} else {
		can_send = false;
		log_debug("Multicast message sent.");
	}
}

static void send_to_userspace(struct joold_queue *queue)
{
	struct nlcore_buffer buffer;

	if (queue->count == 0)
		return;

	if (build_buffer(&buffer, queue))
	 return;

	send_buffer(queue->ns, &buffer);
	nlbuffer_free(&buffer);

}

static void send_to_userspace_timeout(unsigned long arg)
{
	struct joold_queue *queue = (typeof(queue))arg;

	spin_lock_bh(&queue->lock);

	can_send = true;
	send_to_userspace(queue);

	mod_timer(&queue->timer, jiffies + queue->config.timer_period);

	spin_unlock_bh(&queue->lock);

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
	setup_timer(&queue->timer, send_to_userspace_timeout,
			(unsigned long)queue);
	queue->config.enabled = DEFAULT_JOOLD_ENABLED;
	queue->config.queue_capacity = DEFAULT_JOOLD_CAPACITY;
	queue->config.timer_period = DEFAULT_JOOLD_PERIOD;

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
	del_timer_sync(&queue->timer);
	free_list(&queue->sessions);
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

static bool user_wants_timer(struct joold_queue *queue)
{
	return queue->config.enabled && queue->config.timer_period != 0;
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
	if (user_wants_timer(queue)) {
		/*
		 * I don't want to wait timer_period because it would then wait
		 * old timer_period + new timer_period at most, which can be way
		 * longer than each separately.
		 * The timer will re-stabilize itself during the next iteration.
		 */
		mod_timer(&queue->timer, jiffies);
	} else {
		del_timer_sync(&queue->timer);
	}

	spin_unlock_bh(&queue->lock);
}

/**
 * joold_add_session - Add the @entry session to @queue.
 *
 * This is the function that gets called whenever a packet translation
 * successfully triggers the creation of a session entry. @entry will be sent
 * to the joold daemon.
 */
void joold_add_session(struct joold_queue *queue, struct session_entry *entry)
{
	struct joold_node *entry_copy;
	__u64 update_time;
	__u64 creation_time;
	LIST_HEAD(list);
	struct net *ns;

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

	entry_copy->type = 'S';
	entry_copy->session.l4_proto = entry->l4_proto;
	entry_copy->session.local4 = entry->src4;
	entry_copy->session.local6 = entry->dst6;
	entry_copy->session.remote4 = entry->dst4;
	entry_copy->session.remote6 = entry->src6;
	entry_copy->session.state = entry->state;

	update_time = jiffies_to_msecs(jiffies - entry->update_time);
	entry_copy->session.update_time = cpu_to_be64(update_time);
	creation_time = jiffies_to_msecs(jiffies - entry->creation_time);
	entry_copy->session.creation_time = cpu_to_be64(creation_time);

	list_add_tail(&entry_copy->nextprev, &queue->sessions);
	queue->count++;

	ns = queue->ns;
	get_net(ns);

	if (queue->config.queue_capacity <= queue->count && can_send)
		send_to_userspace(queue);

	spin_unlock_bh(&queue->lock);


	put_net(ns);
}

static int add_new_bib(struct bib *db, struct joold_session *session,
		struct bib_entry **result)
{
	struct bib_entry *new; /* The one we're trying to add. */
	struct bib_entry *old; /* The one that was already in the database. */
	int error;

	new = bibentry_create(&session->local4, &session->remote6, false,
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

	out = session_create(&in->remote6, &in->local6, &in->local4,
			&in->remote4, in->l4_proto, bib);
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

static int validate_enabled(struct xlator *jool)
{
	struct joold_queue *queue;
	bool enabled;

	/* TODO (final) Review BH contextness. */
	queue = jool->nat64.joold;
	spin_lock_bh(&queue->lock);
	enabled = queue->config.enabled;
	spin_unlock_bh(&queue->lock);

	if (!enabled) {
		log_err("Session sync is disabled on this instance.");
		return -EINVAL;
	}

	return 0;
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


static int add_advertise_node(struct joold_queue *queue, struct sessiondb *db, char type)
{
	struct joold_node *node;

	node = kmem_cache_alloc(node_cache, GFP_ATOMIC);

	if (!node) {
		log_err("could not allocate joold_node for session advertising!");
		return -ENOMEM;
	}

	node->type = type;
	node->db = db;
	memset(&node->offset.local_offset, 0, sizeof(node->offset.local_offset));
	memset(&node->offset.remote_offset, 0, sizeof(node->offset.local_offset));

	list_add_tail(&node->nextprev, &queue->sessions);
	queue->count++;

	return 0;
}

static int advertise(struct joold_queue *queue, struct sessiondb *db)
{
	int error = 0;


	error = add_advertise_node(queue, db, 'A');

	if (error)
		return error;

	error = add_advertise_node(queue, db, 'B');

	if (error)
		return error;

	error = add_advertise_node(queue, db, 'C');


	return error;

}

int joold_advertise(struct xlator *jool)
{
	int error = 0;

	error = validate_enabled(jool);
	if (error)
		return error;

	spin_lock_bh(&jool->nat64.joold->lock);

	sessiondb_get(jool->nat64.session);
	error = advertise(jool->nat64.joold, jool->nat64.session);
	sessiondb_put(jool->nat64.session);

	send_to_userspace(jool->nat64.joold);

	spin_unlock_bh(&jool->nat64.joold->lock);

	return error;
}

void joold_ack(struct xlator *jool)
{
	spin_lock_bh(&jool->nat64.joold->lock);

	send_to_userspace(jool->nat64.joold);

	can_send = 1;
	spin_unlock_bh(&jool->nat64.joold->lock);

}
