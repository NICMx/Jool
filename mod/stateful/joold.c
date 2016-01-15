#include <linux/netlink.h>
#include <linux/list.h>
#include <linux/spinlock_types.h>
#include <linux/time.h>
#include <linux/jiffies.h>
#include "nat64/common/config.h"
#include "nat64/common/session.h"
#include "nat64/common/joold/joold_config.h"
#include "nat64/mod/common/types.h"
#include "nat64/mod/stateful/session/entry.h"
#include "nat64/mod/stateful/session/db.h"
#include "nat64/mod/stateful/bib/db.h"
#include "nat64/mod/common/nl/nl_sender.h"

static struct sock *sender_sk;

static DEFINE_SPINLOCK(lock_send);
static DEFINE_SPINLOCK(lock_receive);

static int session_list_elem_num = 0;
/* TODO (rob) this value should be taken from config.c. */
static int elements_limit = 20;

static struct timer_list updater_timer;

static struct list_head session_elements;

struct session_element {
	struct ipv6_transport_addr remote6;
	struct ipv6_transport_addr local6;
	struct ipv4_transport_addr local4;
	struct ipv4_transport_addr remote4;
	__be64 update_time;
	/* TODO (rob) This is wasteful. Shouldn't it be a __u8 tops? */
	__be16 is_established;
	/* TODO (rob) Ditto. */
	__be32 l4_proto;
	/* TODO (rob) Ditto. */
	__be16 state;
	char entry_magic[5];
	struct list_head nextprev;
};

static int send_msg(void *payload, size_t payload_len)
{
	struct sk_buff *skb_out;
	struct nlmsghdr *nl_hdr_out;
	int error = 0;

	log_debug("Sending multicast message!");

	skb_out = nlmsg_new(NLMSG_ALIGN(payload_len), GFP_ATOMIC);
	if (!skb_out) {
		log_debug("Failed to allocate the multicast message.");
		return -ENOMEM;
	}

	nl_hdr_out = nlmsg_put(skb_out,
			0, /* src_pid (0 = kernel) */
			0, /* seq */
			0, /* type */
			payload_len, /* payload len */
			0); /* flags */

	memcpy(nlmsg_data(nl_hdr_out), payload, payload_len);

	error = nlmsg_multicast(sender_sk, skb_out, 0, JOOLD_MULTICAST_GROUP,
			GFP_ATOMIC);
	if (error) {
		log_warn_once("Session multicast failed. (errcode %d)", error);
		return error;
	}

	log_debug("Multicast message sent!");
	return 0;
}

/*
 * TODO (rob) this is really bad, performance-wise.
 * The loop is the only thing that handles lock-needing varialbes, but we're
 * locking the entire function (packet fetching included, which can be SLOW).
 * This function should work on a "copy" of the list so we can free the
 * spinlock early.
 *
 * Because they waste CPU, spinlock domains need to be MINIMAL!
 */
static int joold_send_to_userspace(void)
{
	struct request_hdr *hdr;
	struct session_element *s_element;
	size_t total_size;
	size_t payload_size;
	void *payload;

	if (session_list_elem_num < 1)
		return 0;

	payload_size = sizeof(struct session_element) * session_list_elem_num;
	total_size = sizeof(hdr) + payload_size;

	hdr = kmalloc(total_size, GFP_ATOMIC);
	if (!hdr) {
		log_debug("Couldn't allocate memory for entries payload!");
		return -ENOMEM;
	}
	payload = hdr + 1;

	init_request_hdr(hdr, payload_size, MODE_JOOLD, 0);

	while (!list_empty(&session_elements)) {
		s_element = list_first_entry(&session_elements,
				struct session_element, nextprev);

		/*
		 * TODO (rob) This is also copying the nextprev pointer, which
		 * is a waste of packet space.
		 *
		 * Try this instead:
		 *
		 * struct session_element {
		 * 	struct ipv6_transport_addr remote6;
		 *	struct ipv6_transport_addr local6;
		 *	struct ipv4_transport_addr local4;
		 *	...
		 *	__u8 state;
		 *	char entry_magic[5];
		 * }
		 *
		 * struct joold_entry {
		 *	struct session_element element;
		 *	struct list_head nextprev;
		 * }
		 *
		 * This way you only copy the element.
		 */
		memcpy(payload, s_element, sizeof(*s_element));

		list_del(&s_element->nextprev);
		kfree(s_element);

		payload += sizeof(struct session_element);
	}

	send_msg(hdr, total_size);
	session_list_elem_num = 0;

	return 0;
}

static void send_to_userspace_timeout(unsigned long parameter)
{
	spin_lock_bh(&lock_send);
	joold_send_to_userspace();
	spin_unlock_bh(&lock_send);

	/*
	 * TODO (rob) 500 is supposed to be user-defined.
	 * sync_period below should be extracted from the config.c module.
	 */
	mod_timer(&updater_timer, jiffies + msecs_to_jiffies(500));
}

int joold_init(int sender_sock_family, int sync_period)
{
	int error;

	INIT_LIST_HEAD(&session_elements);

	error = nl_sender_init(sender_sock_family, JOOLD_MULTICAST_GROUP);
	if (error)
		return error;
	sender_sk = nl_sender_get();

	setup_timer(&updater_timer, send_to_userspace_timeout, 0);
	error = mod_timer(&updater_timer, jiffies + msecs_to_jiffies(sync_period));
	if (error)
		return error;

	return 0;
}

void joold_destroy(void)
{
	del_timer_sync(&updater_timer);
	netlink_kernel_release(sender_sk);
}

int joold_add_session_element(struct session_entry *entry)
{
	int error = 0;
	struct session_element *entry_copy;
	__u64 update_time;
	__u32 protocol;

	log_debug("Adding session entry to the list of updated entries");

	entry_copy = kmalloc(sizeof(struct session_element), GFP_ATOMIC);
	if (!entry_copy) {
		log_err("Couldn't allocate memory for session element.");
		return -ENOMEM;
	}

	entry_copy->entry_magic[0] = 'j';
	entry_copy->entry_magic[1] = 'o';
	entry_copy->entry_magic[2] = 'o';
	entry_copy->entry_magic[3] = 'l';
	entry_copy->entry_magic[4] = '\0';

	protocol = entry->l4_proto;
	log_debug("protocol %u", protocol);
	entry_copy->l4_proto = cpu_to_be32(protocol);
	log_debug("protocol %u", entry_copy->l4_proto);
	entry_copy->local4 = entry->local4;
	entry_copy->local6 = entry->local6;
	entry_copy->remote4 = entry->remote4;
	entry_copy->remote6 = entry->remote6;
	entry_copy->state = cpu_to_be16(entry->state);
	update_time = jiffies_to_msecs(jiffies - entry->update_time);
	entry_copy->update_time = cpu_to_be64(update_time);

	log_debug("jiffies %lu", jiffies);
	log_debug("is session established %d", entry_copy->is_established);
	log_debug("session update_time %lu", entry->update_time);
	log_debug("session copy update_time %llu", entry_copy->update_time);

	spin_lock_bh(&lock_send);

	list_add(&entry_copy->nextprev, &session_elements);
	session_list_elem_num++;

	if (elements_limit <= session_list_elem_num)
		error = joold_send_to_userspace();

	spin_unlock_bh(&lock_send);

	return error;
}

static int update_session(struct list_head * synch_session_elements)
{
	struct session_element * s_element;
	struct session_entry *s_entry;
	struct session_entry *s_entry_aux;
	struct tuple tuple_aux;
	struct bib_entry *b_entry;
	int error;
	__u8 bib_created = 0;
	l4_protocol protocol;
	__u32 u32_proto;
	__u16 state;
	__u64 update_time;
	bool is_established;

	while (!list_empty(synch_session_elements)) {

		error = 0;
		bib_created = 0;

		s_element = list_first_entry(synch_session_elements,struct session_element,nextprev);

		u32_proto = be32_to_cpu(s_element->l4_proto);
		protocol = u32_proto;
		state = be16_to_cpu(s_element->state);
		update_time = be64_to_cpu(s_element->update_time);
		update_time = jiffies - msecs_to_jiffies(update_time);

		if (protocol == L4PROTO_TCP) {
			is_established = state == ESTABLISHED;
		} else {
			is_established = true;
		}

		log_info("magic session element number %s", s_element->entry_magic);

		s_entry = kmalloc(sizeof(struct session_entry), GFP_ATOMIC);

		if (!s_entry) {
			log_err("Could not allocate memory for session entry!");
			goto next_session;
		}

		kref_init(&s_entry->refcounter);
		INIT_LIST_HEAD(&s_entry->list_hook);
		RB_CLEAR_NODE(&s_entry->tree6_hook);
		RB_CLEAR_NODE(&s_entry->tree4_hook);

		memcpy((void*) &s_entry->l4_proto, (void*) &protocol,
				sizeof(l4_protocol));
		memcpy((void*) &s_entry->local4, (void*) &s_element->local4,
				sizeof(s_element->local4));
		memcpy((void*) &s_entry->local6, (void*) &s_element->local6,
				sizeof(s_element->local6));
		memcpy((void*) &s_entry->remote4, (void*) &s_element->remote4,
				sizeof(s_element->remote4));
		memcpy((void*) &s_entry->remote6, (void*) &s_element->remote6,
				sizeof(s_element->remote6));

		s_entry->state = state;
		s_entry->update_time = update_time;
		s_entry->expirer = 0;

		tuple_aux.dst.addr6 = s_entry->local6;
		tuple_aux.src.addr6 = s_entry->remote6;
		tuple_aux.l4_proto = s_entry->l4_proto;
		tuple_aux.l3_proto = L3PROTO_IPV6;

		error = sessiondb_find(&tuple_aux, 0, 0, &s_entry_aux);

		if (error == -EINVAL) {
			log_err("unexpected error!");
			kfree(s_entry);
			goto next_session;
		}

		if (error == -ESRCH) {

			log_info("creating session!");

			error = bibdb_find(&tuple_aux, &b_entry);

			if (error == -EINVAL) {
				log_err("unexpected error!");
				kfree(s_entry);
				goto next_session;
			}

			if (error == -ESRCH) {
				log_info("bib entry doesnt exist. let's create one");

				b_entry = bibentry_create(&s_entry->local4, &s_entry->remote6,
				false, s_entry->l4_proto);

				if (!b_entry) {
					log_err("couldn't allocate bib entry!");
					kfree(s_entry);
					goto next_session;
				}

				bib_created = 1;
			}

			//we want to copy the value of one pointer to the other, not the content of the struct it is referencing.
			memcpy((void*) &s_entry->bib, (void*) &b_entry, sizeof(b_entry));
			log_info("entry has been copied!");
			log_info("let's see if we are getting an error.");

			if (sessiondb_add(s_entry, is_established, true)) {
				log_err("couldn't add session entry to the database!");

				if (bib_created)
					bibentry_kfree(b_entry);

				kfree(s_entry);
				goto next_session;
			}

			if (bib_created) {
				error = bibdb_add(b_entry);

				if (error == -EINVAL) {
					sessiondb_delete_by_bib(b_entry);
					log_err("couldn't add bib entry to the database!");
					bibentry_kfree(b_entry);
					goto next_session;
				}
			}

		} else {

			log_info("got session!!");

			s_entry_aux->update_time = update_time;
			log_info("is session established %d", is_established);
			log_info("update time %lu", s_entry_aux->update_time);
			log_info("jiffies %lu", jiffies);

			s_entry_aux->state = state;

			if (sessiondb_set_session_timer(s_entry_aux, is_established)) {
				log_err("Could not set session's timer!");
			}

			session_return(s_entry_aux);

			kfree(s_entry);
		}

		next_session:

		list_del(&(s_element->nextprev));
		kfree(s_element);

	}

	return 0;
}

int joold_sync_entires(__u8 *data, __u32 size)
{
	__u32 index = 0;
	struct list_head * synch_session_elements;
	struct session_element * s_element;

	/*
	 * TODO (rob) this temporal intermediary list is redundant (and creates a
	 * plethora of memory leaks; eg. the return -1 below).
	 * The sessions are right there in @data; why doesn't update_session()
	 * work directly on that?
	 */

	synch_session_elements = kmalloc(
			sizeof(struct hlist_head), GFP_ATOMIC);

	log_debug("synching entries... received size %u", size);

	INIT_LIST_HEAD(synch_session_elements);

	if (size % sizeof(struct session_element) != 0) {
		log_err(
				"Inconsistent data detected while synchronizing BIB and SESSION ");
		return -1;
	}

	while (index < size) {

		s_element = kmalloc(sizeof(*s_element), GFP_ATOMIC);

		if (!s_element) {
			log_err("Could not allocate memory for session element!");
			continue;
		}

		memcpy((__u8 *) s_element, data, sizeof(struct session_element));
		list_add(&s_element->nextprev, synch_session_elements);
		index += sizeof(struct session_element);

	}

	spin_lock_bh(&lock_receive);

	update_session(synch_session_elements);

	spin_unlock_bh(&lock_receive);

	return 0;
}

