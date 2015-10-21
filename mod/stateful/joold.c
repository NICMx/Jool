#include <linux/netlink.h>
#include <linux/list.h>
#include <linux/spinlock_types.h>
#include <linux/time.h>
#include <linux/jiffies.h>
#include "nat64/common/config.h"
#include "nat64/common/joold/joold_config.h"
#include "nat64/mod/common/types.h"
#include "nat64/mod/stateful/session/entry.h"
#include "nat64/mod/stateful/session/db.h"
#include "nat64/mod/stateful/bib/db.h"
#include "nat64/mod/common/nl/nl_sender.h"

static struct sock *sender_sk;
static struct request_hdr header_struct;

static DEFINE_SPINLOCK(lock);

static int session_list_elem_num = 0;
static int elements_limit = 20;

static struct timer_list updater_timer;


static struct list_head session_elements;

struct session_element {
	struct session_entry s_entry;
	bool is_established;
	bool delete;
	struct list_head nextprev;
};

static int send_msg(void *payload, int payload_len)
{
	struct sk_buff *skb_out;
	struct nlmsghdr *nl_hdr_out;

	int error = 0;

	log_debug("Sending multicast message!.");

	skb_out = nlmsg_new(NLMSG_ALIGN(payload_len), GFP_ATOMIC);
	if (!skb_out) {
		log_err("Failed to allocate a response skb to the user.");
		return -ENOMEM;
	}

	nl_hdr_out = nlmsg_put(skb_out,
			0, /* src_pid (0 = kernel) */
			0, /* seq */
			NLMSG_DONE, /* type */
			payload_len, /* payload len */
			0); /* flags */

	NETLINK_CB(skb_out).dst_group = JOOLD_MULTICAST_GROUP;

	memcpy((__u8*)nlmsg_data(nl_hdr_out),(__u8*)payload, payload_len);


	error = netlink_broadcast(sender_sk, skb_out,1,JOOLD_MULTICAST_GROUP,GFP_KERNEL);
	if (error < 0) {
		log_err("Error code %d while returning response to the user.", error);
		return error;
	}

	log_debug("Multicast message sent!.");

	return error;
}


static int joold_send_to_userspace(void) {

	struct session_element *s_element;
	__u8 * payload_pointer;
	__u16 total_size;
	__u8 * payload;

	 total_size = sizeof(header_struct)
				+ (sizeof(struct session_element) * session_list_elem_num);
	payload = kmalloc(total_size,GFP_ATOMIC);

		if (!payload) {
			log_err("Couldn't allocate memory for entries payload!.");
			return -ENOMEM;
		}


	payload_pointer = payload + sizeof(header_struct);
	header_struct.length = (sizeof(struct session_element)
			* session_list_elem_num);

	memcpy(payload, (__u8 *)&header_struct, sizeof(header_struct));

	while (!list_empty(&session_elements)) {

		s_element = list_first_entry(&session_elements,struct session_element,nextprev);

		memcpy(payload_pointer, (__u8 *) &s_element,
				sizeof(struct session_element));

		list_del(&(s_element->nextprev));

		kfree(s_element);
		payload_pointer += sizeof(struct session_element);
	}

	if (session_list_elem_num > 0) {
		send_msg(payload,total_size);
	}

	session_list_elem_num = 0;



	return 0;
}


static void send_to_userspace_timeout(unsigned long parameter) {



	spin_lock_bh(&lock);
		log_debug("executing timer's function!!");
		if (joold_send_to_userspace()) {
			log_err("An error occurred while sending session entries to userspace!.");
		}

	spin_unlock_bh(&lock);

	 if (mod_timer(&updater_timer, jiffies + msecs_to_jiffies(500))) {
		 log_err("Something went wrong while reinitializing the updater timer!.");
	 }

	 log_debug("timer's function executed!!");
}

int joold_init(int sender_sock_family, int synch_period) {

	int error;

	init_request_hdr(&header_struct, 0, 0, 0);
	INIT_LIST_HEAD(&session_elements);


	setup_timer(&updater_timer, send_to_userspace_timeout,0);

	error = mod_timer(&updater_timer, jiffies + msecs_to_jiffies(500));


	error = nl_sender_init(sender_sock_family, JOOLD_MULTICAST_GROUP);

	if (error)
		return error;


	sender_sk = nl_sender_get();

		if (error) {
			log_err("Couldn't connect the reciver socket to the kernel.");
			return error;

		}

	return 0;
}

void joold_destroy(void) {

	if (sender_sk) {
		sender_sk = NULL;
	}
}


int joold_add_session_element(struct session_entry *entry) {

	int error = 0;
	struct session_element *entry_copy;

	log_debug("Adding session entry to the list of updated entries");

		entry_copy = kmalloc(sizeof(struct session_element), GFP_ATOMIC);

		if (!entry_copy) {
			log_err("Couldn't allocate memory for session element.");
			return -ENOMEM;
		}



		memcpy(&entry_copy->s_entry, entry, sizeof(struct session_entry));

		entry_copy->is_established = sessiondb_is_session_established(entry);

		spin_lock_bh(&lock);

		list_add(&entry_copy->nextprev, &session_elements);

		session_list_elem_num++;

		log_debug("Number of added entries: %d",session_list_elem_num);

		if (elements_limit <= session_list_elem_num) {

			if (joold_send_to_userspace()) {
				error = -1;
			}

		}

		spin_unlock_bh(&lock);

	return error;

}

static int update_session(struct list_head * session_elements) {

	struct session_element * s_element;
	struct session_entry *s_entry;
	struct session_entry *s_entry_aux;
	struct tuple tuple_aux;
	struct bib_entry *b_entry;

	while (!list_empty(session_elements)) {

		s_element = list_first_entry(session_elements,struct session_element,nextprev);

		s_entry = kmalloc(sizeof(struct session_entry), GFP_ATOMIC) ;

		memcpy((__u8 *) s_entry, (__u8 *) &s_element->s_entry,
				sizeof(struct session_entry));

		tuple_aux.dst.addr6 = s_entry->local6;
		tuple_aux.src.addr6 = s_entry->remote6;
		tuple_aux.l4_proto = s_entry->l4_proto;

		b_entry = bibentry_create(&s_entry->local4, &s_entry->remote6, false,
				s_entry->l4_proto);

		if (sessiondb_get(&tuple_aux, 0, 0, &s_entry_aux)) {

			sessiondb_add(s_entry, s_element->is_established);

		} else {

			memcpy((__u8*)&s_entry_aux->local4, (__u8*)&s_entry->local4,sizeof(s_entry->local4));
			memcpy((__u8*)&s_entry_aux->local6, (__u8*)&s_entry->local6,sizeof(s_entry->local6));
			memcpy((__u8*)&s_entry_aux->remote4, (__u8*)&s_entry->remote4,sizeof(s_entry->remote4));
			memcpy((__u8*)&s_entry_aux->remote6, (__u8*)&s_entry->remote6, sizeof(s_entry->remote6));
			s_entry_aux->update_time = s_entry->update_time;
			session_return(s_entry_aux);

			kfree(s_entry);
		}

		if (bibdb_add(b_entry)) {
			kfree(b_entry);
		}

		list_del(&(s_element->nextprev));
		kfree(s_element);

	}

	return 0;
}

int joold_sync_entires(__u8 * data, __u32 size) {
	__u32 index = 0;

	struct list_head * session_elements = kmalloc(sizeof(struct hlist_head),
			GFP_ATOMIC);
	struct session_element * s_element;

	INIT_LIST_HEAD(session_elements);

	if (size % sizeof(struct session_element) != 0) {
		log_err(
				"Inconsistent data detected while synchronizing BIB and SESSION ");
		return -1;
	}

	while (index < size) {

		s_element = kmalloc(sizeof(struct session_element), GFP_ATOMIC);
		memcpy(s_element, data, sizeof(struct session_element));
		list_add(&s_element->nextprev, session_elements);
		index += sizeof(struct session_element);

	}

	spin_lock_bh(&lock);

	update_session(session_elements);

	spin_unlock_bh(&lock);

	return 0;
}

