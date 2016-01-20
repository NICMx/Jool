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

static DEFINE_SPINLOCK( lock_send);
static DEFINE_SPINLOCK( lock_receive);

static __u8 enabled = 0;

static int session_list_elem_num;

static struct timer_list updater_timer;

static struct list_head session_elements;
struct genl_multicast_group mc_group;

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
	struct nl_core_buffer * buffer;
	log_debug("Sending multicast message!");

	error = nl_core_new_core_buffer(&buffer, payload_len);

	if (error) {
		log_err("Couldn't initialize buffer!");
		return error;
	}


	error = nl_core_write_to_buffer(buffer,payload, payload_len);

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

		memcpy(payload, &entry->element, sizeof(struct session_element));

		list_del(&entry->nextprev);
		kfree(entry);

		payload += sizeof(struct session_element);
	}

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
	copy_elements(&list, &element_num);
	spin_unlock_bh(&lock_send);

	if (element_num > 0)
	{
		joold_send_to_userspace(&list, element_num);
	}
}

static void send_to_userspace_timeout(unsigned long parameter)
{
	send_to_userspace_wrapper();

	if (enabled)
		mod_timer(&updater_timer, jiffies + msecs_to_jiffies((unsigned int) config_get_synch_elements_period()));
}

int joold_init(void)
{
	enabled = 0;

	INIT_LIST_HEAD(&session_elements);

	setup_timer(&updater_timer, send_to_userspace_timeout, 0);

	return 0;
}

void joold_update_config(void)
{

	int error;

	spin_lock_bh(&lock_send);

	if (timer_pending(&updater_timer)) {
		del_timer(&updater_timer);
	}

	if (enabled) {
		error = mod_timer(&updater_timer, jiffies+ msecs_to_jiffies((unsigned long) config_get_synch_elements_threshold()));

		if (error) {
			spin_unlock_bh(&lock_send);
			log_err("Couldn't initialize synchronization timer!");
		}
	}

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
	del_timer_sync(&updater_timer);
}

int joold_add_session_element(struct session_entry *entry)
{
	int error = 0;
	struct joold_entry *entry_copy;
	__u64 update_time;
	__u64 creation_time;

	if (enabled) {

		if (entry->l4_proto == L4PROTO_TCP  &&  jiffies_to_msecs(jiffies - entry->creation_time) < config_get_synch_elements_threshold())
			return 0;


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

		spin_unlock_bh(&lock_send);

		if (config_get_synch_elements_limit() <= session_list_elem_num)
			send_to_userspace_wrapper();

	}

	return error;
}

static int add_new_session(struct session_entry *entry, struct tuple tuple,
bool is_established)
{

	int error;
	struct bib_entry *b_entry;
	__u8 bib_created = 0;

	log_debug("creating session!");

	error = bibdb_get(&tuple, &b_entry);

	if (error == -EINVAL) {
		log_err("Unexpected error while getting bib!");
		return error;
	}

	if (error == -ESRCH) {
		log_debug("bib entry doesnt exist. let's create one");

		b_entry = bibentry_create(&entry->local4, &entry->remote6,
		false, entry->l4_proto);

		if (!b_entry) {
			log_err("couldn't allocate bib entry!");
			return -ENOMEM;
		}

		bib_created = 1;
	}

	/* we want to copy the value of one pointer to the other,
	 not the content of the struct it is referencing. */
	memcpy((void*) &entry->bib, (void*) &b_entry, sizeof(b_entry));

	if (sessiondb_add(entry, is_established, true)) {
		log_err("couldn't add session entry to the database!");

		if (bib_created)
			bibentry_kfree(b_entry);

		return -EINVAL;
	}

	if (bib_created) {
		error = bibdb_add(b_entry);

		if (error == -EINVAL) {
			sessiondb_delete_by_bib(b_entry);
			log_err("couldn't add bib entry to the database!");
			return error;
		}
	}

	return 0;

}


static struct session_entry *initialize_session_entry(
		struct session_element *element)
{

	struct session_entry *s_entry;

	l4_protocol protocol;
	__u8 state;
	__u64 update_time;
	__u64 creation_time;

	protocol = element->l4_proto;
	state = element->state;
	update_time = be64_to_cpu(element->update_time);
	update_time = jiffies - msecs_to_jiffies(update_time);
	creation_time = be64_to_cpu(element->creation_time);
	creation_time = jiffies - msecs_to_jiffies(creation_time);


	s_entry = kmalloc(sizeof(struct session_entry), GFP_ATOMIC);

	if (!s_entry) {
		log_err("Could not allocate memory for session entry!");
		return s_entry;
	}

	kref_init(&s_entry->refcounter);
	INIT_LIST_HEAD(&s_entry->list_hook);
	RB_CLEAR_NODE(&s_entry->tree6_hook);
	RB_CLEAR_NODE(&s_entry->tree4_hook);

	memcpy((void*) &s_entry->l4_proto, (void*) &protocol, sizeof(l4_protocol));
	memcpy((void*) &s_entry->local4, (void*) &element->local4,
			sizeof(element->local4));
	memcpy((void*) &s_entry->local6, (void*) &element->local6,
			sizeof(element->local6));
	memcpy((void*) &s_entry->remote4, (void*) &element->remote4,
			sizeof(element->remote4));
	memcpy((void*) &s_entry->remote6, (void*) &element->remote6,
			sizeof(element->remote6));

	s_entry->state = state;
	s_entry->update_time = update_time;
	s_entry->creation_time = creation_time;
	s_entry->expirer = 0;

	return s_entry;

}



static int update_session(struct session_element *element, int num_elements)
{

	struct session_entry *entry;
	struct session_entry *entry_aux;
	struct tuple tuple_aux;
	bool is_established;

	int error;
	int i;


	for (i = 0; i < num_elements; i++) {

		error = 0;

		entry = initialize_session_entry(element);

		if (!entry)
			goto next_session;

		if (entry->l4_proto == L4PROTO_TCP) {
			is_established = element->state == ESTABLISHED;
		} else {
			is_established = true;
		}

		tuple_aux.dst.addr6 = entry->local6;
		tuple_aux.src.addr6 = entry->remote6;
		tuple_aux.l4_proto = entry->l4_proto;
		tuple_aux.l3_proto = L3PROTO_IPV6;

		error = sessiondb_get(&tuple_aux, 0, 0, &entry_aux);

		if (error == -EINVAL) {
			log_err("unexpected error!");
			kfree(entry);
			goto next_session;
		}

		if (error == -ESRCH) {
			add_new_session(entry, tuple_aux, is_established);
		} else {
			entry_aux->update_time = entry->update_time;
			entry_aux->state = entry->state;


			if (sessiondb_set_session_timer(entry_aux, is_established)) {
				log_err("Could not set session's timer!");
			}

			session_return(entry_aux);
			kfree(entry);
		}

		next_session: element++;
	}

	return 0;
}

int joold_sync_entires(__u8 *data, __u32 size)
{
	struct session_element * s_element;
	int num_elements = size / sizeof(struct session_element);

	if (!enabled)
		return 0;

	if (size == 0 || size % sizeof(struct session_element) != 0) {
		log_err("Inconsistent data detected while synchronizing BIB and SESSION ");
		return -1;
	}

	s_element = (struct session_element *) data;

	spin_lock_bh(&lock_receive);

	update_session(s_element, num_elements);

	spin_unlock_bh(&lock_receive);

	return 0;
}

