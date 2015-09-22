#include <stdarg.h>
#include <linux/string.h>
#include <linux/slab.h>
#include <linux/printk.h>
#include "nat64/mod/common/error_pool.h"


typedef struct error_node {
	char * msg;
	struct list_head prev_next;
} error_node;

static __u8 activated = 0;
static __u8 errors_occurred = 0;
static __u16 msg_size = 0;
static struct list_head db;
static char * msg_buffer = NULL;

void error_pool_init(void) {
    INIT_LIST_HEAD(&db) ;
}

void error_pool_activate(void) {
	activated = 1;
	msg_size = 0;
	errors_occurred = 0;
}

int error_pool_add_message(char * msg) {

    error_node * node;

	if (!activated)
		return 0;

	msg_size+= strlen(msg);
	node = kmalloc(sizeof(struct error_node),GFP_ATOMIC);

	if(!node) {
		pr_err("Could not allocate memory to store an error pool message!.") ;
		return -ENOMEM;
	}

	node->msg = kmalloc(strlen(msg)+1,GFP_ATOMIC);
	memcpy(node->msg,msg,strlen(msg)+1);

	list_add_tail(&node->prev_next,&db) ;

	node = NULL;
	node = list_first_entry(&db,error_node,prev_next);


	return 0;
}

int error_pool_get_message(char ** out_message) {

    error_node * node;
	char * buffer_pointer;

	if (!activated)
		return 0;

	(*out_message) = kmalloc(msg_size+1,GFP_ATOMIC);

	if (!(*out_message)) {
		pr_err("Could not allocate memory to return the error pool message!.") ;
		return -ENOMEM;
	}

	buffer_pointer = (*out_message);

	while (!list_empty(&db)) {
		node = list_first_entry(&db,error_node,prev_next);

		strcpy(buffer_pointer,node->msg);
		buffer_pointer+=strlen(node->msg);
		list_del(&(node->prev_next));
		kfree(node->msg);
		kfree(node);
	}
	strcpy(buffer_pointer,"\0");

	pr_err("returning message: %s",(*out_message));

	return 0;
}

void error_pool_deactivate(void) {
	if(msg_buffer)
	kfree(msg_buffer);

	msg_size = 0;
	msg_buffer = NULL;

	activated = 0;
}

int error_pool_has_errors(void) {
	return errors_occurred;
}
