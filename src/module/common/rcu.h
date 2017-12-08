#ifndef _JOOL_MOD_RCU_H
#define _JOOL_MOD_RCU_H

/**
 * @file
 * RCU primitives which are lacking from the kernel's headers.
 * http://stackoverflow.com/questions/32360052
 */

#define list_for_each_rcu_bh(pos, head) \
	for (pos = rcu_dereference_bh(list_next_rcu(head));	\
	     pos != head;					\
	     pos = rcu_dereference_bh(list_next_rcu(pos)))

#define hlist_for_each_rcu_bh(pos, head) \
	for (pos = rcu_dereference_bh(hlist_first_rcu(head));	\
	     pos;						\
	     pos = rcu_dereference_bh(hlist_next_rcu(pos)))

#endif /* _JOOL_MOD_RCU_H */
