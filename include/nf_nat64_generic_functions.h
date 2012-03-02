/*
 * BEGIN: Generic Auxiliary Functions
 */

#ifndef _NF_NAT64_GENERIC_FUNCTIONS_H
#define _NF_NAT64_GENERIC_FUNCTIONS_H

#include <net/netfilter/nf_conntrack.h>
#include <net/netfilter/nf_conntrack_core.h>
#include <net/netfilter/nf_conntrack_l3proto.h>
#include <net/netfilter/nf_conntrack_l4proto.h>
#include <net/netfilter/ipv4/nf_conntrack_ipv4.h>
#include <linux/string.h>

/*
 * Function that receives a tuple and prints it.
 */
static inline void nat64_print_tuple(const struct nf_conntrack_tuple *t)
{
	pr_debug("NAT64: print_tuple -> l3 proto = %d", t->src.l3num);
	switch(t->src.l3num) {
		case NFPROTO_IPV4:
			pr_debug("NAT64: tuple %p: %u %pI4:%hu -> %pI4:%hu",
				t, t->dst.protonum,
				&t->src.u3.ip, ntohs(t->src.u.all),
				&t->dst.u3.ip, ntohs(t->dst.u.all));
		break;
		case NFPROTO_IPV6:
			pr_debug("NAT64: tuple %p: %u %pI6: %hu -> %pI6:%hu",
				t, t->dst.protonum,
				&t->src.u3.all, t->src.u.all,
				&t->dst.u3.all, t->dst.u.all);
		break;
		default:
			pr_debug("NAT64: Not IPv4 or IPv6?");
	}
}

/*
 * strtok_r - extract tokens from strings
 * @s:  The string to be searched
 * @ct: The characters to deliminate the tokens
 * @saveptr: The pointer to the next token
 *
 * It returns the next token found outside of the @ct delimiters.
 * Multiple occurrences of @ct characters will be considered
 * a single delimiter. In other words, the returned token will
 * always have a size greater than 0 (or NULL if no token found).
 *
 * A '\0' is placed at the end of the found token, and
 * @saveptr is updated to point to the location after that.
 */
static inline char *strtokr(char *s, const char *ct, char **saveptr){
	char *ret;
	int skip;

	if (!s)
		s = *saveptr;

	/* Find start of first token */
	skip = strspn(s, ct);
	*saveptr = s + skip;

	/* return NULL if we found no token */
	if (!*saveptr[0])
		return NULL;

	/*
	 * strsep is different than strtok, where as saveptr will be NULL
	 * if token not found. strtok makes it point to the end of the string.
	 */
	ret = strsep(saveptr, ct);
	if (!*saveptr)
		*saveptr = &ret[strlen(ret)];
	return ret;
}
static inline void print_bufu(char *b){
	char *token, *saveptr1, *str1;
	int j;
	for (j = 1, str1 = b; ; j++, str1 = NULL) {
        	token = strtokr(str1, "&", &saveptr1);
       	 	if (token == NULL)
            		break;
        	printk("%d: %s\n", j, token);
	}
}

/*
 * END: Generic Auxiliary Functions
 */
 #endif
