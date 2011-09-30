#ifndef _LINUX_NETFILTER_LIBXT_NAT64_H
#define _LINUX_NETFILTER_LIBXT_NAT64_H

/* Protocol independent functions */
static void nat64_tg_check(unsigned int);
static void nat64_tg_help(void);

/* IPv4 Functions */
static void nat64_tg4_save(const void *, const struct xt_entry_target *);
static void nat64_tg4_print(const void *, const struct xt_entry_target *, int);
static int nat64_tg4_parse(int, char **, int, unsigned int *, const void *,
		struct xt_entry_target **);

/* IPv6 Functions */
static void nat64_tg6_save(const void *, const struct xt_entry_target *);
static void nat64_tg6_print(const void *, const struct xt_entry_target *, int);
static int nat64_tg6_parse(int, char **, int, unsigned int *, const void *,
		struct xt_entry_target **);
	
#endif /* _LINUX_NETFILTER_LIBXT_NAT64_H */
