#ifndef _LIBXT_NAT64_H
#define _LIBXT_NAT64_H

/* Protocol independent functions */
void nat64_tg_check(unsigned int);
void nat64_tg_help(void);

/* IPv4 Functions */
void nat64_tg4_save(const void *, const struct xt_entry_target *);
void nat64_tg4_print(const void *, const struct xt_entry_target *, int);
int nat64_tg4_parse(int, char **, int, unsigned int *, const void *,
        struct xt_entry_target **);

/* IPv6 Functions */
void nat64_tg6_save(const void *, const struct xt_entry_target *);
void nat64_tg6_print(const void *, const struct xt_entry_target *, int);
int nat64_tg6_parse(int, char **, int, unsigned int *, const void *,
        struct xt_entry_target **);

#endif /* _LIBXT_NAT64_H */
