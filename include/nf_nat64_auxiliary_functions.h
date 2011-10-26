/*
 * BEGIN: Packet Auxiliary Functions
 */

inline void * ip_data(struct iphdr *);
int nat64_get_l4hdrlength(u_int8_t);
int nat64_get_l3hdrlen(struct sk_buff *, u_int8_t);

/*
 * BEGIN SUBSECTION: ECDYSIS FUNCTIONS
 */

void checksum_adjust(uint16_t *, uint16_t, uint16_t, bool);
void checksum_remove(uint16_t *, uint16_t *, uint16_t *, bool);
void checksum_add(uint16_t *, uint16_t *, uint16_t *, bool);
void checksum_change(uint16_t *, uint16_t *, uint16_t, bool);
void adjust_checksum_ipv6_to_ipv4(uint16_t *, struct ipv6hdr *, 
		struct iphdr *, bool);

/*
 * END SUBSECTION: ECDYSIS FUNCTIONS
 */

/*
 * END: Packet Auxiliary Functions
 */
