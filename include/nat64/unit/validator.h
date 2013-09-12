#ifndef _NF_NAT64_VALIDATOR_H
#define _NF_NAT64_VALIDATOR_H

#include "nat64/mod/packet.h"

bool validate_fragment_count(struct packet *pkt, int expected_count);

bool validate_frag_ipv6(struct fragment *frag, int len);
bool validate_frag_ipv4(struct fragment *frag);
bool validate_frag_empty_l4(struct fragment *frag);
bool validate_frag_udp(struct fragment *frag);
bool validate_frag_tcp(struct fragment *frag);
bool validate_frag_icmp6(struct fragment *frag);
bool validate_frag_icmp4(struct fragment *frag);
bool validate_frag_payload(struct fragment *frag, u16 payload_len);

bool validate_ipv6_hdr(struct ipv6hdr *hdr, u16 payload_len, u8 nexthdr, struct tuple *tuple);
bool validate_frag_hdr(struct frag_hdr *hdr, u16 frag_offset, u16 mf, __u8 nexthdr);
bool validate_ipv4_hdr(struct iphdr *hdr, u16 total_len, u16 id, u16 df, u16 mf, u16 frag_off,
		u8 protocol, struct tuple *tuple);
bool validate_udp_hdr(struct udphdr *hdr, u16 payload_len, struct tuple *tuple);
bool validate_tcp_hdr(struct tcphdr *hdr, struct tuple *tuple);
bool validate_icmp6_hdr(struct icmp6hdr *hdr, u16 id, struct tuple *tuple);
bool validate_icmp6_hdr_error(struct icmp6hdr *hdr);
bool validate_icmp4_hdr(struct icmphdr *hdr, u16 id, struct tuple *tuple);
bool validate_icmp4_hdr_error(struct icmphdr *hdr);
bool validate_payload(unsigned char *payload, u16 len, u16 offset);
bool validate_inner_pkt_ipv6(unsigned char *payload, u16 len);
bool validate_inner_pkt_ipv4(unsigned char *payload, u16 len);

#endif
