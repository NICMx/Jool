

bool nat64_filtering_and_updating(u_int8_t l3protocol, u_int8_t l4protocol, 
	struct sk_buff *skb, struct nf_conntrack_tuple * inner);
	
struct nf_conntrack_tuple * nat64_determine_outgoing_tuple(
	u_int8_t l3protocol, u_int8_t l4protocol, struct sk_buff *skb, 
	struct nf_conntrack_tuple * inner,
	struct nf_conntrack_tuple * outgoing);

bool nat64_got_hairpin(u_int8_t l3protocol, struct nf_conntrack_tuple * outgoing);
	
struct nf_conntrack_tuple * nat64_hairpinning_and_handling(u_int8_t l4protocol, 
	struct nf_conntrack_tuple * inner,
	struct nf_conntrack_tuple * outgoing);