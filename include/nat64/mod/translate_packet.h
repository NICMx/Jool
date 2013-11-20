#ifndef _NF_NAT64_TRANSLATING_THE_PACKET_H
#define _NF_NAT64_TRANSLATING_THE_PACKET_H

/**
 * @file
 * Fourth step of the Nat64 translation algorithm: "Translating the Packet", as defined in RFC6146
 * section 3.7.
 *
 * @author Alberto Leiva
 */

#include <linux/skbuff.h>
#include <linux/ip.h>
#include "nat64/comm/types.h"
#include "nat64/comm/config_proto.h"
#include "nat64/mod/packet.h"


/**
 * An accesor for the full unused portion of the ICMP header, which I feel is missing from
 * linux/icmp.h.
 */
#define icmp4_unused un.gateway


struct translation_steps {
	/**
	 * The function that will translate the layer-3 header.
	 * Its purpose if to set the variables from "out" which are prefixed by "l3_", based on the
 	 * packet described by "in".
	 */
	verdict (*l3_hdr_function)(struct tuple *tuple, struct fragment *in, struct fragment *out);
	/**
	 * The function that will translate the layer-4 header and the
	 * payload. Layer 4 and payload are combined in a single function due to their strong
	 * interdependence.
	 * Its purpose is to set the variables from "out" which are prefixed by "l4_" or "payload",
	 * based on the packet described by "in".
	 */
	verdict (*l4_hdr_and_payload_function)(struct tuple *, struct fragment *in, struct fragment *out);
	/**
	 * Post-processing involving the layer 3 header.
	 * Currently, this function fixes the header's lengths and checksum, which cannot be done in
	 * the functions above given that they generally require the packet to be assembled and ready.
	 * Not all lengths and checksums have that requirement, but just to be consistent do it always
	 * here, please.
	 * Note, out.l3_hdr, out.l4_hdr and out.payload point to garbage given that the packet has
	 * already been assembled. When you want to access the headers, use out.packet.
	 */
	verdict (*l3_post_function)(struct fragment *out);
	/**
	 * Post-processing involving the layer 4 header. See l3_post_function.
	 * This one is a little annoying because layer-4 information encompasses all of a packet's
	 * fragments, so this function has to be called separately, after all fragments have been
	 * processed.
	 */
	verdict (*l4_post_function)(struct tuple *tuple, struct packet *pkt_in, struct packet *pkt_out);
};



int translate_packet_init(void);
void translate_packet_destroy(void);

int clone_translate_config(struct translate_config *clone);
int set_translate_config(__u32 operation, struct translate_config *new_config);

verdict translating_the_packet(struct tuple *tuple, struct packet *in, struct packet *out);

verdict translate_inner_packet(struct tuple *tuple, struct fragment *in_inner,
		struct fragment *out_outer);
verdict translate(struct tuple *tuple, struct fragment *in, struct fragment **out,
		struct translation_steps *steps);


#endif /* _NF_NAT64_TRANSLATING_THE_PACKET_H */
