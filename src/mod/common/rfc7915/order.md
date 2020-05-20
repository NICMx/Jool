Train of thought:

- In order to allocate the outgoing packet we need its length.
- Because of `lowest-ipv6-mtu`, in order to find its length we need the MTU of the outgoing interface.
- In order to find the MTU of the outgoing interface, we need the outgoing interface.
- In order to find the outgoing interface, we need to route the outgoing packet.
- To route the outgoing packet, we need to use the kernel's routing functions. (`__ip_route_output_key` and `ip6_route_output`).
- The kernel's routing functions receive flowi fields (set A) as parameters.
- Among the flowi fields (set A), there are several outgoing packet header fields. The IP addresses are among them.
- If the 6791 pool is unpopulated, then we need to route the outgoing packet (without source address) to get the source address.
- To route the outgoing packet (without source address), we need flowi fields (set B).
- Among the flowi fields (set B), we need to include the destination address, ports and some other header fields.

More constraints:

- If the packet is a PTB or FN, the ICMP header will need the MTU of the outgoing interface.
- If the packet is going to hairpin, we need to avoid routing because the routing table doesn't have a proper destination for the packet, and will most likely fail.
- In SIIT, whether we're going to hairpin or not potentially depends on the packet's internal addresses, so those need to be translated by then too.
- Addresses need to be translated before stuff like TTL because of issue #167.

Tentative dependency tree:

	Outgoing packet's allocation
		Outgoing packet's length # 4 -> 6 only
			MTU of the outgoing interface
				Outgoing interface
					Route
						Hairpinning? # If hairpin, then skip Route (notice that hairpinning is 6 -> 4 only)
						Flowi fields
							Translated source address
							Translated destination address
							Translated packet mark
								Incoming packet mark
									<Nothing>
							Translated TOS # 6 -> 4 only
								Incoming packet's traffic class
									<Nothing>
							Translated L4 protocol
								Incoming packet's L4 procotol
									<Nothing>
							Translated source port # TCP, UDP only
							Translated destination port # TCP, UDP only
							Translated ICMP type # ICMP only
							Translated ICMP code # ICMP only

Train of thought:

1. The logical placement of routing is during `sendpkt_send()`. ("Routing SHOULD happen during `sendpkt_send()`.")
2. For the sake of readability, routing SHOULD happen at the same step both in 6-to-4 and in 4-to-6.
3. However, in 4-to-6, routing MUST happen before the outgoing packet's allocation.
4. Hairpinning is another reason to postpone routing during 6-to-4. (SHOULD.)

So we have some contradictions. I believe 2 is more important than 1 and 4 because, once Jool is merged into nftables, Routing will NEED to happen during a consistent step. So, moving forward, I'd like to nail Routing right before outgoing packet allocation.

So the original packet processing algorithm (from RFC 6146):

1. Determining the incoming tuple
2. Filtering and updating binding and session information
3. Computing the outgoing tuple
4. Translating the packet
5. Handling hairpinning
6. Send packet

Needs to morph into

1. Determining the incoming tuple
2. Filtering and updating binding and session information
3. Computing the outgoing tuple
4. Translating the packet
	4.1. Computing flowi fields
	4.2. Routing the (still uncreated) translated packet
	4.3. Rest of Translating the packet
5. Handling hairpinning
6. Send packet
