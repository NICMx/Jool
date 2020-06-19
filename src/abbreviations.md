# Abbreviations

Some shortcuts used while naming variables and functions through the code or documentation:

- src = source
- dst = destination
- in = incoming (Note, not "inner")
- out = outgoing (Not "outer")

- 4to6 = translation from IPv4 to IPv6
- 6to4 = translation from IPv6 to IPv4
- alloc = memory allocation
- addr = address
- ADF = Address-Dependent Filtering
- cb = callback (synonym for "fn")
- cmp = compare (Inherited from the kernel)
- csum = checksum
- daddr = destination address
- dev = network device
- eam = Explicit Address Mapping (https://tools.ietf.org/html/rfc7757)
- eamt = EAM table
- err = error
- est = established session (inherited from RFC 6146.)
- fn = function ("this parameter is a pointer to a function.")
- FN = Fragmentation Needed (ICMPv4 error type 3 code 4)
- frag = fragment
- hdr = header
- init = initialize
- iname = instance name
  (Sorry. I don't like this one either, but "instance_name" would break too many lines.)
- inode = internal node (https://en.wikipedia.org/wiki/Tree_%28data_structure%29)
- l2 = layer 2 (link)
- l3 = layer 3 (network; IPv4 or IPv6.)
- l4 = layer 4 (transport; TCP, UDP. Also ICMP and ICMPv6 for convenience.)
- len = length
- mod = kernel module
- NIC = Network Interface Card
- nf = Netfilter (http://www.netfilter.org/)
- nl = Netlink (http://en.wikipedia.org/wiki/Netlink)
- ns = (network) namespace
- pkt = packet
- proto = protocol
- ptr = pointer
- PTB = Packet Too Big (ICMPv6 error type 2 code 0)
- rm = remove
	- "remove" stands for "take out of a database".  
	  Sometimes, this also means the entry is deleted.
	- "delete" means to actually erase the entry.  
- rtrie = radix trie (https://en.wikipedia.org/wiki/Radix_trie)
- ref = reference
- saddr = source address
- skb = socket buffer (To all intents and purposes, a packet. Inherited from the kernel)
- SO = Simultaneous Open (of TCP connections)
- taddr = Transport address (A network layer id plus a transport layer id).
- trans = transitory session (inherited from RFC 6146.)
- ttp = Translating the Packet (Fourth core step of the NAT64 translation algorithm; see RFC 6146)
- usr = user[space]
- xf = xlator framework (Netfilter or iptables)
- xt = xlator type (SIIT or NAT64)
- x<n> (where x is anything and n is 4 or 6) = x has something to do with IPv<n>. Examples:
	- pool4 = IPv4 pool
	- addr6 = IPv6 address
	- tuple6 = IPv6 tuple
- xlat = translation
- xlator = translator

When we say "payload", we mean the layer-4 payload. When we want to say layer-3 payload, we should prefix it ("l3_payload").
