# Entrance Functions

## Initialization and destruction functions

- `common/init.c`
	- `jool_init()`: Called by the kernel when `jool_common.ko` is modprobed.
	- `jool_exit()`: Called by the kernel when `jool_common.ko` is r-modprobed.
- `nat64/jool.c`:
	- `nat64_init()`: Called by the kernel when `jool.ko` is modprobed.
	- `nat64_exit()`: Called by the kernel when `jool.ko` is r-modprobed.
- `siit/jool_siit.c`:
	- `siit_init()`: Called by the kernel when `jool_siit.ko` is modprobed.
	- `siit_exit()`: Called by the kernel when `jool_siit.ko` is r-modprobed.
- `common/kernel_hook_iptables.c`:
	- `target_checkentry()`: Called by the kernel every time the user creates an iptables/ip6tables rule that includes Jool's target (`-j JOOL` or `-j JOOL_SIIT`).

## Packet handling functions

- `common/kernel-hook-netfilter`:
	- `hook_ipv6()`: Called by the kernel every time an IPv6 packet reaches Jool's Netfilter hook.
	- `hook_ipv4()`: Called by the kernel every time an IPv4 packet reaches Jool's Netfilter hook.
- `common/kernel-hook-iptables`:
	- `target_ipv6()`: Called by the kernel every time an IPv6 packet matches one of Jool's iptables rules.
	- `target_ipv4()`: Called by the kernel every time an IPv4 packet matches one of Jool's iptables rules.
- `common/nl_handler()`:
	- `handle_jool_message()`: Called by the kernel every time one of the userspace clients (`jool` and `jool_siit`) performs a request. (ie. sends a Jool Netlink packet to the kernel.)
