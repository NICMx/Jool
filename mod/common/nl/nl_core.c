#include <linux/skbuff.h>
#include <linux/module.h>
#include <linux/sort.h>
#include <linux/version.h>
#include <net/netlink.h>
#include <net/net_namespace.h>

#include "nat64/mod/common/types.h"
#include "nat64/common/config.h"


struct sock *nl_create_socket(int sock_family, unsigned int sock_group, void (*callback)(struct sk_buff *skb))
{

	struct sock * nl_socket;

			/*
				 * The function changed between Linux 3.5.7 and 3.6, and then again from 3.6.11 to 3.7.
				 *
				 * If you're reading the kernel's Git history, that appears to be the commit
				 * a31f2d17b331db970259e875b7223d3aba7e3821 (v3.6-rc1~125^2~337) and then again in
				 * 9f00d9776bc5beb92e8bfc884a7e96ddc5589e2e (v3.7-rc1~145^2~194).
				 */
			#if LINUX_VERSION_CODE < KERNEL_VERSION(3, 6, 0)
				nl_socket = netlink_kernel_create(&init_net, sock_family, sock_group, callback,
						NULL, THIS_MODULE);
			#elif LINUX_VERSION_CODE < KERNEL_VERSION(3, 7, 0)
				struct netlink_kernel_cfg nl_cfg = { .input  = callback, .groups=sock_group };
				nl_socket = netlink_kernel_create(&init_net, sock_family, THIS_MODULE, &nl_cfg);
			#else
				struct netlink_kernel_cfg nl_cfg = { .input  = callback, .groups=sock_group };
				nl_socket = netlink_kernel_create(&init_net, sock_family, &nl_cfg);
			#endif

				if (nl_socket) {
					log_debug("Netlink socket created.");

				} else {
					log_err("Creation of netlink socket failed.\n"
							"(This usually happens because you already "
							"have a Jool instance running.)\n"
							"I will ignore this error. However, you will "
							"not be able to configure Jool via the "
							"userspace application.");
				}

		return nl_socket;

}
