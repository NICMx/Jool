#include <string.h>
#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>

/* This function converts from the CIDR format (e.g., 192.168.1.0/24) to
 * 'network address' and 'network mask bits' (e.g., 192.168.1.0, 24) format.
 *
 *    -Rob.
 */
int conv_from_cidr_fmt(const char *cidr_address, char **net_addr, char **net_mask_bits)
{
	char *buf = NULL;
	char *buf_ptr = NULL;

	buf = (char *) malloc (INET6_ADDRSTRLEN);	// user space
	// buf = (char *) kmalloc (INET6_ADDRSTRLEN, GFP_KERNEL); // kernel space
	buf_ptr = buf;

	strcpy(buf, cidr_address);

	(*net_addr) = strsep(&buf, "/");
	(*net_mask_bits) = strsep(&buf, "/");

	if ( (*net_addr) == NULL || (*net_mask_bits) == NULL || buf != NULL )
	{
		free(buf_ptr);		// user space
		// kfree(buf_ptr);	// kernel space
		return EXIT_FAILURE;
	}
	return EXIT_SUCCESS;	
}

int main(int argc, char *argv[])
{
	char *full_prefix = NULL;
	char *prefix = NULL;
	char *netmask = NULL; 

	if (argc != 2)
	{
		printf("Usage: %s IP_addr_in_CIDR_fmt\n", argv[0]);
		return EXIT_FAILURE;
	}
	full_prefix = argv[1];

	printf("IP address in CIDR format: %s\n", full_prefix);

	if (conv_from_cidr_fmt(full_prefix, &prefix, &netmask) == EXIT_FAILURE)
	{
		printf("Error, IP address not in CIDR format: %s\n", full_prefix);
		return EXIT_FAILURE;
	}	

	printf("network address: %s\n", prefix);	
	printf("network mask bits: %s\n", netmask);	

	return 0;
}
