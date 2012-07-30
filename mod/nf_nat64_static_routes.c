#include "nf_nat64_static_routes.h"
#include "nf_nat64_bib_session.h"
#include "nf_nat64_rfc6052.h"

#define MY_MACIG 'G'
#define READ_IOCTL _IOR(MY_MACIG, 0, int)
#define WRITE_IOCTL _IOW(MY_MACIG, 1, int)

static int major;
static char msg[200];
char buf[200];

static ssize_t device_read(struct file *filp, char __user *buffer, size_t length, loff_t *offset)
{
    return simple_read_from_buffer(buffer, length, offset, msg, 200);
}

static ssize_t device_write(struct file *filp, const char __user *buff, size_t len, loff_t *off)
{
    if (len > 199)
        return -EINVAL;
    copy_from_user(msg, buff, len);

    msg[len] = '\0';
    return len;
}

long device_ioctl(struct file *filep, unsigned int cmd, unsigned long arg) {

    long len = 200;
    switch(cmd) {
        case READ_IOCTL:
			//FIXME: falta regresar el valor de la pool asignado
            copy_to_user((char *)arg, "Holakern\n", 10);
            break;

        case WRITE_IOCTL:
            copy_from_user(buf, (char *)arg, len);
            nat64_add_static_route(buf);
            break;

        default:
            return -ENOTTY;
    }
    return len;

}

static struct file_operations fops = {
    .read = device_read, 
    .write = device_write,
    .unlocked_ioctl = device_ioctl
};

int nat64_create_character_device(void) {
	// // Load char device used by Miguel
    major = register_chrdev(0, "my_device", &fops);
    if (major < 0) {
        pr_debug ("NAT64: Registering the character device failed with %d\n", major);
        return major;
    }
    pr_debug("\nNAT64: cdev example: assigned major: %d\n", major);
    pr_debug("NAT64: create node with mknod /dev/cdev_example c %d 0\n", major);
    return 0;
	
}

void nat64_destroy_character_device(void){
	unregister_chrdev(major, "my_device");
}

/*
 * strtok_r - extract tokens from strings
 * @s:  The string to be searched
 * @ct: The characters to deliminate the tokens
 * @saveptr: The pointer to the next token
 *
 * It returns the next token found outside of the @ct delimiters.
 * Multiple occurrences of @ct characters will be considered
 * a single delimiter. In other words, the returned token will
 * always have a size greater than 0 (or NULL if no token found).
 *
 * A '\0' is placed at the end of the found token, and
 * @saveptr is updated to point to the location after that.
 */
static inline char *strtokr(char *s, const char *ct, char **saveptr){
	char *ret;
	int skip;

	if (!s)
		s = *saveptr;

	/* Find start of first token */
	skip = strspn(s, ct);
	*saveptr = s + skip;

	/* return NULL if we found no token */
	if (!*saveptr[0])
		return NULL;

	/*
	 * strsep is different than strtok, where as saveptr will be NULL
	 * if token not found. strtok makes it point to the end of the string.
	 */
	ret = strsep(saveptr, ct);
	if (!*saveptr)
		*saveptr = &ret[strlen(ret)];
	return ret;
}

void nat64_add_static_route(char *b){
	struct nat64_bib_entry *bib;
	char *token, *subtoken, *str1, *str2;
	char *saveptr1, *saveptr2;
	int j, ret;
	int cont = 0; 
	int proto =0;
	int con = -1;
	uint16_t p1 =0; 
	uint16_t p2=0;
	long unsigned int res;
	struct in6_addr addr1 = IN6ADDR_ANY_INIT;
	struct in6_addr addr2 = IN6ADDR_ANY_INIT;
	for (j = 1, str1 = b; ; j++, str1 = NULL) {
		token = strtokr(str1, "&", &saveptr1);
		if (token == NULL)
		    break;
		//printk("%d: %s\n", j, token);
	    	if (strcmp (token,"tcp") == 0)
	    		proto = 6;
		else if (strcmp (token,"udp") == 0)
	    		proto = 17;
		else if (strcmp (token,"icmp") == 0)
	    		proto = 1;
		for (str2 = token; ; str2 = NULL) {
			subtoken = strtokr(str2, "#", &saveptr2);
		    	if (subtoken == NULL)
		        	break;
			if (str2 == NULL){
				if (cont==0){
					kstrtoul(subtoken, 10, &res);
					//printk("port 1 %lu\n", res);
					p1 = res;
					//printk("port short %d\n", p1);
					cont++;
				} else{
					kstrtoul(subtoken, 10, &res);
					//printk("port 2 %lu\n", res);
					p2 = res;
					//printk("port short %d\n", p1);
				}
			} else {
				if (con==0){
					//inet_pton6(subtoken, &addr1.s6_addr);
					ret = in6_pton(subtoken, -1, (u8 *)&addr1.s6_addr, '\x0', NULL);
					//printk("KERN_DEBUG2 Address: %pI6 \n", &addr1.s6_addr);
				} else if (con > 0){
					//inet_pton6(subtoken, &addr2.s6_addr);
					//
					ret = in6_pton(subtoken, -1, (u8 *)&addr2.s6_addr, '\x0', NULL);
					//printk("KERN_DEBUG Address: %pI6 \n", addr2.s6_addr);
				}
			con++;
			}
		    	//printk(" --> %s\n", subtoken);
		}
	}

	//FIXME falta mandar como parametro una variable que haga que la bib/sesion no se borre 
	switch(proto) {
		case 1:
			break;
		case 6:
			//printk("port %d\n", p1);
			//printk("port %d\n", p2);
			bib = nat64_bib_session_create_tcp(&addr1,&addr2,nat64_extract_ipv4(addr2,32),ntohs(p1),ntohs(p2),proto,TCP_TRANS);
			break;
		case 17:
			bib = nat64_bib_session_create(&addr1,&addr2,nat64_extract_ipv4(addr2,32),ntohs(p1),ntohs(p2),proto,UDP_DEFAULT);
			break;
		default:
			break;

	}

}
