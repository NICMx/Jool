#ifndef _NF_NAT64_IPV4_POOL_H
#define _NF_NAT64_IPV4_POOL_H

#define FIRST_ADDRESS "192.168.2.1"
#define LAST_ADDRESS "192.168.2.20"
#define FIRST_PORT 1024
#define LAST_PORT 65534

struct transport_addr_struct {
    char *address;
    __be16 port;
    struct list_head list;
};

__be32 next_address;
__be32 last_address;
int next_port;
int first_port;
int last_port;

struct list_head free_transport_addr;

__be32 swap_endians(__be32 be)
{
    __be32 le = ((be & 0xFF) << 24)
                      | ((be & 0xFF00) << 8)
                      | ((be >> 8) & 0xFF00)
                      | (be >> 24);
    return le;
}

char *ip_address_to_string(__be32 ip)
{
    char *result = (char *)kmalloc((sizeof(char))*INET_ADDRSTRLEN, GFP_ATOMIC);
    
    sprintf(result, "%d.%d.%d.%d",
            (ip      ) & 0xFF,
            (ip >>  8) & 0xFF,
            (ip >> 16) & 0xFF,
            (ip >> 24) & 0xFF);
    
    return result;
}


struct transport_addr_struct *get_tranport_addr(struct list_head *head)
{
    // if the list is empty
    if(list_empty(head) == 1){
        // and the next address is greater than the last address, return NULL
        if(next_address > last_address){
            return NULL;
        }
        // get the next address
        else{
            struct transport_addr_struct *new_transport_addr = (struct transport_addr_struct *)kmalloc(sizeof(struct transport_addr_struct), GFP_ATOMIC);
            
            if(new_transport_addr != NULL){
                __be32 r = swap_endians(next_address);
                
                new_transport_addr->address = ip_address_to_string(r);
                
                new_transport_addr->port = next_port++;
    
                if(next_port > last_port){
                    next_port = first_port;
                    next_address++;
                }
    
                return new_transport_addr;
            
            }else{
                return NULL;
            }
        }
    }
    // is not empty
    else{
        // get the last address of the list
        struct list_head *prev = head->prev;
        struct transport_addr_struct *transport_addr = list_entry(prev, struct transport_addr_struct, list);
        list_del(prev);
        return transport_addr;
    }
}

void return_tranpsort_addr(struct transport_addr_struct *transport_addr, struct list_head *head)
{
    INIT_LIST_HEAD(&transport_addr->list);
    list_add(&transport_addr->list, head);
}

void init_pools(void)
{
    __be32 r1,r2;
    char *add1;
    char *add2;
    
    in4_pton(FIRST_ADDRESS, -1, (u8 *)&next_address, '\x0', NULL);

    next_address = swap_endians(next_address);
    
    in4_pton(LAST_ADDRESS, -1, (u8 *)&last_address, '\x0', NULL);
    last_address = swap_endians(last_address);
        
    first_port = FIRST_PORT;
    next_port = first_port;
    last_port = LAST_PORT;
    
    r1 = swap_endians(next_address);
    r2 = swap_endians(last_address);
    
    add1 = ip_address_to_string(r1);
    add2 = ip_address_to_string(r2);
    
    INIT_LIST_HEAD(&free_transport_addr);
    
    printk(KERN_INFO "First address: %s - Last address: %s\n", add1, add2);
    printk(KERN_INFO "First port: %u - Last port: %u\n", first_port, last_port);
}

 #endif
