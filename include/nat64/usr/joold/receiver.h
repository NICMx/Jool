#ifndef RECEIVER_H
#define RECEIVER_H

int receiver_init(char * multicast_address,char * local_ip_address,char * port);
void *receiver_start(void *args);


#endif
