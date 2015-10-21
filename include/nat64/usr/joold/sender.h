#ifndef SENDER_H
#define SENDER_H

int sender_init(char * multicast_address, char * multicast_port);
void *sender_start(void *args);

#endif
