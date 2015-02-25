#ifndef TESTS_GRAYBOX_USR_DEVICE_H_
#define TESTS_GRAYBOX_USR_DEVICE_H_

#include "types.h"

int dev_init(void);

void dev_destroy(void);

int dev_flush(void);

int dev_add(char *dev_name, __u32 str_len);

int dev_remove(char *dev_name, __u32 str_len);

int dev_display(void);

int dev_name_filter(char *skb_dev_name);

#endif /* TESTS_GRAYBOX_USR_DEVICE_H_ */
