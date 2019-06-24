#ifndef SRC_USERSPACE_CLIENT_ARGP_GLOBAL_H_
#define SRC_USERSPACE_CLIENT_ARGP_GLOBAL_H_

int handle_global_display(char *iname, int argc, char **argv, void *arg);
void autocomplete_global_display(void *args);

struct cmd_option *build_global_update_children(void);

#endif /* SRC_USERSPACE_CLIENT_ARGP_GLOBAL_H_ */
