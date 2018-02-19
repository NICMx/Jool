#ifndef SRC_USERSPACE_CLIENT_ARGP_GLOBAL_H_
#define SRC_USERSPACE_CLIENT_ARGP_GLOBAL_H_

int handle_global_display(char *instance, int argc, char **argv);
int handle_global_update(char *instance, int argc, char **argv);

void print_global_display_opts(char *prefix);
void print_global_update_opts(char *prefix);

#endif /* SRC_USERSPACE_CLIENT_ARGP_GLOBAL_H_ */
