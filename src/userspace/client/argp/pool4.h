#ifndef SRC_USERSPACE_CLIENT_ARGP_POOL4_H_
#define SRC_USERSPACE_CLIENT_ARGP_POOL4_H_

int handle_pool4_display(int argc, char **argv);
int handle_pool4_add(int argc, char **argv);
int handle_pool4_remove(int argc, char **argv);
int handle_pool4_flush(int argc, char **argv);

void print_pool4_display_opts(char *prefix);
void print_pool4_add_opts(char *prefix);
void print_pool4_remove_opts(char *prefix);
void print_pool4_flush_opts(char *prefix);

#endif /* SRC_USERSPACE_CLIENT_ARGP_POOL4_H_ */
