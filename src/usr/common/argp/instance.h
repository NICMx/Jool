#ifndef SRC_USERSPACE_CLIENT_ARGP_INSTANCE_H_
#define SRC_USERSPACE_CLIENT_ARGP_INSTANCE_H_

int handle_instance_display(char *instance, int argc, char **argv, void *arg);
int handle_instance_add(char *instance, int argc, char **argv, void *arg);
int handle_instance_remove(char *instance, int argc, char **argv, void *arg);
int handle_instance_flush(char *instance, int argc, char **argv, void *arg);

void print_instance_display_opts(char *prefix);
void print_instance_add_opts(char *prefix);
void print_instance_remove_opts(char *prefix);
void print_instance_flush_opts(char *prefix);

#endif /* SRC_USERSPACE_CLIENT_ARGP_INSTANCE_H_ */
