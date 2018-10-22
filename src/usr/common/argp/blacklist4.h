#ifndef SRC_USERSPACE_CLIENT_ARGP_BLACKLIST_H_
#define SRC_USERSPACE_CLIENT_ARGP_BLACKLIST_H_

int handle_blacklist4_display(char *iname, int argc, char **argv, void *arg);
int handle_blacklist4_add(char *iname, int argc, char **argv, void *arg);
int handle_blacklist4_remove(char *iname, int argc, char **argv, void *arg);
int handle_blacklist4_flush(char *iname, int argc, char **argv, void *arg);

void print_blacklist4_display_opts(char *prefix);
void print_blacklist4_add_opts(char *prefix);
void print_blacklist4_remove_opts(char *prefix);
void print_blacklist4_flush_opts(char *prefix);

#endif /* SRC_USERSPACE_CLIENT_ARGP_BLACKLIST_H_ */
