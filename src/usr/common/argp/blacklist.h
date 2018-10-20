#ifndef SRC_USERSPACE_CLIENT_ARGP_BLACKLIST_H_
#define SRC_USERSPACE_CLIENT_ARGP_BLACKLIST_H_

int handle_blacklist_display(char *iname, int argc, char **argv, void *arg);
int handle_blacklist_add(char *iname, int argc, char **argv, void *arg);
int handle_blacklist_remove(char *iname, int argc, char **argv, void *arg);
int handle_blacklist_flush(char *iname, int argc, char **argv, void *arg);

void print_blacklist_display_opts(char *prefix);
void print_blacklist_add_opts(char *prefix);
void print_blacklist_remove_opts(char *prefix);
void print_blacklist_flush_opts(char *prefix);

#endif /* SRC_USERSPACE_CLIENT_ARGP_BLACKLIST_H_ */
