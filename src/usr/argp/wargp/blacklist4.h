#ifndef SRC_USERSPACE_CLIENT_ARGP_BLACKLIST_H_
#define SRC_USERSPACE_CLIENT_ARGP_BLACKLIST_H_

int handle_blacklist4_display(char *iname, int argc, char **argv, void *arg);
int handle_blacklist4_add(char *iname, int argc, char **argv, void *arg);
int handle_blacklist4_remove(char *iname, int argc, char **argv, void *arg);
int handle_blacklist4_flush(char *iname, int argc, char **argv, void *arg);

void autocomplete_blacklist4_display(void *args);
void autocomplete_blacklist4_add(void *args);
void autocomplete_blacklist4_remove(void *args);
void autocomplete_blacklist4_flush(void *args);

#endif /* SRC_USERSPACE_CLIENT_ARGP_BLACKLIST_H_ */
