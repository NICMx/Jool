#ifndef SRC_USR_ARGP_WARGP_BLACKLIST_H_
#define SRC_USR_ARGP_WARGP_BLACKLIST_H_

int handle_blacklist4_display(char *iname, int argc, char **argv, void const *arg);
int handle_blacklist4_add(char *iname, int argc, char **argv, void const *arg);
int handle_blacklist4_remove(char *iname, int argc, char **argv, void const *arg);
int handle_blacklist4_flush(char *iname, int argc, char **argv, void const *arg);

void autocomplete_blacklist4_display(void const *args);
void autocomplete_blacklist4_add(void const *args);
void autocomplete_blacklist4_remove(void const *args);
void autocomplete_blacklist4_flush(void const *args);

#endif /* SRC_USR_ARGP_WARGP_BLACKLIST_H_ */
