#ifndef SRC_USR_ARGP_WARGP_P4BLOCK_H_
#define SRC_USR_ARGP_WARGP_P4BLOCK_H_

int handle_p4block_display(char *iname, int argc, char **argv, void const *arg);
int handle_p4block_add(char *iname, int argc, char **argv, void const *arg);
int handle_p4block_remove(char *iname, int argc, char **argv, void const *arg);

void autocomplete_p4block_display(void const *args);
void autocomplete_p4block_add(void const *args);
void autocomplete_p4block_remove(void const *args);

#endif /* SRC_USR_ARGP_WARGP_P4BLOCK_H_ */
