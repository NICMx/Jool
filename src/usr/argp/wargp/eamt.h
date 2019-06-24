#ifndef SRC_USR_ARGP_WARGP_EAMT_H_
#define SRC_USR_ARGP_WARGP_EAMT_H_

int handle_eamt_display(char *iname, int argc, char **argv, void *arg);
int handle_eamt_add(char *iname, int argc, char **argv, void *arg);
int handle_eamt_remove(char *iname, int argc, char **argv, void *arg);
int handle_eamt_flush(char *iname, int argc, char **argv, void *arg);
int handle_eamt_query(char *iname, int argc, char **argv, void *arg);

void autocomplete_eamt_display(void *args);
void autocomplete_eamt_add(void *args);
void autocomplete_eamt_remove(void *args);
void autocomplete_eamt_flush(void *args);
void autocomplete_eamt_query(void *args);

#endif /* SRC_USR_ARGP_WARGP_EAMT_H_ */
