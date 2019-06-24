#ifndef SRC_USR_ARGP_WARGP_BIB_H_
#define SRC_USR_ARGP_WARGP_BIB_H_

int handle_bib_display(char *iname, int argc, char **argv, void *arg);
int handle_bib_add(char *iname, int argc, char **argv, void *arg);
int handle_bib_remove(char *iname, int argc, char **argv, void *arg);

void autocomplete_bib_display(void *args);
void autocomplete_bib_add(void *args);
void autocomplete_bib_remove(void *args);

#endif /* SRC_USR_ARGP_WARGP_BIB_H_ */
