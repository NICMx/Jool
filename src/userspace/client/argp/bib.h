#ifndef SRC_USERSPACE_CLIENT_ARGP_BIB_H_
#define SRC_USERSPACE_CLIENT_ARGP_BIB_H_

int handle_bib_display(char *instance, int argc, char **argv);
int handle_bib_add(char *instance, int argc, char **argv);
int handle_bib_remove(char *instance, int argc, char **argv);

void print_bib_display_opts(char *prefix);
void print_bib_add_opts(char *prefix);
void print_bib_remove_opts(char *prefix);

#endif /* SRC_USERSPACE_CLIENT_ARGP_BIB_H_ */
