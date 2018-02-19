#ifndef SRC_USERSPACE_CLIENT_ARGP_EAMT_H_
#define SRC_USERSPACE_CLIENT_ARGP_EAMT_H_

int handle_eamt_display(char *instance, int argc, char **argv);
int handle_eamt_add(char *instance, int argc, char **argv);
int handle_eamt_remove(char *instance, int argc, char **argv);
int handle_eamt_flush(char *instance, int argc, char **argv);

void print_eamt_display_opts(char *prefix);
void print_eamt_add_opts(char *prefix);
void print_eamt_remove_opts(char *prefix);
void print_eamt_flush_opts(char *prefix);

#endif /* SRC_USERSPACE_CLIENT_ARGP_EAMT_H_ */
