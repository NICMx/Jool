#ifndef SRC_USERSPACE_CLIENT_ARGP_EAMT_H_
#define SRC_USERSPACE_CLIENT_ARGP_EAMT_H_

int handle_eamt_display(int argc, char **argv);
int handle_eamt_add(int argc, char **argv);
int handle_eamt_remove(int argc, char **argv);
int handle_eamt_flush(int argc, char **argv);

void print_eamt_display_opts(char *prefix);
void print_eamt_add_opts(char *prefix);
void print_eamt_remove_opts(char *prefix);
void print_eamt_flush_opts(char *prefix);

#endif /* SRC_USERSPACE_CLIENT_ARGP_EAMT_H_ */
