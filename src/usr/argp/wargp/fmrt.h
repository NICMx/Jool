#ifndef SRC_USR_ARGP_WARGP_FMRT_H_
#define SRC_USR_ARGP_WARGP_FMRT_H_

int handle_fmrt_display(char *iname, int argc, char **argv, void const *arg);
int handle_fmrt_add(char *iname, int argc, char **argv, void const *arg);
int handle_fmrt_rm(char *iname, int argc, char **argv, void const *arg);
int handle_fmrt_flush(char *iname, int argc, char **argv, void const *arg);

void autocomplete_fmrt_display(void const *args);
void autocomplete_fmrt_add(void const *args);
void autocomplete_fmrt_rm(void const *args);
void autocomplete_fmrt_flush(void const *args);

#endif /* SRC_USR_ARGP_WARGP_FMRT_H_ */
