#include <stdio.h>
#include <argp.h>
#include <sys/ioctl.h>
#include <fcntl.h>
#include <string.h>
#define MY_MACIG 'G'
#define READ_IOCTL _IOR(MY_MACIG, 0, int)
#define WRITE_IOCTL _IOW(MY_MACIG, 1, int)

const char *argp_program_version =
"static routes 1.0";

const char *argp_program_bug_address =
"<maggonzz@gmail.com>";

/* This structure is used by main to communicate with parse_opt. */
struct arguments
{
  //char *args[2];            /* ARG1 and ARG2 */
  int verbose;              /* The -v flag */
  char *string1, *string2, *string3, *dport, *sport;  /* Arguments for -a and -b */
};

/*
   OPTIONS.  Field 1 in ARGP.
   Order of fields: {NAME, KEY, ARG, FLAGS, DOC}.
*/
static struct argp_option options[] =
{
  {"verbose", 'v', 0, 0, "Produce verbose output"},
  {"protocol",   'p', "STRING1", 0,
   "Do something with PROTO related to the letter p"},
  {"source",   's', "STRING2", 0,
   "Do something with Source IP address related to the letter s"},
  {"sport",   'S', "SPORT", 0,
   "Do something with Source port related to the letter s"},
  {"destination",   'd', "STRING3", 0,
   "Do something with Destination IP address related to the letter d"},
  {"dport",   'D', "SPORT", 0,
   "Do something with Destination port related to the letter d"},
  {0}
};


/*
   PARSER. Field 2 in ARGP.
   Order of parameters: KEY, ARG, STATE.
*/
static error_t
parse_opt (int key, char *arg, struct argp_state *state)
{
  struct arguments *arguments = state->input;

  switch (key)
    {
    case 'v':
      arguments->verbose = 1;
      break;
    case 'S':
      arguments->sport = arg;
      break;
    case 'D':
      arguments->dport = arg;
      break;
    case 'p':
      arguments->string1 = arg;
      break;
    case 's':
      arguments->string2 = arg;
      break;
    case 'd':
      arguments->string3 = arg;
      break;
    default:
      return ARGP_ERR_UNKNOWN;
    }
  return 0;
}

/*
   ARGS_DOC. Field 3 in ARGP.
   A description of the non-option command-line arguments
     that we accept.
*/
static char args_doc[] = "";

/*
  DOC.  Field 4 in ARGP.
  Program documentation.
*/
static char doc[] =
"argex -- A program to demonstrate how to code command-line options and arguments.\vFrom the GNU C Tutorial.";

/*
   The ARGP structure itself.
*/
static struct argp argp = {options, parse_opt, args_doc, doc};

/*
   The main function.
   Notice how now the only function call needed to process
   all command-line options and arguments nicely
   is argp_parse.
*/
int main (int argc, char **argv)
{
  struct arguments arguments;

  /* Set argument defaults */
  arguments.string1 = "";
  arguments.string2 = "";
  arguments.string3 = "";
  arguments.verbose = 0;
  arguments.dport = "";
  arguments.sport = "";

    if(argc != 11)
    {
        printf("\n Usage : -p <protocol> -x <val1> -y <val2>\n");
	printf("%d\n", argc);
        return 1;
    }

  /* Where the magic happens */
  argp_parse (&argp, argc, argv, 0, 0, &arguments);


  char array[60];
  strcat(array,arguments.string1);
  strcat(array,"&");
  strcat(array,arguments.string2);
  strcat(array,"#");
  strcat(array,arguments.sport);
  strcat(array,"&");
  strcat(array,arguments.string3);
  strcat(array,"#");
  strcat(array,arguments.dport);
  strcat(array,"&");
  printf("%s\n",array, sizeof(array) );


	char buf[200];
	int fd = -1;
	if ((fd = open("/dev/cdev_example", O_RDWR)) < 0) {
		perror("open");
		return -1;
	}
	if(ioctl(fd, WRITE_IOCTL, array) < 0)
		perror("first ioctl");
	if(ioctl(fd, READ_IOCTL, buf) < 0)
		perror("second ioctl");

	printf("message: %s\n", buf);


  return 0;
}
