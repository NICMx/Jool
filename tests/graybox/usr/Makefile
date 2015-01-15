EXEC = graybox

SOURCES += communication.c
SOURCES += graybox.c
SOURCES += netlink.c

OBJS = $(SOURCES:.c=.o)

CC = gcc
CFLAGS += -Wall
CFLAGS += -g
CFLAGS += -I/usr/include/libnl3
CFLAGS += -I../include
LDFLAGS = -lnl-3

all: ${EXEC}

${EXEC}: ${OBJS}
	$(CC) $(OBJS) $(LDFLAGS) -o $@
	
%.o: %.c $(DEPS)
	$(CC) $(CFLAGS) -c -o $@ $<

clean:
	rm -f *.o ${EXEC}
