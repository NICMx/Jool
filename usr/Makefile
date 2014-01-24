CC=gcc
LD=ld

VERSION = 3.1.0
PROGRAM = jool

CFLAGS = -c -Wall -I../include -I/usr/include/libnl3 -DVERSION=$(VERSION) -DPROG=$(PROGRAM)
LDFLAGS = -lnl-3

OBJECTS=str_utils.o netlink.o pool6.o pool4.o bib.o session.o filtering.o translate.o fragmentation.o jool.o 
SOURCE=str_utils.c netlink.c pool6.c pool4.c bib.c session.c filtering.c translate.c fragmentation.c jool.c

all: $(SOURCE)
	$(CC) $(CFLAGS) $(SOURCE)
	$(CC) $(OBJECTS) $(LDFLAGS) -o $(PROGRAM)
clean:
	rm -f $(OBJECTS) $(PROGRAM)
