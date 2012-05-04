CC = gcc
CFLAGS = -Wall

all: client server

%.o: %.c
	$(CC) -c $(CFLAGS) $(CPPFLAGS) $< -o $@

clean:
	rm -f *.o

