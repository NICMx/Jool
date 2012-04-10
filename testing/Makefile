CC = gcc
CFLAGS = -Wall
LDFLAGS += -lnl	# para netlink library : libnl

# aqui va la lista de archivos .c que se quieren compilar 
all: netlink_client

# esta regla es para compilar individualmente con: make nombre_archivo
%.o: %.c
	$(CC) -c $(CFLAGS) $(CPPFLAGS) $< -o $@

clean:
	rm -f *.o


