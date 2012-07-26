MODULES_DIR := /lib/modules/$(shell uname -r)
KERNEL_DIR := ${MODULES_DIR}/build
EXTRA_CFLAGS += -I$(src)/../include
EXTRA_CFLAGS += -DDEBUG

obj-m += nat64.o 
nat64-objs := nf_nat64_translate_packet.o nf_nat64_bib_session.o nf_nat64_determine_incoming_tuple.o nf_nat64_rfc6052.o nf_nat64_tuple_handling.o xt_nat64_module_conf.o xt_nat64.o

all:
	make -C ${KERNEL_DIR} M=$$PWD;
modules:
	make -C ${KERNEL_DIR} M=$$PWD $@;
modules_install:
	make -C ${KERNEL_DIR} M=$$PWD $@;
clean:
	make -C ${KERNEL_DIR} M=$$PWD $@;
