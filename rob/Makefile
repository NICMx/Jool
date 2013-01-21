MODULES_DIR := /lib/modules/$(shell uname -r)
KERNEL_DIR := ${MODULES_DIR}/build
EXTRA_CFLAGS += -DDEBUG
EXTRA_CFLAGS += -I$(src)/../include
EXTRA_CFLAGS += -I$(src)/../mod
EXTRA_CFLAGS += -I$(src)/.

MOD_DIR = ../mod

obj-m += TESTfiltering.o
TESTfiltering-objs += nf_nat64_filtering_and_updating_test.o \
		${MOD_DIR}/nf_nat64_ipv4_pool.o \
		$(MOD_DIR)/nf_nat64_config.o \
		$(MOD_DIR)/xt_nat64_module_conf_validation.o \
		$(MOD_DIR)/nf_nat64_session.o \
		$(MOD_DIR)/nf_nat64_types.o \
		$(MOD_DIR)/nf_nat64_bib.o \
		$(MOD_DIR)/nf_nat64_rfc6052.o \
		$(MOD_DIR)/nf_nat64_static_routes.o
#~ TESTfiltering2-objs += ${MOD_DIR}/nf_nat64_ipv4_pool.o
#~ TESTfiltering2-objs += $(MOD_DIR)/xt_nat64_module_conf.o
#~ TESTfiltering2-objs += $(MOD_DIR)/xt_nat64_module_conf_validation.o
#~ TESTfiltering2-objs += $(FILTERING_DIR)/nf_nat64_session.o
#~ TESTfiltering2-objs += $(FILTERING_DIR)/nf_nat64_types.o
#~ TESTfiltering2-objs += $(FILTERING_DIR)/nf_nat64_bib.o
#~ TESTfiltering2-objs += $(FILTERING_DIR)/nf_nat64_rfc6052.o


#~ TESTfiltering-objs += $(FILTERING_DIR)/filtering_tcp.o
#~ TESTfiltering-objs += $(FILTERING_DIR)/filtering.o


all:
	make -C ${KERNEL_DIR} M=$$PWD;
modules:
	make -C ${KERNEL_DIR} M=$$PWD $@;
modules_install:
	make -C ${KERNEL_DIR} M=$$PWD $@;
clean:
	make -C ${KERNEL_DIR} M=$$PWD $@;
