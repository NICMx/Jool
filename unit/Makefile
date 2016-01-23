MODULES_DIR := /lib/modules/$(shell uname -r)
KERNEL_DIR := ${MODULES_DIR}/build
EXTRA_CFLAGS += -DDEBUG
EXTRA_CFLAGS += -DUNIT_TESTING
EXTRA_CFLAGS += -DBENCHMARK

#CC=cgcc
ccflags-y := -I$(src)/../include
ccflags-y += -I$(src)/../mod/common
ccflags-y += -I$(src)/../mod/stateful
ccflags-y += -I$(src)/../mod/stateless


ADDR = addr
ITERATOR = iterator
HASHTABLE = hashtable
RFC6052 = rfc6052
PKT = pkt
RBTREE = rbtree
POOL4DB = pool4db
BIBTABLE = bibtable
BIBDB = bibdb
SESSIONTABLE = sessiontable
SESSIONDB = sessiondb
FRAGDB = fragdb
FILTERING = filtering
TRANSLATE = translate
CONFIG_PROTO = config_proto
LOGTIME = logtime
EAMT = eamt
PALLOC = palloc4
JOOLNS = joolns


obj-m += $(ADDR).o
obj-m += $(ITERATOR).o
obj-m += $(HASHTABLE).o
obj-m += $(RFC6052).o
obj-m += $(PKT).o
obj-m += $(RBTREE).o
obj-m += $(POOL4DB).o
obj-m += $(BIBTABLE).o
obj-m += $(BIBDB).o
obj-m += $(SESSIONTABLE).o
obj-m += $(SESSIONDB).o
#obj-m += $(FRAGDB).o
obj-m += $(FILTERING).o
obj-m += $(TRANSLATE).o
obj-m += $(CONFIG_PROTO).o
obj-m += $(LOGTIME).o
obj-m += $(EAMT).o
obj-m += $(PALLOC).o
obj-m += $(JOOLNS).o


MIN_REQS = ../mod/common/types.o \
	../mod/common/address.o \
	framework/str_utils.o \
	framework/unit_test.o \
	impersonator/error_pool.o \
	impersonator/stats.o \
	impersonator/xlat.o


$(ADDR)-objs += $(MIN_REQS)
$(ADDR)-objs += address_test.o

$(ITERATOR)-objs += $(MIN_REQS)
$(ITERATOR)-objs += ipv6_hdr_iterator_test.o

$(HASHTABLE)-objs += $(MIN_REQS)
$(HASHTABLE)-objs += hash_table_test.o

$(RFC6052)-objs += $(MIN_REQS)
$(RFC6052)-objs += ../mod/common/pool6.o
$(RFC6052)-objs += rfc6052_test.o

$(PKT)-objs += $(MIN_REQS)
$(PKT)-objs += ../mod/common/packet.o
$(PKT)-objs += framework/skb_generator.o
$(PKT)-objs += framework/types.o
$(PKT)-objs += packet_test.o

$(RBTREE)-objs += $(MIN_REQS)
$(RBTREE)-objs += rbtree_test.o

$(POOL4DB)-objs += $(MIN_REQS)
$(POOL4DB)-objs += ../mod/stateful/pool4/table.o
$(POOL4DB)-objs += ../mod/stateful/pool4/entry.o
$(POOL4DB)-objs += impersonator/pool4_empty.o
$(POOL4DB)-objs += pool4db_test.o

$(BIBTABLE)-objs += $(MIN_REQS)
$(BIBTABLE)-objs += ../mod/common/rbtree.o
$(BIBTABLE)-objs += bibtable_test.o

$(BIBDB)-objs += $(MIN_REQS)
$(BIBDB)-objs += ../mod/common/rbtree.o
$(BIBDB)-objs += ../mod/stateful/bib/table.o
$(BIBDB)-objs += framework/bib.o
$(BIBDB)-objs += bibdb_test.o

$(SESSIONTABLE)-objs += $(MIN_REQS)
$(SESSIONTABLE)-objs += ../mod/common/rbtree.o
$(SESSIONTABLE)-objs += ../mod/stateful/session/entry.o
$(SESSIONTABLE)-objs += impersonator/bib.o
$(SESSIONTABLE)-objs += impersonator/joold.o
$(SESSIONTABLE)-objs += impersonator/route.o
$(SESSIONTABLE)-objs += sessiontable_test.o

$(SESSIONDB)-objs += $(MIN_REQS)
$(SESSIONDB)-objs += ../mod/common/rbtree.o
$(SESSIONDB)-objs += ../mod/stateful/session/entry.o
$(SESSIONDB)-objs += ../mod/stateful/session/table.o
$(SESSIONDB)-objs += ../mod/stateful/session/pkt_queue.o
$(SESSIONDB)-objs += framework/session.o
$(SESSIONDB)-objs += impersonator/bib.o
$(SESSIONDB)-objs += impersonator/icmp_wrapper.o
$(SESSIONDB)-objs += impersonator/joold.o
$(SESSIONDB)-objs += impersonator/route.o
$(SESSIONDB)-objs += sessiondb_test.o

$(FRAGDB)-objs += $(MIN_REQS)
$(FRAGDB)-objs += ../mod/common/config.o
$(FRAGDB)-objs += ../mod/common/ipv6_hdr_iterator.o
$(FRAGDB)-objs += ../mod/common/packet.o
$(FRAGDB)-objs += framework/skb_generator.o
$(FRAGDB)-objs += framework/types.o
$(FRAGDB)-objs += fragment_db_test.o

$(FILTERING)-objs += $(MIN_REQS)
$(FILTERING)-objs += ../mod/common/config.o
$(FILTERING)-objs += ../mod/common/packet.o
$(FILTERING)-objs += ../mod/common/namespace.o
$(FILTERING)-objs += ../mod/common/pool6.o
$(FILTERING)-objs += ../mod/common/rbtree.o
$(FILTERING)-objs += ../mod/common/rfc6052.o
$(FILTERING)-objs += ../mod/stateful/impersonator.o
$(FILTERING)-objs += ../mod/stateful/pool4/entry.o
$(FILTERING)-objs += ../mod/stateful/pool4/table.o
$(FILTERING)-objs += ../mod/stateful/pool4/db.o
$(FILTERING)-objs += ../mod/stateful/bib/table.o
$(FILTERING)-objs += ../mod/stateful/bib/db.o
$(FILTERING)-objs += ../mod/stateful/session/entry.o
$(FILTERING)-objs += ../mod/stateful/session/table.o
$(FILTERING)-objs += ../mod/stateful/session/db.o
$(FILTERING)-objs += ../mod/stateful/session/pkt_queue.o
$(FILTERING)-objs += framework/skb_generator.o
$(FILTERING)-objs += framework/types.o
$(FILTERING)-objs += impersonator/icmp_wrapper.o
$(FILTERING)-objs += impersonator/port_allocator.o
$(FILTERING)-objs += impersonator/joold.o
$(FILTERING)-objs += impersonator/pool4_empty.o
$(FILTERING)-objs += impersonator/route.o
$(FILTERING)-objs += filtering_and_updating_test.o

$(TRANSLATE)-objs += $(MIN_REQS)
$(TRANSLATE)-objs += ../mod/common/config.o
$(TRANSLATE)-objs += ../mod/common/ipv6_hdr_iterator.o
$(TRANSLATE)-objs += ../mod/common/packet.o
$(TRANSLATE)-objs += ../mod/common/pool6.o
$(TRANSLATE)-objs += ../mod/common/rfc6052.o
$(TRANSLATE)-objs += ../mod/common/rfc6145/common.o
$(TRANSLATE)-objs += ../mod/stateful/impersonator.o
$(TRANSLATE)-objs += framework/skb_generator.o
$(TRANSLATE)-objs += framework/types.o
$(TRANSLATE)-objs += impersonator/icmp_wrapper.o
$(TRANSLATE)-objs += translate_packet_test.o

$(CONFIG_PROTO)-objs += $(MIN_REQS)
$(CONFIG_PROTO)-objs += ../mod/common/config.o
$(CONFIG_PROTO)-objs += config_test.o

$(LOGTIME)-objs += $(MIN_REQS)
$(LOGTIME)-objs += log_time_test.o

$(EAMT)-objs += $(MIN_REQS)
$(EAMT)-objs += ../mod/common/rtrie.o
$(EAMT)-objs += eamt_test.o

$(PALLOC)-objs += $(MIN_REQS)
$(PALLOC)-objs += impersonator/bib.o
$(PALLOC)-objs += impersonator/pool4.o
$(PALLOC)-objs += impersonator/rfc6145.o
$(PALLOC)-objs += port_allocator_test.o

$(JOOLNS)-objs += $(MIN_REQS)
$(JOOLNS)-objs += ../mod/common/config.o
$(JOOLNS)-objs += ../mod/common/namespace.o
$(JOOLNS)-objs += ../mod/common/rbtree.o
$(JOOLNS)-objs += ../mod/common/rtrie.o
$(JOOLNS)-objs += ../mod/stateless/blacklist4.o
$(JOOLNS)-objs += ../mod/stateless/eam.o
$(JOOLNS)-objs += ../mod/stateless/json_parser.o
$(JOOLNS)-objs += ../mod/stateless/pool.o
$(JOOLNS)-objs += ../mod/stateless/rfc6791.o
$(JOOLNS)-objs += ../mod/stateful/bib/table.o
$(JOOLNS)-objs += ../mod/stateful/bib/db.o
$(JOOLNS)-objs += ../mod/stateful/pool4/entry.o
$(JOOLNS)-objs += ../mod/stateful/pool4/table.o
$(JOOLNS)-objs += ../mod/stateful/pool4/db.o
$(JOOLNS)-objs += ../mod/stateful/session/entry.o
$(JOOLNS)-objs += ../mod/stateful/session/table.o
$(JOOLNS)-objs += ../mod/stateful/session/db.o
$(JOOLNS)-objs += ../mod/stateful/session/pkt_queue.o
$(JOOLNS)-objs += impersonator/icmp_wrapper.o
$(JOOLNS)-objs += impersonator/joold.o
$(JOOLNS)-objs += impersonator/pool4_empty.o
$(JOOLNS)-objs += impersonator/route.o
$(JOOLNS)-objs += joolns_test.o


all:
	make -C ${KERNEL_DIR} M=$$PWD;
test:
	-sudo insmod $(ADDR).ko && sudo rmmod $(ADDR)
	-sudo insmod $(ITERATOR).ko && sudo rmmod $(ITERATOR)
	-sudo insmod $(HASHTABLE).ko && sudo rmmod $(HASHTABLE)
	-sudo insmod $(RFC6052).ko && sudo rmmod $(RFC6052)
	-sudo insmod $(PKT).ko && sudo rmmod $(PKT)
	-sudo insmod $(RBTREE).ko && sudo rmmod $(RBTREE)
	-sudo insmod $(POOL4DB).ko && sudo rmmod $(POOL4DB)
	-sudo insmod $(BIBDB).ko && sudo rmmod $(BIBDB)
	-sudo insmod $(SESSIONDB).ko && sudo rmmod $(SESSIONDB)
	-sudo insmod $(FRAGDB).ko && sudo rmmod $(FRAGDB)
	-sudo insmod $(FILTERING).ko && sudo rmmod $(FILTERING)
	-sudo insmod $(TRANSLATE).ko && sudo rmmod $(TRANSLATE)
	-sudo insmod $(CONFIG_PROTO).ko && sudo rmmod $(CONFIG_PROTO)
	#-sudo insmod $(LOGTIME).ko && sudo rmmod $(LOGTIME)
	-sudo insmod $(EAMT).ko && sudo rmmod $(EAMT)
	dmesg | grep 'Finished.'
modules:
	make -C ${KERNEL_DIR} M=$$PWD $@;
clean:
	make -C ${KERNEL_DIR} M=$$PWD $@;
	rm -f  ../mod/*.o  *.ko  *.o
