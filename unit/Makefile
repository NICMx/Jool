MODULES_DIR := /lib/modules/$(shell uname -r)
KERNEL_DIR := ${MODULES_DIR}/build
EXTRA_CFLAGS += -DDEBUG
# If it cannot compile, install sparse or comment this line.
CC=cgcc

PKT = pkt
PKTDB = pktdb
INCOMING = incoming
FILTERING = filtering
OUTGOING = outgoing
TRANSLATE = translate
HAIRPINNING = hairpinning
SEND = send


ccflags-y := -I$(src)/../include
ccflags-y += -I$(src)/../mod


obj-m += $(FILTERING).o # $(PKT).o $(PKTDB).o $(INCOMING).o $(OUTGOING).o $(TRANSLATE).o $(SEND).o # $(HAIRPINNING).o


# Packet
$(PKT)-objs += ../mod/types.o
$(PKT)-objs += ../mod/str_utils.o
$(PKT)-objs += ../mod/ipv6_hdr_iterator.o
$(PKT)-objs += ../mod/packet.o
$(PKT)-objs += framework/unit_test.o
$(PKT)-objs += packet_test.o

# Packet DB
$(PKTDB)-objs += ../mod/types.o
$(PKTDB)-objs += ../mod/str_utils.o
$(PKTDB)-objs += ../mod/ipv6_hdr_iterator.o
$(PKTDB)-objs += ../mod/packet.o
$(PKTDB)-objs += framework/unit_test.o
$(PKTDB)-objs += framework/skb_generator.o
$(PKTDB)-objs += framework/validator.o
$(PKTDB)-objs += framework/types.o
$(PKTDB)-objs += packet_db_test.o

# Incoming tuple
$(INCOMING)-objs += ../mod/types.o
$(INCOMING)-objs += ../mod/str_utils.o
$(INCOMING)-objs += ../mod/ipv6_hdr_iterator.o
$(INCOMING)-objs += ../mod/packet.o
$(INCOMING)-objs += framework/unit_test.o
$(INCOMING)-objs += framework/skb_generator.o
$(INCOMING)-objs += framework/validator.o
$(INCOMING)-objs += framework/types.o
$(INCOMING)-objs += ../mod/packet_db.o
$(INCOMING)-objs += determine_incoming_tuple_test.o

# Filtering and Updating
$(FILTERING)-objs += filtering_and_updating_test.o

# Computing the Outgoing Tuple
$(OUTGOING)-objs += ../mod/types.o
$(OUTGOING)-objs += ../mod/str_utils.o
$(OUTGOING)-objs += ../mod/packet.o
$(OUTGOING)-objs += ../mod/ipv6_hdr_iterator.o
$(OUTGOING)-objs += ../mod/rfc6052.o
$(OUTGOING)-objs += ../mod/pool6.o
$(OUTGOING)-objs += ../mod/bib.o
$(OUTGOING)-objs += framework/unit_test.o
$(OUTGOING)-objs += compute_outgoing_tuple_test.o

# Translating the Packet
$(TRANSLATE)-objs += ../mod/types.o
$(TRANSLATE)-objs += ../mod/str_utils.o
$(TRANSLATE)-objs += ../mod/packet.o
$(TRANSLATE)-objs += ../mod/packet_db.o
$(TRANSLATE)-objs += ../mod/ipv6_hdr_iterator.o
$(TRANSLATE)-objs += framework/unit_test.o
$(TRANSLATE)-objs += framework/skb_generator.o
$(TRANSLATE)-objs += framework/validator.o
$(TRANSLATE)-objs += framework/types.o
$(TRANSLATE)-objs += framework/impersonator_send_packet.o
$(TRANSLATE)-objs += translate_packet_test.o

# Hairpinning
$(HAIRPINNING)-objs += ../mod/types.o
$(HAIRPINNING)-objs += ../mod/str_utils.o
$(HAIRPINNING)-objs += ../mod/ipv6_hdr_iterator.o
$(HAIRPINNING)-objs += ../mod/packet.o
$(HAIRPINNING)-objs += framework/unit_test.o
$(HAIRPINNING)-objs += framework/skb_generator.o
$(HAIRPINNING)-objs += framework/validator.o
$(HAIRPINNING)-objs += framework/types.o
$(HAIRPINNING)-objs += ../mod/packet_db.o
$(HAIRPINNING)-objs += handling_hairpinning_test.o

# Send packet (does not have a unit test, so just make sure it compiles.)
$(SEND)-objs += ../mod/send_packet.o



all:
	make -C ${KERNEL_DIR} M=$$PWD;
test:
	#-sudo insmod rfc6052.ko
	#-sudo rmmod rfc6052
	#-sudo insmod hashtable.ko
	#-sudo rmmod hashtable
	#-sudo insmod poolnum.ko
	#-sudo rmmod poolnum
	#-sudo insmod pool4.ko
	#-sudo rmmod pool4
	#-sudo insmod bib_session.ko
	#-sudo rmmod bib_session
	#-sudo insmod iterator.ko
	#-sudo rmmod iterator
	-sudo insmod $(PKT).ko
	-sudo rmmod $(PKT)
	-sudo insmod $(PKTDB).ko
	-sudo rmmod $(PKTDB)
	-sudo insmod $(INCOMING).ko
	-sudo rmmod $(INCOMING)
	#-sudo insmod filtering.ko
	#-sudo rmmod filtering
	-sudo insmod $(OUTGOING).ko
	-sudo rmmod $(OUTGOING)
	-sudo insmod $(TRANSLATE).ko
	-sudo rmmod $(TRANSLATE)
	#-sudo insmod $(HAIRPINNING).ko
	#-sudo rmmod $(HAIRPINNING)
	dmesg | grep 'Finished.'
modules:
	make -C ${KERNEL_DIR} M=$$PWD $@;
clean:
	make -C ${KERNEL_DIR} M=$$PWD $@;
	rm -f  ../mod/*.o  *.ko  *.o
