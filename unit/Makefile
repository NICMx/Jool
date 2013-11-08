MODULES_DIR := /lib/modules/$(shell uname -r)
KERNEL_DIR := ${MODULES_DIR}/build
EXTRA_CFLAGS += -DDEBUG -DUNIT_TESTING
# If it won't compile, install sparse or comment this line.
CC=cgcc

PKT = pkt
FRAGDB = fragdb
INCOMING = incoming
FILTERING = filtering
OUTGOING = outgoing
TRANSLATE = translate
HAIRPINNING = hairpinning
SEND = send
SENDFRAGPKT = sendFragmentedPacket


ccflags-y := -I$(src)/../include
ccflags-y += -I$(src)/../mod


obj-m +=  $(FRAGDB).o
#obj-m += $(PKT).o $(FRAGDB).o $(SEND).o $(SENDFRAGPKT).o
#obj-m += $(INCOMING).o $(FILTERING).o $(OUTGOING).o $(TRANSLATE).o $(HAIRPINNING).o

# Packet
$(PKT)-objs += ../mod/types.o
$(PKT)-objs += ../mod/str_utils.o
$(PKT)-objs += ../mod/ipv6_hdr_iterator.o
$(PKT)-objs += ../mod/packet.o
$(PKT)-objs += framework/unit_test.o
$(PKT)-objs += packet_test.o

# Packet DB
$(FRAGDB)-objs += ../mod/types.o
$(FRAGDB)-objs += ../mod/str_utils.o
$(FRAGDB)-objs += ../mod/ipv6_hdr_iterator.o
$(FRAGDB)-objs += ../mod/packet.o
$(FRAGDB)-objs += framework/unit_test.o
$(FRAGDB)-objs += framework/skb_generator.o
$(FRAGDB)-objs += framework/types.o
$(FRAGDB)-objs += fragment_db_test.o

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
$(FILTERING)-objs += ../mod/random.o
$(FILTERING)-objs += ../mod/types.o
$(FILTERING)-objs += ../mod/str_utils.o
$(FILTERING)-objs += ../mod/ipv6_hdr_iterator.o
$(FILTERING)-objs += ../mod/pool6.o
$(FILTERING)-objs += ../mod/bib.o
$(FILTERING)-objs += ../mod/session.o
$(FILTERING)-objs += ../mod/rfc6052.o
$(FILTERING)-objs += ../mod/poolnum.o
$(FILTERING)-objs += ../mod/packet.o
$(FILTERING)-objs += ../mod/packet_db.o
$(FILTERING)-objs += ../mod/send_packet.o
$(FILTERING)-objs += framework/skb_generator.o
$(FILTERING)-objs += framework/unit_test.o
$(FILTERING)-objs += framework/types.o
$(FILTERING)-objs += framework/impersonator_pool4.o
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
$(HAIRPINNING)-objs += ../mod/random.o
$(HAIRPINNING)-objs += ../mod/rfc6052.o
$(HAIRPINNING)-objs += ../mod/out_stream.o
$(HAIRPINNING)-objs += ../mod/packet.o
$(HAIRPINNING)-objs += ../mod/packet_db.o
$(HAIRPINNING)-objs += ../mod/pool6.o
$(HAIRPINNING)-objs += ../mod/bib.o
$(HAIRPINNING)-objs += ../mod/session.o
$(HAIRPINNING)-objs += ../mod/determine_incoming_tuple.o
$(HAIRPINNING)-objs += ../mod/filtering_and_updating.o
$(HAIRPINNING)-objs += ../mod/compute_outgoing_tuple.o
$(HAIRPINNING)-objs += ../mod/translate_packet.o
$(HAIRPINNING)-objs += ../mod/handling_hairpinning.o
$(HAIRPINNING)-objs += ../mod/core.o
$(HAIRPINNING)-objs += framework/unit_test.o
$(HAIRPINNING)-objs += framework/skb_generator.o
$(HAIRPINNING)-objs += framework/types.o
$(HAIRPINNING)-objs += framework/bib_session_helper.o
$(HAIRPINNING)-objs += framework/impersonator_pool4.o
$(HAIRPINNING)-objs += framework/impersonator_send_packet.o
$(HAIRPINNING)-objs += handling_hairpinning_test.o

# Send packet (does not have a unit test, so just make sure it compiles.)
$(SEND)-objs += ../mod/send_packet.o

## TODO: Move this code to somewhere else.
# Send fragmented packets
$(SENDFRAGPKT)-objs += ../mod/types.o
$(SENDFRAGPKT)-objs += ../mod/str_utils.o
$(SENDFRAGPKT)-objs += ../mod/ipv6_hdr_iterator.o
$(SENDFRAGPKT)-objs += ../mod/packet.o
$(SENDFRAGPKT)-objs += framework/unit_test.o
$(SENDFRAGPKT)-objs += framework/skb_generator.o
$(SENDFRAGPKT)-objs += framework/validator.o
$(SENDFRAGPKT)-objs += framework/types.o
$(SENDFRAGPKT)-objs += ../mod/packet_db.o
$(SENDFRAGPKT)-objs += ../mod/send_packet.o
$(SENDFRAGPKT)-objs += send_fragmented_packet.o



all:
	make -C ${KERNEL_DIR} M=$$PWD;
test:
	#-sudo insmod rfc6052.ko && sudo rmmod rfc6052 
	#-sudo insmod hashtable.ko && sudo rmmod hashtable
	#-sudo insmod poolnum.ko && sudo rmmod poolnum
	#-sudo insmod pool4.ko && sudo rmmod pool4
	#-sudo insmod bib_session.ko && sudo rmmod bib_session
	#-sudo insmod iterator.ko && sudo rmmod iterator
	#-sudo insmod $(PKT).ko && sudo rmmod $(PKT)
	-sudo insmod $(FRAGDB).ko && sudo rmmod $(FRAGDB)
	#-sudo insmod $(INCOMING).ko && sudo rmmod $(INCOMING)
	#-sudo insmod $(FILTERING).ko && sudo rmmod $(FILTERING)
	#-sudo insmod $(OUTGOING).ko & sudo rmmod $(OUTGOING)
	#-sudo insmod $(TRANSLATE).ko && sudo rmmod $(TRANSLATE)
	#-sudo insmod $(HAIRPINNING).ko && sudo rmmod $(HAIRPINNING)
	#-sudo insmod $(SENDFRAGPKT).ko && sudo rmmod $(SENDFRAGPKT)
	dmesg | grep 'Finished.'
modules:
	make -C ${KERNEL_DIR} M=$$PWD $@;
clean:
	make -C ${KERNEL_DIR} M=$$PWD $@;
	rm -f  ../mod/*.o  *.ko  *.o
