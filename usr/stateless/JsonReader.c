#include "nat64/common/JsonReader.h"
#include "nat64/common/JsonReaderCommon.h"


static int do_parsing(char * buffer);
static int parse_siit_json(cJSON * json_structure);
static int parse_siit_global(cJSON * global_json);
static int parse_siit_pool6(cJSON * pool6_json);
static int parse_siit_eamt(cJSON * eamt_json);
static int parse_siit_blacklist(cJSON * blacklist_json);
static int parse_siit_pool6791(cJSON * pool6791_json);

static int send_buffers();
static int send_global_buffer();
static int send_pool6_buffer();
static int send_eamt_buffer();
static int send_blacklist_buffer();
static int send_pool6791_buffer();
static int send_multipart_request_buffer(__u8*buffer,__u16 request_len, __u16 section);

#ifdef DEBUG

static int print_config();
static int print_global();
static int print_pool6();
static int print_eamt();
static int print_blacklist();
static int print_pool6791();

#endif

static struct global_bits * configured_parameters;
static __u16 num_items_mtu_plateaus=0;

static __u8 send_global = 0;
static struct global_config * global;

static __u8 send_pool6 = 0;
static struct ipv6_prefix * pool6_entry;

static __u8 send_eamt = 0;
static __u16 eamt_items_num = 0;
static __u8 * eamt_buffer;

static __u8 send_blacklist = 0;
static __u16 blacklist_items_num = 0;
static __u8 * blacklist_buffer;

static __u8 send_pool6791 = 0;
static __u16 pool6791_items_num = 0;
static __u8 * pool6791_buffer;


extern int parse_file(char * fileName)
{
	FILE * file = fopen(fileName, "rb");

	long length;
	long read_bytes = 0;
	char * buffer = 0;

	int error = 0;

	if (file) {

		fseek(file, 0, SEEK_END);
		length = ftell(file);
		fseek(file, 0, SEEK_SET);
		buffer = malloc(length);

		if (buffer) {

			while (read_bytes < length) {
				read_bytes+= fread(&buffer[read_bytes], 1, length, file);
			}
		}

		fclose(file);

	} else {
		printf("%s", "File not found!");
		error = -1;
	}

	if (buffer) {
		error = do_parsing(buffer);
	} else {
		printf("%s", "No buffer!");
		error = -1;
	}

	return error;
}


static int do_parsing(char * buffer)
{
	int error = 0;

	cJSON * json_structure = cJSON_Parse(buffer);

	if (json_structure) {

		cJSON * file_type = cJSON_GetObjectItem(json_structure, "File_Type");

		if (file_type) {
			if (strcmp(file_type->valuestring, "SIIT") != 0) {
				log_err("El valor - %s - del atributo FILE_TYPE no es válido.",file_type->valuestring);
				return 1;
			}
		} else {
			return 1;
		}

		log_info("parsing file...");
		error = parse_siit_json(json_structure);

		if (!error) {

			log_info("file parsed!!.");
			#ifdef DEBUG
			error = print_config();
			if (error) {
				log_err("Something went wrong while trying to print the configuration!.");
				return 1;
			}
			#endif


			error = send_buffers();
			if (error) {
				log_err("Something went wrong while trying to send the buffers to the kernel!.");
				return 1;
			}

			return 0;
		}

		log_info("file parsed with errors!!.");
		return 1;

	} else {
		log_err("Something went wrong while trying to parse the file!. ->  %s", cJSON_GetErrorPtr());
		return 1;
	}

	return 0;
}

static int parse_siit_json(cJSON * json_structure)
{
	int error = 0;
	char * section_name = "Global";

	cJSON * global = cJSON_GetObjectItem(json_structure, section_name);
	error = parse_siit_global(global);

	if (error) {
		return error;
	}

	cJSON * pool6_json = cJSON_GetObjectItem(json_structure, "Pool6");
	error = parse_siit_pool6(pool6_json);

	if (error) {
		return error;
	}

	cJSON * eamt_json = cJSON_GetObjectItem(json_structure, "EAMT");
	error = parse_siit_eamt(eamt_json);

	if (error) {
		return error;
	}

	cJSON * blacklist_json = cJSON_GetObjectItem(json_structure, "Blacklist");
	error = parse_siit_blacklist(blacklist_json);

	if (error) {
		return error;
	}

	cJSON * pool6791_json = cJSON_GetObjectItem(json_structure, "Pool6791");
	error = parse_siit_pool6791(pool6791_json);

	return error;
}

static int parse_siit_global(cJSON * global_json)
{
	int error = 0;
	cJSON * read_value;

	//We verify that the bitfield structure, that tells which parameters are initialized, dont be already allocated, if so, we free it.
	if (configured_parameters)
		free(configured_parameters);

	configured_parameters  = malloc(sizeof(struct global_bits));


	if (global_json) {

		send_global = 1;

		global = (struct global_config *) malloc(sizeof(struct global_config));

		//Reading manually-enabled
		error = parse_bool_parameter(global_json, "manually-enabled", "Global",
						&configured_parameters->manually_enabled,&global->is_disable);
		if (error) {
			return error;
		}


		//Reading drop-icmpv6-info.
		error = parse_bool_parameter(global_json, "drop-icmpv6-info", "Global",
						&configured_parameters->drop_icmpv6_info,&global->nat64.drop_icmp6_info) ;
		if (error) {
			return error;
		}

		//Reading zeroize-traffic-class.
		error = parse_bool_parameter(global_json, "zeroize-traffic-class", "Global",
						&configured_parameters->zeroize_traffic_class,&global->reset_traffic_class) ;
		if (error) {
			return error;
		}


		//Reading override-tos.
		error = parse_bool_parameter(global_json, "override-tos", "Global",
						&configured_parameters->override_tos,&global->reset_tos) ;
		if (error) {
			return error;
		}



		//Reading tos.
		error = parse_u8_parameter(global_json, "tos", "Global",
					 	 &configured_parameters->tos, &global->new_tos);
		if (error) {
			return error;
		}


		//Reading amend-udp-checksum-zero.
		error = parse_bool_parameter(global_json, "amend-udp-checksum-zero", "Global",
					&configured_parameters->amend_udp_checksum_zero, &global->siit.compute_udp_csum_zero);
		if (error) {
			return error;
		}



		//Reading randomize-rfc6791-addresses.
		error = parse_bool_parameter(global_json, "randomize-rfc6791-addresses", "Global",
							&configured_parameters->randomize_rfc6791_addresses, &global->siit.randomize_error_addresses) ;

		if (error) {
			return error;
		}


		//Se intenta leer el parámetro mtu-plateaus.
		read_value = cJSON_GetObjectItem(global_json, "mtu-plateaus") ;
		configured_parameters->mtu_plateaus = 0;

		int i;
		num_items_mtu_plateaus = 0;


		if (read_value) {
			cJSON * mtu_item = read_value->child;


			while (mtu_item) {
				mtu_item = mtu_item->next;
				num_items_mtu_plateaus++;
			}

			global->mtu_plateaus = malloc(sizeof(__u16)*num_items_mtu_plateaus) ;

			__u16 value;
			mtu_item = read_value->child;

			for (i=0 ; i < num_items_mtu_plateaus; i++) {
				error = str_to_u16(mtu_item->valuestring,&value,0,3000) ;

				if (error) {
					log_err("mtu-plateaus, not valid!. Global: %s", read_value->valuestring) ;
					return 1;
				}

				global->mtu_plateaus[i] = value;
				mtu_item = mtu_item->next;
			}

			configured_parameters->mtu_plateaus = 1;
		}

	}

	return 0;
}
static int parse_siit_pool6(cJSON * pool6_json)
{
	int error = 0;
	//ver cual va a ser el valor por default si es que habra alguno.
	struct ipv6_prefix pool6_value;

	if (pool6_json) {
		send_pool6 = 1;
		pool6_entry = malloc(sizeof(struct ipv6_prefix));

		error = str_to_ipv6_prefix(pool6_json->valuestring,&pool6_value);
		if (!error) {
			pool6_entry->address = pool6_value.address;
			pool6_entry->len = pool6_value.len;
		} else {
			log_err("Pool6 value not valid!.: %s",pool6_json->valuestring);
			return 1;
		}

	}

	return 0;

}
static int parse_siit_eamt(cJSON * eamt_json)
{
	__u8 i = 0;
	int error = 0;
	eamt_items_num = 0;
	if (eamt_json) {

		send_eamt = 1;
		cJSON * item = eamt_json->child;

		while (item) {
			eamt_items_num+=1;
			item = item->next;
		}

		eamt_buffer = malloc(sizeof(__u8)*eamt_items_num*22) ;
		item = eamt_json->child;

		cJSON * ipv6_prefix_item;
		struct ipv6_prefix ipv6_value;

		cJSON * ipv4_prefix_item;
		struct ipv4_prefix ipv4_value;

		for (i = 0; i < eamt_items_num;i++) {

			ipv6_prefix_item = cJSON_GetObjectItem(item, "ipv6_prefix");

			if (!ipv6_prefix_item) {
				log_err("EAMT item #%d does not contain an ipv6_prefix.",(i+1));
				return 1;
			}

			ipv4_prefix_item = cJSON_GetObjectItem(item, "ipv4_prefix");

			if (!ipv4_prefix_item) {
				log_err("EAMT item #%d does not contain an ipv4_prefix.",(i+1));
				return 1;
			}

			error = str_to_ipv6_prefix(ipv6_prefix_item->valuestring,&ipv6_value);

			if (error) {
				log_err("Ipv6 Prefix, not valid!. EAMT item: #%d",(i+1)) ;
				return 1;
			}


			error = str_to_ipv4_prefix(ipv4_prefix_item->valuestring,&ipv4_value) ;

			if (error) {
				log_err("Ipv4 Prefix, not valid!. EAMT item: #%d",(i+1)) ;
				return 1;
			}

			memcpy(&eamt_buffer[i*22],(__u8*)(&ipv6_value.address),16);
			memcpy(&eamt_buffer[(i*22)+16],(&ipv6_value.len),1);

			memcpy(&eamt_buffer[(i*22)+17],(__u8*)(&ipv4_value.address),4);
			memcpy(&eamt_buffer[(i*22)+21],(&ipv4_value.len),1);

			item = item->next;
		}
	}
	return 0;
}

static int parse_siit_blacklist(cJSON * blacklist_json)
{
	int error = 0;
	int i = 0;

	if (blacklist_json) {

		send_blacklist = 1;
		cJSON * item = blacklist_json->child;

		while (item) {
			blacklist_items_num+=1;
			item = item->next;
		}

		blacklist_buffer = malloc(sizeof(__u8)*blacklist_items_num*5) ;
		item = blacklist_json->child;

		struct ipv4_prefix ipv4_value;

		for (i=0; i < blacklist_items_num; i++) {

			error = str_to_ipv4_prefix(item->valuestring, &ipv4_value) ;

			if (error) {
				log_err("Ipv4 Prefix, not valid. Blacklist item: %s", item->valuestring) ;
				return 1;
			}

			memcpy(&blacklist_buffer[i*5] ,(__u8*)&ipv4_value.address,4);
			memcpy(&blacklist_buffer[(i*5)+4] ,(__u8*)&ipv4_value.len,1);

			item = item->next;
		}
	}

	return 0;
}
static int parse_siit_pool6791(cJSON * pool6791_json)
{
	int error = 0;
	int i = 0;

	if (pool6791_json) {

		send_pool6791 = 1;
		cJSON * item = pool6791_json->child;

		while (item) {
			pool6791_items_num+=1;
			item = item->next;
		}

		item = pool6791_json->child;
		pool6791_buffer = malloc(sizeof(__u8)*eamt_items_num*5) ;
		struct ipv4_prefix ipv4_value;

		for (i=0; i < pool6791_items_num;i++) {

			error = str_to_ipv4_prefix(item->valuestring,&ipv4_value) ;
			if (error) {
				log_err("Ipv4 Prefix, not valid!. Pool6791 item: %s", item->valuestring) ;
				return 1;
			}

			memcpy(&pool6791_buffer[i*5] ,(__u8*)&ipv4_value.address,4);
			memcpy(&pool6791_buffer[(i*5)+4] ,(__u8*)&ipv4_value.len,1);

			item = item->next;
		}

	}
	return 0;
}


static int send_buffers()
{
	int error = 0;

	error = send_multipart_request_buffer(0,0, SEC_INIT) ;

	if(send_global)
		error = send_global_buffer();

	if(error)
		goto error_happened;

	if(send_pool6)
		error = send_pool6_buffer();

	if(error)
		goto error_happened;

	if(send_eamt)
		error = send_eamt_buffer();

	if(error)
		goto error_happened;

	if(send_blacklist)
		error = send_blacklist_buffer();

	if(error)
		goto error_happened;

	if(send_pool6791)
		error = send_pool6791_buffer();

	if(error)
		goto error_happened;


	error = send_multipart_request_buffer(0,0,SEC_COMMIT) ;

	if(error)
		goto error_happened;


	return 0;

	error_happened:
	return error;
}
static int send_global_buffer()
{
	int error = 0;
	int index = 0;

	__u8 global_parameters_buffer[41];
	__u8 plateaus_value[2];

	memcpy(global_parameters_buffer,(__u8*)(configured_parameters),32) ;
	index+=32;


	if (configured_parameters->manually_enabled) {
		memcpy(&global_parameters_buffer[index],&global->is_disable,1);
	}

	index+=1;

	if (configured_parameters->drop_icmpv6_info) {
		memcpy(&global_parameters_buffer[index],&global->nat64.drop_icmp6_info,1);
	}

	index+=1;

	if (configured_parameters->zeroize_traffic_class) {
		memcpy(&global_parameters_buffer[index],&global->reset_traffic_class,1);
	}

	index+=1;

	if (configured_parameters->override_tos) {
		memcpy(&global_parameters_buffer[index],&global->reset_tos,1);
	}

	index+=1;

	if (configured_parameters->tos) {
		memcpy(&global_parameters_buffer[index],&global->new_tos,1);
	}

	index+=1;

	if (configured_parameters->amend_udp_checksum_zero) {
		memcpy(&global_parameters_buffer[index],&global->siit.compute_udp_csum_zero,1);
	}

	index+=1;

	if (configured_parameters->randomize_rfc6791_addresses) {
		memcpy(&global_parameters_buffer[index],&global->siit.randomize_error_addresses,1);
	}

	index+=1;

	memcpy(&global_parameters_buffer[index],(__u8*)&num_items_mtu_plateaus,2);
	error = send_multipart_request_buffer(global_parameters_buffer,41,SEC_GLOBAL) ;
	log_info("Global buffer has been sent.");


	if (error) {

		log_err("Something went wrong while sending Global Parameters to the kernel!.") ;
		return error;
	}

	index+=2;
	int i;

	log_info("Sending %d mtu-plateaus-items", num_items_mtu_plateaus) ;


	if (configured_parameters->mtu_plateaus) {
		for (i=0 ; i < num_items_mtu_plateaus; i++) {
			memcpy(plateaus_value,(__u8*)&(global->mtu_plateaus[i]),2) ;
			error = send_multipart_request_buffer(plateaus_value,2,SEC_GLOBAL) ;

			if (error) {
				log_err("Something went wrong while sending a mtu-plateaus element to the kernel!.");
				return error;
			}

		}
	}

	return 0;

}
static int send_pool6_buffer()
{
	int error = 0;

	error = send_multipart_request_buffer((__u8*)&pool6_entry->address,16,SEC_POOL6) ;
	if (error) {
		log_err("Something went wrong while sending the pool6 prefix address to the kernel!.");
		return error;
	}

	error = send_multipart_request_buffer(&pool6_entry->len,
			1,SEC_POOL6) ;

	if (error) {
		log_err("Something went wrong while sending the pool6 prefix segment to the kernel!.");
		return error;
	}

	return error;
}
static int send_eamt_buffer()
{
	int error = 0;

	int page_size = getpagesize();
	int eamt_entry_size= EAMT_ENTRY_SIZE;

	int buffer_size = (page_size-sizeof(struct request_hdr)-sizeof(struct nlmsghdr)-100);
	int entries_per_message =  (buffer_size-2)/ eamt_entry_size;

	__u8 eamt_kernel_buffer[buffer_size];
	__u8 * kernel_buffer_pointer;



	error = send_multipart_request_buffer((__u8*)&eamt_items_num,2,SEC_EAMT) ;

	if(error) {
		log_err("Something went wrong while sending the eamt entries number to the kernel!.");
		return error;
	}

	log_info("Sending eamt entries to the kernel!.");
	log_info("Eamt buffer size: %d",buffer_size) ;
	log_info("Eamt page size: %d", page_size);

	int items_sent = 0;
	int items_sent_in_message = 0;
	int i;
	int real_index = 0;

	while (items_sent < eamt_items_num) {
		kernel_buffer_pointer = eamt_kernel_buffer;
		kernel_buffer_pointer += 2;

		for (i=0; (i < entries_per_message) && real_index < eamt_items_num; i++) {

			memcpy(&kernel_buffer_pointer[0],&eamt_buffer[real_index*eamt_entry_size],16);
			memcpy(&kernel_buffer_pointer[16],&eamt_buffer[(real_index*eamt_entry_size)+16],1);
			memcpy(&kernel_buffer_pointer[17],&eamt_buffer[(real_index*eamt_entry_size)+17],4);
			memcpy(&kernel_buffer_pointer[21],&eamt_buffer[(real_index*eamt_entry_size)+21],1);


			kernel_buffer_pointer +=eamt_entry_size;
			real_index++;
		}

		//We add the number of elements to send at the beginning of the buffer.
		items_sent_in_message = real_index - items_sent;
		memcpy(eamt_kernel_buffer,(__u8*)&items_sent_in_message,2);

		items_sent = real_index;

		error = send_multipart_request_buffer(eamt_kernel_buffer,buffer_size,SEC_EAMT) ;
		if (error) {
			log_err("Something went wrong while sending eamt entries to the kernel!.");
			return error;
		}
	}

	return error;
}
static int send_blacklist_buffer()
{
	int error = 0;

	__u8 entry_size = BLACKLIST_ENTRY_SIZE;
	__u32 page_size = getpagesize();
	__u32 buffer_size = (page_size-sizeof(struct request_hdr)-sizeof(struct nlmsghdr)-100);
	__u32 entries_per_message =  (buffer_size-2)/ entry_size;

	__u8 blacklist_kernel_buffer[buffer_size];
	__u8 * kernel_buffer_pointer;



	error = send_multipart_request_buffer((__u8*)&blacklist_items_num,2,SEC_BLACKLIST) ;
	if (error) {
		log_err("Something went wrong while sending the blacklist entries number to the kernel!.");
		return error;
	}

	__u16 items_sent = 0;
	__u16 items_sent_in_message = 0;
	__u16 i;
	__u16 real_index = 0;

	log_info("blacklist entries num: %d",blacklist_items_num) ;
	log_info("blacklist entries per message: %d", entries_per_message) ;

	while (items_sent < blacklist_items_num) {
		kernel_buffer_pointer = blacklist_kernel_buffer;
		kernel_buffer_pointer += 2;

		for (i=0; i < entries_per_message && real_index < blacklist_items_num;i++) {
			memcpy(kernel_buffer_pointer,(__u8*)&blacklist_buffer[real_index*entry_size],4);
			memcpy(&kernel_buffer_pointer[4],(__u8*)&blacklist_buffer[real_index*entry_size+4],1);
			kernel_buffer_pointer+=entry_size;
			real_index++;
		}

		items_sent_in_message = real_index - items_sent;

		memcpy(blacklist_kernel_buffer,(__u8*)&items_sent_in_message,2);
		items_sent = real_index;

		log_info("blacklist items sent in message: %d", items_sent_in_message) ;
		log_info("blacklist items sent: %d", items_sent) ;

		error = send_multipart_request_buffer(blacklist_kernel_buffer,buffer_size,SEC_BLACKLIST) ;
		if (error) {
			log_err("Something went wrong while sending blacklist entries to the kernel!.");
			return -1;
		}
	}

	return error;
}
static int send_pool6791_buffer()
{
	int error = 0;

	__u8 entry_size = POOL6791_ENTRY_SIZE;
	__u32 page_size = getpagesize();
	__u32 buffer_size = (page_size-sizeof(struct request_hdr)-sizeof(struct nlmsghdr)-100);
	__u32 entries_per_message =  (buffer_size-2)/ entry_size;

	__u8 pool6791_kernel_buffer[buffer_size];
	__u8 * kernel_buffer_pointer = pool6791_kernel_buffer;



	error = send_multipart_request_buffer((__u8*)&pool6791_items_num,2,SEC_POOL6791) ;
	if (error) {
		log_err("Something went wrong while sending the pool6791 entries number to the kernel!.");
		return error;
	}

	__u16 items_sent = 0;
	__u16 items_sent_in_message = 0;
	__u16 i;
	__u16 real_index = 0;

	while (items_sent < pool6791_items_num) {
		kernel_buffer_pointer = pool6791_kernel_buffer;

		kernel_buffer_pointer += 2;

		for (i=0; i < entries_per_message && real_index < pool6791_items_num;i++) {
			memcpy(kernel_buffer_pointer,&pool6791_buffer[real_index*entry_size],4);
			memcpy(&kernel_buffer_pointer[4] ,&pool6791_buffer[real_index*entry_size+4],1);
			kernel_buffer_pointer+=entry_size;
			real_index++;
		}

		items_sent_in_message = real_index - items_sent;

		memcpy(pool6791_kernel_buffer,(__u8*)&items_sent_in_message,2);
		items_sent = real_index;


		error = send_multipart_request_buffer(pool6791_kernel_buffer,buffer_size,SEC_POOL6791) ;

		if (error) {
			log_err("Something went wrong while sending a Pool6791 entries to the kernel!.");
			return error;
		}
	}
	return error;
}


static int send_multipart_request_buffer(__u8*buffer,__u16 request_len, __u16 section)
{
	__u32 real_length = request_len +2;
	__u8 * buffer_to_send = malloc(sizeof(struct request_hdr)+real_length);
	__u8 * section_pointer = (__u8*)&section;

	struct request_hdr * request_pointer = (struct request_hdr *)buffer_to_send;

	init_request_hdr(request_pointer, real_length, MODE_PARSE_FILE, OP_UPDATE);

	buffer_to_send += sizeof(*request_pointer);

	buffer_to_send[0] = section_pointer[0];
	buffer_to_send[1] = section_pointer[1];

	if(request_len > 0)
		memcpy(&buffer_to_send[2],buffer,request_len);

	return netlink_request(request_pointer, sizeof(*request_pointer)+2,NULL, NULL);
}

#ifdef DEBUG

static int print_config()
{
	int error = 0;
	error = print_global();

	if (error) {
		log_info("error while trying to print global section.");
	}

	error = print_pool6();

	if (error) {
		log_info("error while trying to print pool6 section.");
	}
	error = print_eamt();

	if (error) {
		log_info("error while trying to print eamt section.");
	}
	error = print_blacklist();

	if (error) {
		log_info("error while trying to print blacklist section.");
	}

	error = print_pool6791();

	if (error) {
		log_info("error while trying to print pool6791 section.");
	}

	return 0;
}
static int print_global()
{

	if (configured_parameters->manually_enabled) {
		log_info("manually-enabled: %s", (!global->is_disable) ? "true" : "false") ;
	}

	if (configured_parameters->drop_icmpv6_info) {
		log_info("drop-icmpv6-info: %s", global->nat64.drop_icmp6_info ? "true" : "false") ;

	}

	if (configured_parameters->zeroize_traffic_class) {
		log_info("zeroize-traffic-class: %s", global->reset_traffic_class ? "true" : "false") ;
	}


	if (configured_parameters->override_tos) {
		log_info("override-tos: %s", global->reset_tos ? "true" : "false") ;
	}


	if (configured_parameters->tos) {
		log_info("tos: %u", global->new_tos) ;
	}

	if (configured_parameters->amend_udp_checksum_zero) {
		log_info("amend-udp-checksum-zero: %s", global->siit.compute_udp_csum_zero ? "true" : "false") ;
	}


	if (configured_parameters->randomize_rfc6791_addresses) {
		log_info("randomize-rfc6791-addresses: %s", global->siit.randomize_error_addresses ? "true" : "false") ;
	}



	int i;

	log_info ("mtu-plateaus-items Number: %u", num_items_mtu_plateaus) ;

	if (configured_parameters->mtu_plateaus) {

		for (i=0 ; i < num_items_mtu_plateaus; i++) {
			log_info("mtu-plateaus-item #%d: %u",i,global->mtu_plateaus[i]) ;
		}
	}

	return 0;
}
static int print_pool6()
{
	if(pool6_entry) {
		char ipv6_str[32];
		if (!inet_ntop(AF_INET6,&pool6_entry->address,ipv6_str,32)) {
			log_err("error while trying to print pool6!.");
			return 1;
		}
		log_info("Pool6: %s/%u", ipv6_str,pool6_entry->len) ;
	}

	return 0;
}
static int print_eamt()
{
	int i;
	struct ipv6_prefix ipv6_value;
	char ipv6_str[32];

	struct ipv4_prefix ipv4_value;
	char ipv4_str[16];

	log_info("Printing eamt-items...") ;
	log_info("----------------------") ;
	log_info("eamt-items Ammount: %u", num_items_mtu_plateaus) ;

	for (i = 0; i < eamt_items_num;i++) {

		memcpy((__u8*)(&ipv6_value.address),&eamt_buffer[i*22],16);
		memcpy((&ipv6_value.len),&eamt_buffer[(i*22)+16],1);

		if (!inet_ntop(AF_INET6,&(ipv6_value.address),ipv6_str,32)) {
			log_err("error while trying to get Ipv6 address from eamt item #%d.",(i+1));
			return 1;
		}

		memcpy(&eamt_buffer[(i*22)+17],(__u8*)(&ipv4_value.address),4);
		memcpy(&eamt_buffer[(i*22)+21],(&ipv4_value.len),1);

		if (!inet_ntop(AF_INET,&(ipv4_value.address),ipv4_str,16)) {
			log_err("error while trying to get Ipv4 address from eamt item #%d.",(i+1));
			return 1;
		}

		log_info("eamt item #%d:",(i+1));
		log_info("Ipv6 value: %s/%u ",ipv6_str,ipv6_value.len);
		log_info("Ipv4 value: %s/%u ",ipv4_str,ipv4_value.len);
		log_info("---------------------");

	}
	return 0;

}
static int print_blacklist()
{
	int i = 0;

	log_info("Printing blacklist-items...") ;
	log_info("---------------------------") ;
	log_info("blacklist-items Ammount: %u", blacklist_items_num) ;

	struct ipv4_prefix ipv4_value;
	char ipv4_str[16];
	for (i=0; i < blacklist_items_num; i++) {
		memcpy((__u8*)&ipv4_value.address,&blacklist_buffer[i*5],4);
		memcpy((__u8*)&ipv4_value.len,&blacklist_buffer[(i*5)+4],1);

		if (!inet_ntop(AF_INET,&(ipv4_value.address),ipv4_str,16)) {
			log_err("error while trying to get Ipv4 address from blacklist item #%d.",(i+1));
			return 1;
		}

		log_info("blacklist item #%d:",(i+1));
		log_info("Ipv4 value: %s/%u",ipv4_str,ipv4_value.len);
		log_info("---------------------");
	}

	return 0;

}
static int print_pool6791()
{
	int i=0;

	log_info("Printing blacklist-items...") ;
	log_info("---------------------------") ;
	log_info("pool6791-items Ammount: %u", blacklist_items_num) ;

	struct ipv4_prefix ipv4_value;
	char ipv4_str[16];
	for (i=0; i < pool6791_items_num;i++) {
		memcpy((__u8*)&ipv4_value.address,&pool6791_buffer[i*5],4);
		memcpy((__u8*)&ipv4_value.len,&pool6791_buffer[(i*5)+4],1);

		if (!inet_ntop(AF_INET,&(ipv4_value.address),ipv4_str,16)) {
			log_err("error while trying to get Ipv4 address from pool6791 item #%d.",(i+1));
			return 1;
		}

		log_info("pool6791 item #%d:",(i+1));
		log_info("Ipv4 value: %s/%u",ipv4_str,ipv4_value.len);
		log_info("---------------------");

	}

	return 0;
}

#endif
