#include "nat64/mod/common/json_parser.h"
#include "nat64/mod/stateful/bib/entry.h"
static struct pool4_entry
{
	__u32 mark;
	struct ipv4_prefix *prefix;
	struct port_range *ports;
};





static int init_configuration(void);
static int init_members(void);
static int handle_global_config(__u8*request, __u32 length);
static void handle_global_parameters(__u8 * request, __u32 length);
static int handle_mtu_plateaus_entry(__u8 * request, __u32 length);
static int handle_pool6_config(__u8*request, __u32 length);
static int handle_pool4_config(__u8*request, __u32 length);
static int handle_pool4_entry(__u8*request, __u32 length);
static int handle_bib_config(__u8*request, __u32 length);
static int save_configuration(void);
static void free_members_on_error(void);
static void free_members(void);
static void end_configuration(void);


static __u8 initialized = 0;
static union global_bits * configured_parameters;
static struct global_config * global;

static struct ipv6_prefix * pool6_entry;

static __u16 mtu_plateaus_entries_num = 0;
static __u16 mtu_plateaus_entries_received = 0;
static __u16 * plateaus_entries_buffer;

static __u16 pool4_entries_num = 0;
static __u16 pool4_entries_received = 0;
static struct pool4_entry * pool4_entries_buffer;

static __u16 bib_entries_num = 0;
static __u16 bib_entries_received = 0;
static struct bib_entry * bib_entries_buffer;


static int init_configuration(void)
{
	int error = 0;

	free_members();
	error = init_members();
	if(error)
	{
		log_err("Error while trying to initialize members.");
		return error;
	}
	initialized = 1;

	return error;
}
static int init_members(void)
{

	mtu_plateaus_entries_num = 0;
	mtu_plateaus_entries_received = 0;

	pool4_entries_num = 0;
	pool4_entries_received = 0;

	bib_entries_num = 0;
	bib_entries_received = 0;

	free_members();

	global = kmalloc(sizeof(struct global_config),GFP_ATOMIC) ;

	if(!global)
	{
		log_err("An error occurred while trying to allocate memory for Global parameters!.");
		return -ENOMEM;
	}



	config_clone(global);

	pool6_entry = kmalloc(sizeof(struct ipv6_prefix), GFP_ATOMIC) ;

	if(!pool6_entry)
	{
		log_err("An error occurred while trying to allocate memory for Pool6 entry!.");
		return -ENOMEM;
	}

	return 0;
}
static void free_members(void)
{
	if(configured_parameters)
	kfree(configured_parameters);

	global = NULL;

	if(pool6_entry)
	kfree(pool6_entry);

	if(plateaus_entries_buffer)
	kfree(plateaus_entries_buffer) ;

	if(bib_entries_buffer)
	kfree(bib_entries_buffer);

	if(pool4_entries_buffer)
	kfree(pool4_entries_buffer);
}
static void free_members_on_error(void)
{
	if(configured_parameters)
	kfree(configured_parameters);

	if(global)
	kfree(global);

	if(pool6_entry)
	kfree(pool6_entry);

	if(plateaus_entries_buffer)
	kfree(plateaus_entries_buffer) ;

	if(bib_entries_buffer)
	kfree(bib_entries_buffer);

	if(pool4_entries_buffer)
	kfree(pool4_entries_buffer);
}
static void end_configuration(void)
{
	free_members();
	initialized = 0;
}


int handle_json_file_config(struct nlmsghdr *nl_hdr,struct request_hdr *jool_hdr,__u8*request)
{
	int error = 0;
	__u16 request_type = *((__u16 *) request);
	__u32 length = jool_hdr->length - (sizeof(struct request_hdr));

	request = request + 2;


	log_info("the length is: %d", length);

	if(request_type == SEC_INIT)
	{
		return init_configuration();
	}


	if(initialized)
	{
		switch(request_type)
		{
			case SEC_GLOBAL: error = handle_global_config(request,length);
			break;

			case SEC_POOL6: error = handle_pool6_config(request,length);
			break;

			case SEC_POOL4: error = handle_pool4_config(request,length) ;
			break;

			case SEC_BIB: error = handle_bib_config(request,length) ;
			break;

			case SEC_DONE: error = save_configuration();
			end_configuration();
			break;
		}

		if(error)
		{
		  log_err("An error occured configuration transaction will be ended.");
		  free_members_on_error();
		  initialized = 0;
		}
	}
	else
	{
		log_err("Configuration transaction has not been initialized!.") ;
		return -EINVAL;
	}
	return error;
}
static int handle_global_config(__u8*request, __u32 length)
{
	int error = 0;
	switch(length)
	{
		//If length is 2 bytes in size we assume that we are receiving an mtu-plateaus item.
		case 2: error = handle_mtu_plateaus_entry(request, length) ;
		break;

		//If length is 64 bytes in size we assume that we are receiving the global configuration parameters whithout the mtu-plateaus items.
		case 64: handle_global_parameters(request, length) ;
		break;

		//We don't know what it is.
		default: log_err("Unrecognized configuration request for Global section.");
			error = -EINVAL;
		break;
	}
	return 0;
}
static void handle_global_parameters(__u8 * request, __u32 length)
{

	   int index = 0;


	   memcpy((__u8*)(&configured_parameters->as_int),request,4) ;


	        index+=4;

	   		if(configured_parameters->as_fields.manually_enabled) {
	   		   memcpy(&global->is_disable,&request[index],1);
	   		}

	   		index+=1;


	   		if(configured_parameters->as_fields.address_dependent_filtering)
	   		{
	   		   memcpy(&global->nat64.drop_by_addr,&request[index],1) ;
	   		}

	   		index+=1;


	   		if(configured_parameters->as_fields.drop_icmpv6_info)
	   		{

	   		   memcpy(&global->nat64.drop_icmp6_info,&request[index],1) ;
	   		}

	   		index+=1;


	   		if(configured_parameters->as_fields.drop_externally_initiated_tcp)
	   		{
	   		 memcpy(&global->nat64.drop_external_tcp,&request[index],1) ;
	   		}

	   		index+=1;


	   		if(configured_parameters->as_fields.udp_timeout)
	   		{
	   		memcpy(&global->nat64.ttl.udp,&request[index],8) ;
	   		}

	   		index+=8;


	   		if(configured_parameters->as_fields.tcp_est_timeout) {

	   	    	memcpy(&global->nat64.ttl.tcp_est,&request[index],8) ;
	   		}

	   		index+=8;


	   		if(configured_parameters->as_fields.tcp_trans_timeout)
	   		{
	   		memcpy(&global->nat64.ttl.tcp_trans,&request[index],8) ;
	   		}

	   		index+=8;


	   		if(configured_parameters->as_fields.icmp_timeout)
	   		{
	   		   memcpy(&global->nat64.ttl.icmp,&request[index],8) ;
	   		}

	   		index+=8;


	   		if(configured_parameters->as_fields.fragment_arrival_timeout)
	   		{
	  		   memcpy(&global->nat64.ttl.frag,&request[index],8) ;
	   		}

	   		index+=8;


	   		if(configured_parameters->as_fields.maximum_simultaneous_opens)
	   		{
	   		   memcpy(&global->nat64.max_stored_pkts,&request[index],8) ;
	   		}

	   		index+=8;


	   		if(configured_parameters->as_fields.source_icmpv6_errors_better)
	   		{
	   		   memcpy(&global->nat64.src_icmp6errs_better,&request[index],1) ;
	   		}

	   		index+=1;


	   		if(configured_parameters->as_fields.logging_bib)
	   		{
	   		   memcpy(&global->nat64.bib_logging,&request[index],1) ;
	   		}

	   		index+=1;


	   		if(configured_parameters->as_fields.logging_session)
	   		{
	   		   memcpy(&global->nat64.session_logging,&request[index],1) ;
	   		}

	   		index+=1;


	   		if(configured_parameters->as_fields.zeroize_traffic_class)
	   		{
	  		   memcpy(&global->reset_traffic_class,&request[index],1) ;
	   		}

	   		index+=1;


	   		if(configured_parameters->as_fields.override_tos)
	   		{
	   			memcpy(&global->reset_tos,&request[index],1) ;
	   		}

	   		index+=1;


	   		if(configured_parameters->as_fields.tos)
	   		{
	   			memcpy(&global->new_tos,&request[index],1) ;
	   		}

	   		index+=1;

	   		memcpy((__u8*)&mtu_plateaus_entries_num,&request[index],2) ;

}
static int handle_mtu_plateaus_entry(__u8 * request, __u32 length)
{
	if(!configured_parameters)
	{
		log_err("configured_parameters flags were not initialized!.");
		return -EINVAL;
	}
	if(!configured_parameters->as_fields.mtu_plateaus)
	{
		log_err("an attemp to add an mtu-plateaus item whit the configuration flag set to false was made!.");
		return -EINVAL;
	}

	if(mtu_plateaus_entries_received < mtu_plateaus_entries_num)
	{
		memcpy((__u8*)&plateaus_entries_buffer[mtu_plateaus_entries_received],request,2);
		mtu_plateaus_entries_received++;
	}
	else
	{
		log_err("The Number of mtu-plateaus entries recieved is bigger than the number of allocated entries") ;
		return -EINVAL;
	}

	return 0;

}
static int handle_pool6_config(__u8*request, __u32 length)
{
	switch(length)
	{
		case 16:memcpy((__u8*)&pool6_entry->address,request,16);
		break;

		case 1:memcpy(&pool6_entry->len,request,1);
		break;

		default: log_err("Unrecognized configuration request for Pool6 section.");
		break;
	}
	return 0;
}
static int handle_pool4_config(__u8*request, __u32 length)
{
	switch(length)
	{
		case 2:memcpy((__u8*)&pool4_entries_num,request,2);

		if(pool4_entries_buffer)
			kfree(pool4_entries_buffer);

		pool4_entries_buffer = kmalloc(sizeof(struct pool4_entry)*pool4_entries_num,GFP_ATOMIC) ;

		if(!pool4_entries_buffer)
		{
			log_err("An error ocurred while trying to allocate memory for pool4 entries");
			return -ENOMEM;
		}

		break;

		default: handle_pool4_entry(request,length) ;
		break;
	}

	return 0;
}

static int handle_pool4_entry(__u8*request, __u32 length)
{
	int error = 0;
	int i;

	__u8 * request_pointer = request;

	__u16 entries_number = 0;
	__u8 bytes_to_skip = 4;

	__u8 boolean_value = 0;



	if(error)
	{
		log_err("Received Pool4 entries are not valid!");
		return error;
	}

	request += bytes_to_skip;

	if(pool4_entries_received < pool4_entries_num)
	{
		for(i = 0; i < entries_number &&  pool4_entries_received < pool4_entries_num; i++)
		{
			boolean_value =  request[0];

			if(boolean_value)
			{
				memcpy((__u8*)&pool4_entries_buffer[pool4_entries_received].mark,&request[1],4);
			}

			boolean_value = request[5];

			pool4_entries_buffer[pool4_entries_received].ports = kmalloc(sizeof(struct port_range),GFP_ATOMIC) ;

			if(!pool4_entries_buffer[pool4_entries_received].ports)
			{
				log_err("An error occurred while trying to allocate memory for a pool4 entry's ports!.");
				return -ENOMEM;
			}

			if(boolean_value)
			{
				  memcpy((__u8*)&pool4_entries_buffer[pool4_entries_received].ports->min,&request[6],2);
				  memcpy((__u8*)&pool4_entries_buffer[pool4_entries_received].ports->max,&request[8],2);
			}

			boolean_value = request[10];

			if(!boolean_value){
				log_err("prefix is not configured and it is expected!");
				return -EINVAL;
			}

			pool4_entries_buffer[pool4_entries_received].prefix = kmalloc(sizeof(struct ipv4_prefix),GFP_ATOMIC) ;

			if(!pool4_entries_buffer[pool4_entries_received].prefix)
			{
				log_err("An error occurred while trying to allocate memory for a pool4 entry's ipv4 prefix.") ;
				return -ENOMEM;
			}

			memcpy((__u8*)&pool4_entries_buffer[pool4_entries_received].prefix->address,&request[11],4);
			pool4_entries_buffer[pool4_entries_received].prefix->len = request[15];

			pool4_entries_received++;
			request+=POOL4_ENTRY_SIZE;
		}
	}
	else
	{
		log_err("The Number of Pool4 entries recieved is bigger than the number of allocated entries") ;
		return -EINVAL;
	}


	return 0;
}

static int handle_bib_config(__u8*request, __u32 length)
{
	switch(length)
	{
		case 2:memcpy((__u8*)&bib_entries_num,request,2);

		if(bib_entries_buffer)
			kfree(bib_entries_buffer);

		bib_entries_buffer = kmalloc(sizeof(struct bib_entry)*bib_entries_num,GFP_ATOMIC) ;

		if(!bib_entries_buffer)
		{
			log_err("An error occured while trying to allocate memory for bib entries buffer!.");
			return -ENOMEM;
		}

		break;

		default: handle_bib_entry(request,length) ;
		break;
	}

	return 0;
}

static int handle_bib_entry(__u8*request, __u32 length)
{
	int error = 0;

	__u8 * request_pointer = request;

	__u16 magic_number_beginning = 0;
	__u16 magic_number_ending = 0;

	__u16 entries_number = 0;
	__u8 bytes_to_skip = 4;

	error = validate_entry_magic_numbers(request,MAGIC_BIB_BEGINNING,MAGIC_BIB_ENDING,BIB_ENTRY_SIZE, &entries_number);


	if(error)
	{
		log_err("Received BIB entries are not valid!");
		return error;
	}

	request += bytes_to_skip;
	int i;
	if(bib_entries_received < bib_entries_num)
	{
		for(i = 0; i < entries_number && bib_entries_received < bib_entries_num; i++)
		{
			if(request[0] != L4PROTO_TCP && request[0] != L4PROTO_UDP)
			{
				log_err("BIB entry protocol not valid!.");
				return -EINVAL;
			}

			bib_entries_buffer[bib_entries_received].l4_proto = request[0];
			bib_entries_buffer[bib_entries_received].ipv4.l3


			memcpy(&bib_entries_buffer[bib_entries_received].ipv4.l3,&request[1],4);
			memcpy(&bib_entries_buffer[bib_entries_received].ipv4.l4,&request[5],2);
			memcpy(&bib_entries_buffer[bib_entries_received].ipv6.l3,&request[7],16);
			memcpy(&bib_entries_buffer[bib_entries_received].ipv6.l4,&request[23],2);

			bib_entries_received++;
			request+=BIB_ENTRY_SIZE;
		}
	}
	else
	{
		log_err("The Number of BIB entries recieved is bigger than the number of allocated entries") ;
		return -EINVAL;
	}


		return 0;
}

static int save_configuration(void)
{
	int error = 0;
	int i = 0;
	struct ipv4_transport_addr addr;

	if(global->mtu_plateaus)
		kfree(global->mtu_plateaus);

	log_info("mtu_plateaus_entries_received: %d",mtu_plateaus_entries_received) ;
	log_info("mtu_plateaus_allocated: %d",sizeof(*global->mtu_plateaus)*mtu_plateaus_entries_received);

	global->mtu_plateaus = kmalloc(sizeof(*global->mtu_plateaus)*mtu_plateaus_entries_received,GFP_ATOMIC);


	for(i=0; i < mtu_plateaus_entries_received; i++)
	{
		global->mtu_plateaus[i] = plateaus_entries_buffer[i];
	}

	global->mtu_plateau_count = mtu_plateaus_entries_received;

	log_info("global plateau count: %d",global->mtu_plateau_count) ;

	error = config_set(global);

	if(error)
	{
		log_err("An error ocurred while saving Global configuration!.");
		return error;
	}


	if(error)
	{
		log_err("An error ocurred while saving Global configuration!.");
		return error;
	}

	pool4db_flush();

	for(i = 0; i < pool4_entries_received; i++)
	{
		if(!pool4db_contains(pool4_entries_buffer[i].mark, pool4_entries_buffer[i].prefix))
		{
			pool4db_add(pool4_entries_buffer[i].mark, pool4_entries_buffer[i].prefix,
					pool4_entries_buffer[i].ports);
		}
	}

	for(i=0; i < bib_entries_received; i++)
	{

	}

	return 0;
}

