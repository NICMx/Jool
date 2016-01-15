#include "nat64/common/genetlink.h"
#include "nat64/mod/common/pool6.h"
#include "nat64/mod/common/nl/nl_core2.h"
#include "nat64/mod/stateless/blacklist4.h"
#include "nat64/mod/stateless/rfc6791.h"
#include "nat64/mod/common/config.h"



static enum config_mode command = MODE_PARSE_FILE;

static int init_configuration(void);
static int init_members(void);
static int handle_global_config(__u8*request, __u32 length);
static int handle_global_parameters(__u8 * request, __u32 length);
static int handle_mtu_plateaus_entry(__u8 * request, __u32 length);
static int handle_pool6_config(__u8*request, __u32 length);
static int handle_eamt_config(__u8*request, __u32 length);
static int handle_eamt_entry(__u8*request, __u32 length);
static int handle_blacklist_config(__u8*request, __u32 length);
static int handle_blacklist_entry(__u8*request, __u32 length);
static int handle_pool6791_config(__u8*request, __u32 length);
static int handle_pool6791_entry(__u8 * request, __u32 length);
static int save_configuration(void);
static void free_members_on_error(void);
static void free_members(void);
static void end_configuration(void);


static __u8 initialized = 0;
static struct global_bits * configured_parameters = NULL;

static __u8 global_configured = 0;
static struct global_config * global = NULL;

static __u8 pool6_address_received = 0;
static __u8 pool6_len_received = 0;
static struct ipv6_prefix * pool6_entry = NULL;

static __u16 mtu_plateaus_entries_num = 0;
static __u16 mtu_plateaus_entries_received = 0;
static __u16 * plateaus_entries_buffer = NULL;

static __u16 eamt_entries_num = 0;
static __u16 eamt_entries_received = 0;
static __u8 * eamt_entries_buffer = NULL;

static __u16 blacklist_entries_num = 0;
static __u16 blacklist_entries_received = 0;
static struct ipv4_prefix * blacklist_entries_buffer = NULL;

static __u16 pool6791_entries_num = 0;
static __u16 pool6791_entries_received = 0;
static struct ipv4_prefix * pool6791_entries_buffer = NULL;


static int init_configuration(void)
{
	int error = 0;

	free_members_on_error();
	error = init_members();
	if (error) {
		log_err("Error while trying to initialize members.");
		return error;
	}
	initialized = 1;

	return error;
}
static int init_members(void)
{
	global_configured = 0;

	mtu_plateaus_entries_num = 0;
	mtu_plateaus_entries_received = 0;

	pool6_address_received = 0;
	pool6_len_received = 0;

	eamt_entries_num = 0;
	eamt_entries_received = 0;

	pool6791_entries_num = 0;
	pool6791_entries_received = 0;

	blacklist_entries_num = 0;
	blacklist_entries_received = 0;



	global = kmalloc(sizeof(*global), GFP_ATOMIC) ;

	if (!global) {
		log_err("An error occurred while trying to allocate memory for Global parameters!.");
		return -ENOMEM;
	}

	global->mtu_plateaus = NULL;
	config_clone(global);

	configured_parameters = kmalloc(sizeof(*configured_parameters),GFP_ATOMIC) ;

	if (!configured_parameters) {
		log_err("An error occurred while trying to allocate memory for Configured parameters union!.");
		return -ENOMEM;
	}

	if(pool6_entry)
		kfree(pool6_entry);

	pool6_entry = kmalloc(sizeof(*pool6_entry), GFP_ATOMIC) ;

	if (!pool6_entry) {
		log_err("An error occurred while trying to allocate memory for Pool6 entry!.");
		return -ENOMEM;
	}

	return 0;
}
static void free_members_on_error(void)
{
	if (configured_parameters) {
		kfree(configured_parameters);
		configured_parameters = NULL;
	}

	if (global) {
		if (global->mtu_plateaus) {
			kfree(global->mtu_plateaus);
			global->mtu_plateaus = NULL;
		}
		kfree(global);
		global = NULL;
	}

	if (pool6_entry) {
		kfree(pool6_entry);
		pool6_entry = NULL;
	}

	if (plateaus_entries_buffer) {
		kfree(plateaus_entries_buffer) ;
		plateaus_entries_buffer = NULL;
	}

	if (eamt_entries_buffer) {
		kfree(eamt_entries_buffer);
		eamt_entries_buffer = NULL;
	}

	if (blacklist_entries_buffer) {
		kfree(blacklist_entries_buffer);
		blacklist_entries_buffer = NULL;
	}

	if (pool6791_entries_buffer) {
		kfree(pool6791_entries_buffer) ;
		pool6791_entries_buffer = NULL;
	}
}
static void free_members(void)
{
	if (configured_parameters) {
		kfree(configured_parameters);
		configured_parameters = NULL;
	}

	global = NULL;

	if (pool6_entry) {
		kfree(pool6_entry);
		pool6_entry = NULL;
	}

	if (plateaus_entries_buffer) {
		kfree(plateaus_entries_buffer) ;
		plateaus_entries_buffer = NULL;
	}

	if (eamt_entries_buffer) {
		kfree(eamt_entries_buffer);
		eamt_entries_buffer = NULL;
	}

	if (blacklist_entries_buffer) {
		kfree(blacklist_entries_buffer);
		blacklist_entries_buffer = NULL;
	}

	if (pool6791_entries_buffer) {
		kfree(pool6791_entries_buffer) ;
		pool6791_entries_buffer = NULL;
	}
}
static void end_configuration(void)
{
	free_members();
	initialized = 0;
}


static int handle_json_file_config_wrapped(struct genl_info *info)
{

	struct request_hdr *jool_hdr = (struct request_hdr *) (info->attrs[ATTR_DATA] + 1);
		__u8*request = (__u8 *)(jool_hdr + 1);
		int error = 0;
		__u16 request_type =  *((__u16 *) request);
		__u32 length = jool_hdr->length - 2;


		if (request_type == SEC_INIT) {

			if(init_configuration()) {
				free_members_on_error();
				initialized = 0;
				return -EINVAL;
			}
		}


		if (request_type == SEC_DONE) {
			if(save_configuration()) {
				free_members_on_error();
				initialized = 0;
				return -EINVAL;
			}

			end_configuration();
			return 0;
		}

		if (!request) {
			log_err("NULL request received!.");
			free_members_on_error();
			initialized = 0;
			return -EINVAL;
		}

		request = request + 2;

		if(initialized) {
			switch(request_type) {

			case SEC_GLOBAL:
			error = handle_global_config(request,length);
			break;

			case SEC_POOL6:
			error = handle_pool6_config(request,length);
			break;

			case SEC_EAMT:
			error = handle_eamt_config(request,length);
			break;

			case SEC_BLACKLIST:
			error = handle_blacklist_config(request,length);
			break;

			case SEC_POOL6791:
			error = handle_pool6791_config(request,length);
			break;
			}

			if(error) {
				free_members_on_error();
				initialized = 0;
			}

		} else {
			log_err("Configuration transaction has not been initialized!.") ;
			return -EINVAL;
		}

		return error;

}


int handle_json_file_config(struct genl_info *info)
{
	int error = handle_json_file_config_wrapped(info);

	if (error)
		return nl_core_respond_error(info, command, error);

	return nl_core_send_acknowledgement(info, command);
}


static int handle_global_config(__u8*request, __u32 length)
{
	switch(length) {
	case 2:
		return handle_mtu_plateaus_entry(request,length);
		break;

	case 41:
		global_configured = 1;
		return handle_global_parameters(request,length);

		break;

	default:
		log_err("Unrecognized configuration request for Global section.");
		return -EINVAL;

		break;

	}

	return 0;
}
static int handle_global_parameters(__u8 * request, __u32 length)
{
	int index = 0;

	memcpy((__u8*)(configured_parameters),request,32) ;
	index+=32;

	if(configured_parameters->manually_enabled) {
		memcpy(&global->is_disable,&request[index],1);
	}

	index+=1;

	if(configured_parameters->drop_icmpv6_info) {
		memcpy(&global->nat64.drop_icmp6_info,&request[index],1);
	}

	index+=1;

	if(configured_parameters->zeroize_traffic_class) {
		memcpy(&global->reset_traffic_class,&request[index],1);
	}

	index+=1;

	if(configured_parameters->override_tos) {
		memcpy(&global->reset_tos,&request[index],1);
	}

	index+=1;

	if(configured_parameters->tos) {
		memcpy(&global->new_tos,&request[index],1);
	}

	index+=1;

	if(configured_parameters->amend_udp_checksum_zero) {
		memcpy(&global->siit.compute_udp_csum_zero,&request[index],1);
	}

	index+=1;

	if(configured_parameters->randomize_rfc6791_addresses) {
		memcpy(&global->siit.randomize_error_addresses,&request[index],1);
	}

	index+=1;

	memcpy((__u8*)&mtu_plateaus_entries_num,&request[index],2);

	if(mtu_plateaus_entries_num > 0) {

		plateaus_entries_buffer = kmalloc(sizeof(*plateaus_entries_buffer)*mtu_plateaus_entries_num,GFP_ATOMIC) ;

		if(!plateaus_entries_buffer) {
			log_err("An error occurred while trying to allocate memory for plateaus entries buffer!.") ;
			return -ENOMEM;
		}
	}

	return 0;
}
static int handle_mtu_plateaus_entry(__u8 * request, __u32 length)
{
	if(!configured_parameters) {
		log_err("configured_parameters flags were not initialized!.");
		return -EINVAL;
	}

	if(!configured_parameters->mtu_plateaus) {
		log_err("an attemp to add an mtu-plateaus item whit the configuration flag set to false was made!.");
		return -EINVAL;
	}

	if(!plateaus_entries_buffer) {
		log_err("the plateaus entries buffer was not initialized!.");
		return -EINVAL;
	}

	if(mtu_plateaus_entries_received < mtu_plateaus_entries_num) {
		memcpy((__u8*)&plateaus_entries_buffer[mtu_plateaus_entries_received],request,2);
		mtu_plateaus_entries_received++;
	}else {
		log_err("The Number of mtu-plateaus entries recieved is bigger than the number of allocated entries") ;
		return 1;
	}

	return 0;
}
static int handle_pool6_config(__u8*request, __u32 length)
{
	switch(length) {

	case 16:
		memcpy((__u8*)&pool6_entry->address,request,16);
		pool6_address_received =1;
		break;

	case 1:
		memcpy(&pool6_entry->len,request,1);
		pool6_len_received = 1;
		break;

	default:
		log_err("Unrecognized configuration request for Pool6 section.");
		return -EINVAL;
		break;

	}
	return 0;
}

static int handle_eamt_config(__u8*request, __u32 length)
{
	switch(length) {
	case 2:
		memcpy((__u8*)&eamt_entries_num,request,2);
		eamt_entries_buffer = kmalloc(sizeof(__u8)*EAMT_ENTRY_SIZE*eamt_entries_num, GFP_ATOMIC);

		if(!eamt_entries_buffer) {
			log_err("An error ocurred while trying to allocate memory for eamt entries!.");
			return -ENOMEM;
		}
		break;

	default:
		return handle_eamt_entry(request,length);

	}

	return 0;
}

static int handle_eamt_entry(__u8*request, __u32 length)
{
	int i = 0;

	__u16 entries_number = 0;
	__u8 bytes_to_skip = 2;

	memcpy((__u8*)&entries_number,request,2) ;

	request += bytes_to_skip;

	if (eamt_entries_received < eamt_entries_num) {

		for (i = 0; i < entries_number && eamt_entries_received < eamt_entries_num; i++) {

			memcpy(&eamt_entries_buffer[eamt_entries_received*EAMT_ENTRY_SIZE],request,16);
			memcpy(&eamt_entries_buffer[eamt_entries_received*EAMT_ENTRY_SIZE+16],&request[16],1);

			memcpy(&eamt_entries_buffer[eamt_entries_received*EAMT_ENTRY_SIZE+17],&request[17],4);
			memcpy(&eamt_entries_buffer[eamt_entries_received*EAMT_ENTRY_SIZE+21],&request[21],1);

			eamt_entries_received++;
			request+=EAMT_ENTRY_SIZE;

		}
	} else {
		log_err("The Number of EAMT entries recieved is bigger than the number of allocated entries") ;
		return 1;
	}

	return 0;
}

static int handle_blacklist_config(__u8*request, __u32 length)
{

	switch (length) {
	case 2:

		if(blacklist_entries_buffer)
		kfree(blacklist_entries_buffer);

		memcpy((__u8*)&blacklist_entries_num,request,2);
		blacklist_entries_buffer = kmalloc(sizeof(*blacklist_entries_buffer)*blacklist_entries_num, GFP_ATOMIC) ;

		if (!blacklist_entries_buffer) {
			log_err("An error ocurred while trying to allocate memory for blacklist entries!.");
			return -ENOMEM;
		}
		break;

	default:
		return handle_blacklist_entry(request,length);

	}

	return 0;
}
static int handle_blacklist_entry(__u8*request, __u32 length)
{
	int i;

	__u16 entries_number = 0;
	__u8 bytes_to_skip = 2;

	memcpy((__u8*)&entries_number,request,2) ;
	request += bytes_to_skip;

	if (blacklist_entries_received  < blacklist_entries_num) {
		for (i = 0; i < entries_number; i++) {
			memcpy(&blacklist_entries_buffer[i].address,request,4);
			memcpy(&blacklist_entries_buffer[i].len,&request[4],1);

			blacklist_entries_received++;
			request+=BLACKLIST_ENTRY_SIZE;
		}
	} else {
		log_err("The Number of Blacklist entries recieved is bigger than the number of allocated entries buffer!") ;
		return -EINVAL;
	}


	return 0;
}

static int handle_pool6791_config(__u8*request, __u32 length)
{

	switch(length)
	{
		case 2:
			if(pool6791_entries_buffer)
				kfree(pool6791_entries_buffer);

			memcpy((__u8*)&pool6791_entries_num,request,2);
			pool6791_entries_buffer = kmalloc(sizeof(*pool6791_entries_buffer)*pool6791_entries_num, GFP_ATOMIC);
			if (!pool6791_entries_buffer) {
				log_err("An error ocurred while trying to allocate memory for pool6791 entries buffer!.");
				return -ENOMEM;
			}
			break;

		default:
			return handle_pool6791_entry(request,length) ;
	}
	return 0;
}

static int handle_pool6791_entry(__u8 * request, __u32 length)
{
	int i;

	__u16 entries_number = 0;
	__u8 bytes_to_skip = 2;

	memcpy((__u8*)&entries_number,request,2) ;

	request += bytes_to_skip;

	if (pool6791_entries_received < pool6791_entries_num) {

		for (i = 0; i < entries_number; i++) {

			memcpy(&pool6791_entries_buffer[i].address,request,4);
			memcpy(&pool6791_entries_buffer[i].len,&request[4],1);

			pool6791_entries_received++;
			request+=POOL6791_ENTRY_SIZE;

		}

	} else {

		log_err("The Number of Pool6791 entries recieved is bigger than the number of allocated entries.") ;
		return -EINVAL;
	}

	return 0;

}

static int save_configuration(void)
{
	int error = 0;
	int i = 0;

	struct list_head * blacklist_db = NULL;
	struct list_head * pool6791_db = NULL;

	if (global_configured) {

		global->mtu_plateaus = kmalloc(sizeof(*global->mtu_plateaus)*mtu_plateaus_entries_received,GFP_ATOMIC);

		if (!global->mtu_plateaus) {
			log_err("Memory for saving mtu_plateaus items could not be allocated!.");
			return -ENOMEM;
		}

		for(i=0; i < mtu_plateaus_entries_received; i++) {
			global->mtu_plateaus[i] = plateaus_entries_buffer[i];
		}

		global->mtu_plateau_count = mtu_plateaus_entries_received;

	}

	if (pool6_address_received && pool6_len_received) {

		error  = pool6_replace(pool6_entry);

		if(error) {
			log_err("An error occured while saving Pool6 configuration!.") ;
			return error;
		}

	}


	if (eamt_entries_received > 0) {
		//Initialize database.

		for(i = 0; i < eamt_entries_received; i++) {
			//Add entries to database.
		}

	}


	if (blacklist_entries_received > 0) {

		blacklist_db = blacklist_config_init_db();

		if(!blacklist_db) {
			log_err("An error occurred while initializing blacklist configuration database!.");
			return 1;
		}

		for(i=0; i < blacklist_entries_received; i++) {

			error = blacklist_config_add(blacklist_db, &blacklist_entries_buffer[i]) ;
			if(error) {
				log_err("An error occurred while adding a blacklist entry to the database!.");
				return error;
			}
		}

	}



	if (pool6791_entries_received > 0) {
			pool6791_db = rfc6791_config_init_db();
			if (!pool6791_db) {
				log_err("An error occurred while initializing pool6791 configuration database!.");
				return 1;
			}

			for (i=0; i < pool6791_entries_received;i++) {
				error = rfc6791_config_add(pool6791_db, &pool6791_entries_buffer[i]) ;
				if (error) {
					log_err("An error occurred while adding a pool6791 entry to the database!.");
					return error;
				}
			}

		}


		if (global_configured) {
			config_replace(global);
			error = 0;
		}

		if (blacklist_entries_received > 0) {

			error = blacklist_switch_database(blacklist_db);
			if (error) {
				log_err("An error occurred while saving Blacklist configuration!.");
				return error;
			}
		}

		if (pool6791_entries_received > 0) {
			error = rfc6791_switch_database(pool6791_db);
			if (error) {
				log_err("An error occurred while saving Pool6791 configuration!.");
				return error;
			}
		}

		return 0;
}

