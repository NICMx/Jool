#include "mode.h"

void print_code_msg(struct response_hdr *hdr, const char *mode, const char *success_msg)
{
	switch (hdr->result_code) {
	case RESPONSE_SUCCESS:
		printf("%s\n", success_msg);
		break;
	case RESPONSE_UNKNOWN_MODE:
		printf("Unknown configuration mode.\n");
		break;
	case RESPONSE_UNKNOWN_OP:
		printf("Unknown operation.\n");
		break;
	case RESPONSE_UNKNOWN_L3PROTO:
		printf("Unknown layer-3 protocol.\n");
		break;
	case RESPONSE_UNKNOWN_L4PROTO:
		printf("Unknown layer-4 protocol.\n");
		break;
	case RESPONSE_NOT_FOUND:
		printf("The requested entry could not be found in the %s.\n", mode);
		break;
	case RESPONSE_ALLOC_FAILED:
		printf("The kernel module could not answer because some memory allocation failed.\n");
		break;
	case RESPONSE_CONNECT_FAILED:
		printf("Could not connect to the NAT64. Is it really up?\n");
		break;
	case RESPONSE_SEND_FAILED:
		printf("Could not send the message to the NAT64 for unknown reasons.\n");
		break;
	case RESPONSE_PARSE_FAIL:
		printf("The input seems malformed.\n");
		break;
	case RESPONSE_INVALID_VALUE:
		printf("The input was rejected by some validation.\n");
		break;
	case RESPONSE_MISSING_PARAM:
		printf("Missing input value.\n");
		break;
	case RESPONSE_UNKNOWN_ERROR:
		printf("Unknown error.\n");
		break;
	default:
		printf("Unknown result code: %u.\n", hdr->result_code);
		break;
	}
}
