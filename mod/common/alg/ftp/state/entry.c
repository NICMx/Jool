#include "nat64/mod/common/alg/ftp/state/entry.h"

enum ftpxlat_action ftpsm_client_sent_auth(struct ftp_state *state)
{
	state->client_sent_auth = true;
	return FTPXLAT_DO_NOTHING;
}

enum ftpxlat_action ftpsm_client_sent_epsv(struct ftp_state *state)
{
	if (config_ftp_requires_algs_request() && !state->algs_requested)
		return FTPXLAT_DO_NOTHING;

	state->client_sent_epsv = true;
	return FTPXLAT_EPSV_TO_PASV;
}

enum ftpxlat_action ftpsm_client_sent_eprt(struct ftp_state *state)
{
	return (!config_ftp_requires_algs_request() || state->algs_requested)
			? FTPXLAT_EPRT_TO_PORT
			: FTPXLAT_DO_NOTHING;
}

enum ftpxlat_action ftpsm_client_sent_algs(struct ftp_state *state,
		struct ftp_client_msg *token)
{
	switch (token->algs.arg) {
	case ALGS_STATUS64:
		break;
	case ALGS_ENABLE64:
		state->algs_requested = true;
		break;
	case ALGS_DISABLE64:
		state->algs_requested = false;
		break;
	case ALGS_BAD_SYNTAX:
		return FTPXLAT_SYNTAX_ERROR;
	}

	return FTPXLAT_RESPOND_STATUS;
}

enum ftpxlat_action ftpsm_server_denied(struct ftp_state *state)
{
	state->client_sent_auth = false;
	state->client_sent_epsv = false;
	return FTPXLAT_DO_NOTHING;
}

enum ftpxlat_action ftpsm_server_sent_227(struct ftp_state *state)
{
	return state->client_sent_epsv
			? FTPXLAT_227_TO_229
			: FTPXLAT_DO_NOTHING;
}

enum ftpxlat_action ftpsm_server_finished(struct ftp_state *state)
{
	if (state->client_sent_auth)
		state->transparent_mode = true;

	state->client_sent_auth = false;
	state->client_sent_epsv = false;
	return FTPXLAT_DO_NOTHING;
}

bool ftpsm_is_transparent_mode(struct ftp_state *state)
{
	return state->transparent_mode;
}
