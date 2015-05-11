#ifndef MEDUSA_MSG_ERROR_CODES_HPP_
#define MEDUSA_MSG_ERROR_CODES_HPP_

#include <poseidon/cbpp/status_codes.hpp>

namespace Medusa {

namespace Msg {
	using namespace Poseidon::Cbpp::StatusCodes;

	enum {
		ERR_INVALID_AUTH				= 9301,

		ERR_FETCH_NOT_CONNECTED			= 9501,
		ERR_FETCH_CONNECTION_LOST		= 9502,
		ERR_FETCH_CONNECTION_TIMED_OUT	= 9503,
		ERR_FETCH_DNS_TIMED_OUT			= 9504,
		ERR_FETCH_DNS_FAILURE			= 9505,
		ERR_FETCH_MAX_PIPELINING_SIZE	= 9506,
		ERR_FETCH_MAX_PENDING_SIZE		= 9507,
		ERR_FETCH_CLIENT_REQUESTED		= 9508,
	};
}

}

#endif
