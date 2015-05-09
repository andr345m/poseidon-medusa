#ifndef MEDUSA_MSG_ERROR_CODES_HPP_
#define MEDUSA_MSG_ERROR_CODES_HPP_

#include <poseidon/cbpp/status_codes.hpp>

namespace Medusa {

namespace Msg {
	using namespace Poseidon::Cbpp::StatusCodes;

	enum {
		ERR_INVALID_AUTH			= 9301,

		ERR_FETCH_CONNECTION_LOST	= 9501,
		ERR_FETCH_DNS_TIMED_OUT		= 9502,
		ERR_FETCH_DNS_FAILURE		= 9503,
	};
}

}

#endif
