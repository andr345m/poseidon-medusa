#ifndef MEDUSA_MSG_ERROR_CODES_HPP_
#define MEDUSA_MSG_ERROR_CODES_HPP_

#include <poseidon/cbpp/status_codes.hpp>

namespace Medusa {

namespace Msg {
	using namespace Poseidon::Cbpp::StatusCodes;

	enum {
		ERR_NOT_CONNECTED               = 9501,
		ERR_CONNECTION_LOST             = 9502,
		ERR_DNS_FAILURE                 = 9503,
		ERR_MAX_PIPELINING_SIZE         = 9504,
		ERR_MAX_PENDING_BUFFER_SIZE     = 9505,
		ERR_ACCESS_DENIED               = 9506,
		ERR_CONNECTION_REFUSED          = 9507,
		ERR_CONNECTION_TIMED_OUT        = 9508,
	};
}

}

#endif
