#ifndef MEDUSA_MSG_ERROR_CODES_HPP_
#define MEDUSA_MSG_ERROR_CODES_HPP_

#include <poseidon/cbpp/status_codes.hpp>

namespace Medusa {

namespace Msg {
	using namespace Poseidon::Cbpp::StatusCodes;

	enum {
		ERR_FETCH_CRC_MISMATCH		= 9501,
		ERR_FETCH_DNS_FAILURE		= 9502,
	};
}

}

#endif
