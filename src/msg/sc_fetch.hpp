#ifndef MEDUSA_MSG_SC_FETCH_HPP_
#define MEDUSA_MSG_SC_FETCH_HPP_

#include <poseidon/cbpp/message_base.hpp>

namespace Medusa {

namespace Msg {

#define MESSAGE_NAME	SC_FetchReceive
#define MESSAGE_ID		199
#define MESSAGE_FIELDS	\
	// 这个结构并不使用，我们只用协议号。
#include <poseidon/cbpp/message_generator.hpp>

#define MESSAGE_NAME	SC_FetchEnd
#define MESSAGE_ID		198
#define MESSAGE_FIELDS	\
	FIELD_VINT			(errCode)
#include <poseidon/cbpp/message_generator.hpp>

#define MESSAGE_NAME	SC_FetchClose
#define MESSAGE_ID		197
#define MESSAGE_FIELDS	\
	FIELD_VINT			(cbppErrCode)	\
	FIELD_VINT			(sysErrCode)	\
	FIELD_STRING		(errMsg)
#include <poseidon/cbpp/message_generator.hpp>

}

}

#endif
