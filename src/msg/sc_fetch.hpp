#ifndef MEDUSA_MSG_SC_FETCH_HPP_
#define MEDUSA_MSG_SC_FETCH_HPP_

#include <poseidon/cbpp/message_base.hpp>

namespace Medusa {

namespace Msg {

#define MESSAGE_NAME    SC_FetchConnected
#define MESSAGE_ID      199
#define MESSAGE_FIELDS  \
	FIELD_VUINT         (flags)
#include <poseidon/cbpp/message_generator.hpp>

#define MESSAGE_NAME    SC_FetchReceived
#define MESSAGE_ID      198
#define MESSAGE_FIELDS  \
	FIELD_FLEXIBLE      (recv_queue)
#include <poseidon/cbpp/message_generator.hpp>

#define MESSAGE_NAME    SC_FetchEnded
#define MESSAGE_ID      197
#define MESSAGE_FIELDS  \
	//
#include <poseidon/cbpp/message_generator.hpp>

#define MESSAGE_NAME    SC_FetchClosed
#define MESSAGE_ID      196
#define MESSAGE_FIELDS  \
	FIELD_VINT          (err_code) \
	FIELD_VUINT         (reserved)  \
	FIELD_STRING        (err_msg)
#include <poseidon/cbpp/message_generator.hpp>

}

}

#endif
