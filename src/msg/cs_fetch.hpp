#ifndef MEDUSA_MSG_CS_FETCH_HPP_
#define MEDUSA_MSG_CS_FETCH_HPP_

#include <poseidon/cbpp/message_base.hpp>

namespace Medusa {

namespace Msg {

#define MESSAGE_NAME    CS_FetchOpen
#define MESSAGE_ID      104
#define MESSAGE_FIELDS  \
	//
#include <poseidon/cbpp/message_generator.hpp>

#define MESSAGE_NAME    CS_FetchConnect
#define MESSAGE_ID      100
#define MESSAGE_FIELDS  \
	FIELD_STRING        (host)  \
	FIELD_VUINT         (port)  \
	FIELD_VUINT         (use_ssl)   \
	FIELD_VUINT         (flags)
#include <poseidon/cbpp/message_generator.hpp>

#define MESSAGE_NAME    CS_FetchSend
#define MESSAGE_ID      101
#define MESSAGE_FIELDS  \
	FIELD_FLEXIBLE      (data)
#include <poseidon/cbpp/message_generator.hpp>

#define MESSAGE_NAME    CS_FetchAcknowledge
#define MESSAGE_ID      103
#define MESSAGE_FIELDS  \
	FIELD_VUINT         (size)
#include <poseidon/cbpp/message_generator.hpp>

#define MESSAGE_NAME    CS_FetchClose
#define MESSAGE_ID      102
#define MESSAGE_FIELDS  \
	FIELD_VINT          (err_code)
#include <poseidon/cbpp/message_generator.hpp>

}

}

#endif
