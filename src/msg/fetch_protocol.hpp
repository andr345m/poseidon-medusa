#ifndef MEDUSA_MSG_FETCH_PROTOCOL_HPP_
#define MEDUSA_MSG_FETCH_PROTOCOL_HPP_

#include <poseidon/cbpp/message_base.hpp>

namespace Medusa {

namespace Msg {

#define MESSAGE_NAME	GN_FetchEncryptedMessage
#define MESSAGE_ID		100
#define MESSAGE_FIELDS	\
	FIELD_VUINT			(context)	\
	FIELD_STRING		(nonce)	\
	FIELD_VUINT			(messageId)	\
	FIELD_VUINT			(crc32)	\
	FIELD_STRING		(data)
#include <poseidon/cbpp/message_generator.hpp>

#define MESSAGE_NAME	CS_FetchRequest
#define MESSAGE_ID		200
#define MESSAGE_FIELDS	\
	FIELD_STRING		(host)	\
	FIELD_VUINT			(port)	\
	FIELD_VUINT			(useSsl)	\
	FIELD_STRING		(contents)
#include <poseidon/cbpp/message_generator.hpp>

#define MESSAGE_NAME	SC_FetchSuccess
#define MESSAGE_ID		299
#define MESSAGE_FIELDS	\
	FIELD_STRING		(contents)
#include <poseidon/cbpp/message_generator.hpp>

#define MESSAGE_NAME	SC_FetchFailure
#define MESSAGE_ID		298
#define MESSAGE_FIELDS	\
	FIELD_VINT			(errCode)	\
	FIELD_STRING		(description)
#include <poseidon/cbpp/message_generator.hpp>

}

}

#endif
