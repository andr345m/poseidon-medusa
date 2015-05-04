#ifndef MEDUSA_FETCH_PROTOCOL_HPP_
#define MEDUSA_FETCH_PROTOCOL_HPP_

#include <poseidon/cbpp/message_base.hpp>

namespace Medusa {

#define MESSAGE_NAME	FetchEncryptedMessage
#define MESSAGE_ID		100
#define MESSAGE_FIELDS	\
	FIELD_STRING		(nonce)	\
	FIELD_VUINT			(crc32)	\
	FIELD_STRING		(data)
#include <poseidon/cbpp/message_generator.hpp>

#define MESSAGE_NAME	FetchRequest
#define MESSAGE_ID		0
#define MESSAGE_FIELDS	\
	FIELD_STRING		(host)	\
	FIELD_VUINT			(port)	\
	FIELD_VUINT			(useSsl)	\
	FIELD_VUINT			(isTunnel)	\
	FIELD_STRING		(body)
#include <poseidon/cbpp/message_generator.hpp>

}

#endif
