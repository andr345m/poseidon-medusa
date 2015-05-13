#ifndef MEDUSA_MSG_FETCH_HPP_
#define MEDUSA_MSG_FETCH_HPP_

#include <poseidon/cbpp/message_base.hpp>

namespace Medusa {

namespace Msg {

#define MESSAGE_NAME	CS_FetchRequestHeaders
#define MESSAGE_ID		100
#define MESSAGE_FIELDS	\
	FIELD_STRING		(host)	\
	FIELD_VUINT			(port)	\
	FIELD_VUINT			(useSsl)	\
	FIELD_STRING		(xff)	\
	FIELD_VUINT			(verb)	\
	FIELD_STRING		(uri)	\
	FIELD_ARRAY			(getParams,	\
		FIELD_STRING		(name)	\
		FIELD_STRING		(value)	\
	)	\
	FIELD_ARRAY			(headers,	\
		FIELD_STRING		(name)	\
		FIELD_STRING		(value)	\
	)	\
	FIELD_ARRAY			(transferEncoding,	\
		FIELD_STRING		(value)	\
	)
#include <poseidon/cbpp/message_generator.hpp>

#define MESSAGE_NAME	CS_FetchHttpSend
#define MESSAGE_ID		101
#define MESSAGE_FIELDS	\
	// 这个结构并不使用，我们只用协议号。
#include <poseidon/cbpp/message_generator.hpp>

#define MESSAGE_NAME	CS_FetchHttpSendEof
#define MESSAGE_ID		102
#define MESSAGE_FIELDS	\
	FIELD_ARRAY			(headers,	\
		FIELD_STRING		(name)	\
		FIELD_STRING		(value)	\
	)
#include <poseidon/cbpp/message_generator.hpp>

#define MESSAGE_NAME	CS_FetchTunnelSend
#define MESSAGE_ID		103
#define MESSAGE_FIELDS	\
	// 这个结构并不使用，我们只用协议号。
#include <poseidon/cbpp/message_generator.hpp>

#define MESSAGE_NAME	CS_FetchClose
#define MESSAGE_ID		104
#define MESSAGE_FIELDS	\
	FIELD_VINT			(errCode)
#include <poseidon/cbpp/message_generator.hpp>

#define MESSAGE_NAME	SC_FetchResponseHeaders
#define MESSAGE_ID		199
#define MESSAGE_FIELDS	\
	FIELD_VUINT			(statusCode)	\
	FIELD_STRING		(reason)	\
	FIELD_ARRAY			(headers,	\
		FIELD_STRING		(name)	\
		FIELD_STRING		(value)	\
	)	\
	FIELD_ARRAY			(transferEncoding,	\
		FIELD_STRING		(value)	\
	)
#include <poseidon/cbpp/message_generator.hpp>

#define MESSAGE_NAME	SC_FetchHttpReceive
#define MESSAGE_ID		198
#define MESSAGE_FIELDS	\
	// 这个结构并不使用，我们只用协议号。
#include <poseidon/cbpp/message_generator.hpp>

#define MESSAGE_NAME	SC_FetchHttpReceiveEof
#define MESSAGE_ID		197
#define MESSAGE_FIELDS	\
	FIELD_ARRAY			(headers,	\
		FIELD_STRING		(name)	\
		FIELD_STRING		(value)	\
	)
#include <poseidon/cbpp/message_generator.hpp>

#define MESSAGE_NAME	SC_FetchTunnelReceive
#define MESSAGE_ID		196
#define MESSAGE_FIELDS	\
	// 这个结构并不使用，我们只用协议号。
#include <poseidon/cbpp/message_generator.hpp>

#define MESSAGE_NAME	SC_FetchError
#define MESSAGE_ID		195
#define MESSAGE_FIELDS	\
	FIELD_VINT			(cbppErrCode)	\
	FIELD_VINT			(sysErrCode)	\
	FIELD_STRING		(description)
#include <poseidon/cbpp/message_generator.hpp>

}

}

#endif
