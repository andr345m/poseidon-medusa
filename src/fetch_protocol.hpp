#ifndef MEDUSA_FETCH_PROTOCOL_HPP_
#define MEDUSA_FETCH_PROTOCOL_HPP_

#include <poseidon/cbpp/message_base.hpp>

namespace Medusa {

#define MESSAGE_NAME	CS_FetchSyn
#define MESSAGE_ID		1001
#define MESSAGE_FIELDS	\
	FIELD_VUINT			(nonce)	\
	FIELD_STRING		(passwordHash)
#include <poseidon/cbpp/message_generator.hpp>

#define MESSAGE_NAME	SC_FetchAck
#define MESSAGE_ID		1999
#define MESSAGE_FIELDS	\
	//
#include <poseidon/cbpp/message_generator.hpp>

#define MESSAGE_NAME	CS_FetchHttpRequest
#define MESSAGE_ID		2001
#define MESSAGE_FIELDS	\
	FIELD_VUINT			(nonce)	\
	FIELD_VUINT			(context)	\
	FIELD_STRING		(host)	\
	FIELD_STRING		(port)	\
	FIELD_STRING		(uri)	\
	FIELD_VUINT			(version)	\
	FIELD_ARRAY			(headers,	\
		FIELD_STRING		(key)	\
		FIELD_STRING		(val)	\
	)	\
	FIELD_STRING		(entity)
#include <poseidon/cbpp/message_generator.hpp>

#define MESSAGE_NAME	CS_FetchTunnelRequest
#define MESSAGE_ID		2002
#define MESSAGE_FIELDS	\
	FIELD_VUINT			(nonce)	\
	FIELD_VUINT			(context)	\
	FIELD_STRING		(host)	\
	FIELD_VUINT			(port)
#include <poseidon/cbpp/message_generator.hpp>

#define MESSAGE_NAME	SC_FetchResponse
#define MESSAGE_ID		2999
#define MESSAGE_FIELDS	\
	FIELD_VUINT			(nonce)	\
	FIELD_VUINT			(context)	\
	FIELD_STRING		(data)
#include <poseidon/cbpp/message_generator.hpp>

}

#endif
