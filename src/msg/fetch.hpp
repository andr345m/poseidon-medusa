#ifndef MEDUSA_MSG_FETCH_HPP_
#define MEDUSA_MSG_FETCH_HPP_

#include <poseidon/cbpp/message_base.hpp>

namespace Medusa {

namespace Msg {

#define MESSAGE_NAME	G_FetchEncryptedMessage
#define MESSAGE_ID		0
#define MESSAGE_FIELDS	\
	FIELD_STRING		(sessionId)	\
	FIELD_STRING		(nonce)	\
	FIELD_STRING		(noncedKeyHash)	\
	FIELD_STRING		(encrypted)
#include <poseidon/cbpp/message_generator.hpp>

#define MESSAGE_NAME	CS_FetchDnsRequest
#define MESSAGE_ID		100
#define MESSAGE_FIELDS	\
	FIELD_STRING		(host)	\
	FIELD_VUINT			(port)
#include <poseidon/cbpp/message_generator.hpp>

#define MESSAGE_NAME	CS_FetchRequest
#define MESSAGE_ID		101
#define MESSAGE_FIELDS	\
	FIELD_STRING		(host)	\
	FIELD_VUINT			(port)	\
	FIELD_VUINT			(useSsl)	\
	FIELD_STRING		(contents)
#include <poseidon/cbpp/message_generator.hpp>

#define MESSAGE_NAME	CS_FetchClose
#define MESSAGE_ID		102
#define MESSAGE_FIELDS	\
	FIELD_VINT			(errCode)
#include <poseidon/cbpp/message_generator.hpp>

#define MESSAGE_NAME	SC_FetchDnsResult
#define MESSAGE_ID		199
#define MESSAGE_FIELDS	\
	FIELD_STRING		(ip)	\
	FIELD_VUINT			(port)
#include <poseidon/cbpp/message_generator.hpp>

#define MESSAGE_NAME	SC_FetchSuccess
#define MESSAGE_ID		198
#define MESSAGE_FIELDS	\
	FIELD_STRING		(host)	\
	FIELD_VUINT			(port)	\
	FIELD_STRING		(contents)
#include <poseidon/cbpp/message_generator.hpp>

#define MESSAGE_NAME	SC_FetchFailure
#define MESSAGE_ID		197
#define MESSAGE_FIELDS	\
	FIELD_STRING		(host)	\
	FIELD_VUINT			(port)	\
	FIELD_VINT			(cbppErrCode)	\
	FIELD_VINT			(sysErrCode)	\
	FIELD_STRING		(description)
#include <poseidon/cbpp/message_generator.hpp>

}

}

#endif
