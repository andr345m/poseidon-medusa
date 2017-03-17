#include "precompiled.hpp"
#include "fetch_client.hpp"
#include <poseidon/singletons/timer_daemon.hpp>
#include <poseidon/job_base.hpp>
#include "proxy_session.hpp"
#include "encryption.hpp"
#include "msg/cs_fetch.hpp"
#include "msg/sc_fetch.hpp"
#include "msg/error_codes.hpp"

namespace Medusa {

FetchClient::FetchClient(const Poseidon::SockAddr &sock_addr, bool use_ssl, bool verify_peer, std::string password)
	: Poseidon::Cbpp::Client(sock_addr, use_ssl, verify_peer)
	, m_password(STD_MOVE(password))
{
	LOG_MEDUSA_INFO("FetchClient constructor: remote = ", Poseidon::get_ip_port_from_sock_addr(sock_addr));
}
FetchClient::~FetchClient(){
	LOG_MEDUSA_INFO("FetchClient destructor: remote = ", get_remote_info());

	for(AUTO(it, m_sessions.begin()); it != m_sessions.end(); ++it){
		const AUTO(session, it->second.lock());
		if(session){
			session->on_fetch_closed(Msg::ERR_CONNECTION_LOST, "Lost connection to fetch server");
		}
	}
}

bool FetchClient::send_explicit(const Poseidon::Uuid &fetch_uuid, boost::uint16_t message_id, Poseidon::StreamBuffer plain){
	PROFILE_ME;

	AUTO(pair, encrypt_header(fetch_uuid, m_password));
	AUTO(payload, encrypt_payload(pair.first, STD_MOVE(plain)));
	pair.second.splice(payload);
	return Poseidon::Cbpp::Client::send(message_id, STD_MOVE(pair.second));
}
bool FetchClient::send(const Poseidon::Uuid &fetch_uuid, const Poseidon::Cbpp::MessageBase &msg){
	PROFILE_ME;

	return send_explicit(fetch_uuid, msg.get_message_id(), msg);
}

void FetchClient::on_sync_data_message(boost::uint16_t message_id, Poseidon::StreamBuffer payload){
	PROFILE_ME;
	LOG_MEDUSA_DEBUG("Fetch data message: message_id = ", message_id, ", payload_size = ", payload.size());

	const AUTO(payload_size, payload.size());
	const AUTO(header_size, get_encrypted_header_size());
	if(payload_size < header_size){
		LOG_MEDUSA_ERROR("Frame from fetch server is too small: expecting ", header_size, ", got ", payload_size);
		DEBUG_THROW(Poseidon::Cbpp::Exception, Poseidon::Cbpp::ST_END_OF_STREAM, Poseidon::sslit("Frame from fetch server is too small"));
	}
	const AUTO(context, try_decrypt_header(payload, m_password));
	if(!context){
		LOG_MEDUSA_ERROR("Checksum mismatch. Maybe you provided a wrong password?");
		DEBUG_THROW(Poseidon::Cbpp::Exception, Poseidon::Cbpp::ST_FORBIDDEN, Poseidon::sslit("Checksum mismatch"));
	}
	payload.discard(header_size);
	AUTO(plain, decrypt_payload(context, STD_MOVE(payload)));

	const AUTO_REF(fetch_uuid, context->uuid);
	LOG_MEDUSA_DEBUG("Fetch response: fetch_uuid = ", fetch_uuid, ", message_id = ", message_id);
	AUTO(it, m_sessions.find(fetch_uuid));
	if(it == m_sessions.end()){
		LOG_MEDUSA_DEBUG("Proxy session has gone away: fetch_uuid = ", fetch_uuid);
		return;
	}
	AUTO(session, it->second.lock());
	if(session){
		try {
			switch(message_id){
				{{
#define ON_MESSAGE(Msg_, req_)  \
				}}  \
				break;  \
			case Msg_::ID: {    \
				Msg_ (req_)(plain); \
				{ //
#define ON_RAW_MESSAGE(Msg_, req_)  \
				}}  \
				break;  \
			case Msg_::ID: {    \
				::Poseidon::StreamBuffer & (req_) = plain;  \
				{ //
//=============================================================================
	ON_MESSAGE(Msg::SC_FetchConnected, req){
		LOG_MEDUSA_DEBUG("Fetch connected: fetch_uuid = ", fetch_uuid, ", flags = ", req.flags);
		session->on_fetch_connected(req.flags);
	}
	ON_RAW_MESSAGE(Msg::SC_FetchReceived, req){
		const AUTO(size, req.size());
		LOG_MEDUSA_DEBUG("Fetch received: fetch_uuid = ", fetch_uuid, ", size = ", size);
		session->on_fetch_received(STD_MOVE(req));
		send(fetch_uuid, Msg::CS_FetchAcknowledge(size));
	}
	ON_MESSAGE(Msg::SC_FetchEnded, req){
		LOG_MEDUSA_DEBUG("Fetch ended: fetch_uuid = ", fetch_uuid);
		session->on_fetch_ended();
	}
	ON_MESSAGE(Msg::SC_FetchClosed, req){
		LOG_MEDUSA_DEBUG("Fetch closed: fetch_uuid = ", fetch_uuid, ", err_code = ", req.err_code, ", err_msg = ", req.err_msg);
		session->on_fetch_closed(req.err_code, req.err_msg.c_str());
	}
//=============================================================================
				}}
				break;
			default:
				LOG_MEDUSA_ERROR("Unknown fetch response from server: message_id = ", message_id, ", size = ", plain.size());
				break;
			}
		} catch(Poseidon::Cbpp::Exception &e){
			LOG_MEDUSA_ERROR("Poseidon::Cbpp::Exception thrown: status_code = ", e.get_status_code(), ", what = ", e.what());
			session->on_fetch_closed(e.get_status_code(), e.what());
			session.reset();
		} catch(std::exception &e){
			LOG_MEDUSA_ERROR("std::exception thrown: what = ", e.what());
			session->on_fetch_closed(Msg::ERR_CONNECTION_LOST, e.what());
			session.reset();
		}
	}
	if(!session || session->has_been_shutdown_write()){
		LOG_MEDUSA_DEBUG("Reclaiming fetch request: fetch_uuid = ", fetch_uuid);
		if(m_sessions.erase(fetch_uuid) > 0){
			send(fetch_uuid, Msg::CS_FetchClose(Msg::ERR_CONNECTION_LOST));
		}
	}
}

bool FetchClient::fetch_connect(const boost::shared_ptr<ProxySession> &session, std::string host, unsigned port, bool use_ssl, boost::uint64_t flags){
	PROFILE_ME;

	const AUTO_REF(fetch_uuid, session->get_fetch_uuid());
	const AUTO(result, m_sessions.emplace(fetch_uuid, session));
	if(result.second && !send(fetch_uuid, Msg:: CS_FetchOpen())){
		return false;
	}
	return send(fetch_uuid, Msg::CS_FetchConnect(STD_MOVE(host), port, use_ssl, flags));
}
bool FetchClient::fetch_send(const boost::shared_ptr<ProxySession> &session, Poseidon::StreamBuffer data){
	PROFILE_ME;

	const AUTO_REF(fetch_uuid, session->get_fetch_uuid());
	const AUTO(it, m_sessions.find(fetch_uuid));
	if(it == m_sessions.end()){
		LOG_MEDUSA_WARNING("Fetch client not connected? fetch_uuid = ", fetch_uuid);
		return false;
	}
	return send_explicit(fetch_uuid, Msg::CS_FetchSend::ID, STD_MOVE(data));
}
void FetchClient::fetch_close(const Poseidon::Uuid &fetch_uuid, int err_code, const char *err_msg) NOEXCEPT {
	PROFILE_ME;

	const AUTO(it, m_sessions.find(fetch_uuid));
	if(it == m_sessions.end()){
		return;
	}
	const AUTO(session, it->second.lock());
	m_sessions.erase(it);

	try {
		send(fetch_uuid, Msg::CS_FetchClose(err_code));
	} catch(std::exception &e){
		LOG_MEDUSA_ERROR("std::exception thrown: what = ", e.what());
		force_shutdown();
	}

	if(session){
		session->on_fetch_closed(err_code, err_msg);
	}
}

}
