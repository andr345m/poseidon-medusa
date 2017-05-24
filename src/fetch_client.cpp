#include "precompiled.hpp"
#include "fetch_client.hpp"
#include <poseidon/singletons/timer_daemon.hpp>
#include <poseidon/job_base.hpp>
#include <poseidon/zlib.hpp>
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
	LOG_MEDUSA_INFO("FetchClient constructor: remote = ", Poseidon::IpPort(sock_addr));
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

void FetchClient::on_sync_data_message(boost::uint16_t message_id, Poseidon::StreamBuffer payload){
	PROFILE_ME;
	LOG_MEDUSA_DEBUG("Fetch data message: message_id = ", message_id, ", payload_size = ", payload.size());

	Poseidon::Uuid fetch_uuid;
	Poseidon::StreamBuffer plain;
	if(!decrypt(fetch_uuid, plain, STD_MOVE(payload), m_password)){
		LOG_MEDUSA_ERROR("Error decrypting data from fetch server: remote = ", get_remote_info());
		DEBUG_THROW(Poseidon::Cbpp::Exception, Poseidon::Cbpp::ST_END_OF_STREAM, Poseidon::sslit("Error decrypting data from fetch server"));
	}
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
				PROFILE_ME;	\
				Msg_ (req_)(plain); \
				{ //
//=============================================================================
	ON_MESSAGE(Msg::SC_FetchConnected, resp){
		LOG_MEDUSA_DEBUG("Fetch connected: fetch_uuid = ", fetch_uuid, ", flags = ", resp.flags);
		session->on_fetch_connected(resp.flags);
	}
	ON_MESSAGE(Msg::SC_FetchReceived, resp){
		Poseidon::Inflator inflator;
		inflator.put(resp.recv_queue.data(), resp.recv_queue.size());
		AUTO(data, inflator.finalize());
		const AUTO(size, data.size());
		LOG_MEDUSA_DEBUG("Fetch received: fetch_uuid = ", fetch_uuid, ", size = ", size);
		session->on_fetch_received(STD_MOVE(data));
		send(fetch_uuid, Msg::CS_FetchAcknowledge(size));
	}
	ON_MESSAGE(Msg::SC_FetchEnded, resp){
		LOG_MEDUSA_DEBUG("Fetch ended: fetch_uuid = ", fetch_uuid);
		session->on_fetch_ended();
	}
	ON_MESSAGE(Msg::SC_FetchClosed, resp){
		LOG_MEDUSA_DEBUG("Fetch closed: fetch_uuid = ", fetch_uuid, ", err_code = ", resp.err_code, ", err_msg = ", resp.err_msg);
		session->on_fetch_closed(resp.err_code, resp.err_msg.c_str());
	}
//=============================================================================
#undef ON_MESSAGE
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
bool FetchClient::send(const Poseidon::Uuid &fetch_uuid, const Poseidon::Cbpp::MessageBase &msg){
	PROFILE_ME;

	Poseidon::StreamBuffer encrypted;
	encrypt(encrypted, fetch_uuid, Poseidon::StreamBuffer(msg), m_password);
	return Poseidon::Cbpp::Client::send(msg.get_id(), STD_MOVE(encrypted));
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
bool FetchClient::fetch_send(const boost::shared_ptr<ProxySession> &session, Poseidon::StreamBuffer send_queue){
	PROFILE_ME;

	const AUTO_REF(fetch_uuid, session->get_fetch_uuid());
	const AUTO(it, m_sessions.find(fetch_uuid));
	if(it == m_sessions.end()){
		LOG_MEDUSA_WARNING("Fetch client not connected? fetch_uuid = ", fetch_uuid);
		return false;
	}

	::boost::container::vector<unsigned char> temp;
	for(;;){
		temp.resize(8192);
		temp.resize(send_queue.get(temp.data(), temp.size()));
		if(temp.empty()){
			break;
		}
		Poseidon::Deflator deflator;
		deflator.put(temp.data(), temp.size());
		AUTO(data, deflator.finalize());
		temp.resize(data.size());
		data.get(temp.data(), temp.size());
		DEBUG_THROW_ASSERT(data.empty());
		send(fetch_uuid, Msg::CS_FetchSend(STD_MOVE(data)));
	}
	return true;
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
