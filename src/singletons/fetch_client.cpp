#include "../precompiled.hpp"
#include "fetch_client.hpp"
#include <poseidon/job_base.hpp>
#include <poseidon/singletons/timer_daemon.hpp>
#include <poseidon/cbpp/control_message.hpp>
#include <poseidon/cbpp/control_codes.hpp>
#include "../proxy_session.hpp"
#include "../encryption.hpp"
#include "../msg/cs_fetch.hpp"
#include "../msg/sc_fetch.hpp"
#include "../msg/error_codes.hpp"

namespace Medusa {

namespace {
	std::vector<boost::weak_ptr<FetchClient> > g_clients;
	std::size_t g_current_index = 0;

	boost::weak_ptr<FetchClient> &get_next_client_ref(){
		PROFILE_ME;

		if(g_clients.empty()){
			AUTO(count, get_config<std::size_t>("fetch_client_count", 5));
			if(count == 0){
				LOG_MEDUSA_WARNING("Fetch client count was set to zero? Corrected as one.");
				count = 1;
			}
			g_clients.resize(count);
		}

		if(++g_current_index >= g_clients.size()){
			g_current_index = 0;
		}
		return g_clients.at(g_current_index);
	}
}

class FetchClient::CloseJob : public Poseidon::JobBase {
private:
	const boost::shared_ptr<FetchClient> m_client;
	const int m_err_code;

public:
	CloseJob(const boost::shared_ptr<FetchClient> &client, int err_code)
		: m_client(client), m_err_code(err_code)
	{
	}

protected:
	boost::weak_ptr<const void> get_category() const FINAL {
		return m_client;
	}
	void perform() FINAL {
		PROFILE_ME;

		if(m_err_code == 0){
			m_client->clear(Msg::ST_OK, 0, "Connection to fetch server closed gracefully");
		} else {
			m_client->clear(Msg::ERR_CONNECTION_LOST, m_err_code, "Lost connection to fetch server");
		}
	}
};

boost::shared_ptr<FetchClient> FetchClient::get(){
	PROFILE_ME;

	const AUTO_REF(weak_client, get_next_client_ref());
	AUTO(client, weak_client.lock());
	return client;
}
boost::shared_ptr<FetchClient> FetchClient::require(){
	PROFILE_ME;

	AUTO_REF(weak_client, get_next_client_ref());
	AUTO(client, weak_client.lock());
	if(!client){
		AUTO(addr, get_config<std::string>("fetch_client_addr", "0.0.0.0"));
		AUTO(port, get_config<unsigned>("fetch_client_port", 5326));
		AUTO(hbtm, get_config<boost::uint64_t>("fetch_client_heartbeat_interval", 15000));
		AUTO(ssl,  get_config<bool>("fetch_client_uses_ssl", false));
		AUTO(pass, get_config<std::string>("fetch_client_password", ""));

		const Poseidon::IpPort addr_port(SharedNts(addr), port);
		client.reset(new FetchClient(addr_port, ssl, hbtm, STD_MOVE(pass)));
		client->go_resident();
		weak_client = client;
	}
	return client;
}

FetchClient::FetchClient(const Poseidon::IpPort &addr, bool use_ssl, boost::uint64_t keep_alive_interval, std::string password)
	: Poseidon::Cbpp::Client(addr, use_ssl, keep_alive_interval)
	, m_password(STD_MOVE(password))
{
	LOG_MEDUSA_INFO("Creating fetch client: addr = ", addr);
}
FetchClient::~FetchClient(){
	try {
		LOG_MEDUSA_INFO("Shutting down fetch client: addr = ", get_remote_info());
	} catch(...){
		LOG_MEDUSA_INFO("Shutting down fetch client: remote is not connected.");
	}

	clear(Msg::ERR_CONNECTION_LOST, ECONNRESET, "Lost connection to fetch server");
}

void FetchClient::on_close(int err_code) NOEXCEPT {
	PROFILE_ME;

	try {
		Poseidon::enqueue_job(boost::make_shared<CloseJob>(virtual_shared_from_this<FetchClient>(), err_code));
	} catch(std::exception &e){
		LOG_MEDUSA_ERROR("std::exception thrown: what = ", e.what());
	}

	Poseidon::Cbpp::Client::on_close(err_code);
}

bool FetchClient::send_data(const Poseidon::Uuid &fetch_uuid, boost::uint16_t message_id, Poseidon::StreamBuffer plain){
	PROFILE_ME;

	AUTO(pair, encrypt_header(fetch_uuid, m_password));
	AUTO(payload, encrypt_payload(pair.first, STD_MOVE(plain)));
	pair.second.splice(payload);
	return Poseidon::Cbpp::Client::send(message_id, STD_MOVE(pair.second));
}
bool FetchClient::send_control(Poseidon::Cbpp::ControlCode control_code, boost::int64_t vint_param, std::string string_param){
	PROFILE_ME;

	return Poseidon::Cbpp::Client::send_control(control_code, vint_param, STD_MOVE(string_param));
}

void FetchClient::on_sync_data_message_header(boost::uint16_t message_id, boost::uint64_t payload_size){
	PROFILE_ME;
	LOG_MEDUSA_DEBUG("Fetch data message header: message_id = ", message_id, ", payload_size = ", payload_size);

	const AUTO(header_size, get_encrypted_header_size());
	if(payload_size < header_size){
		LOG_MEDUSA_ERROR("Frame from fetch server is too small: expecting ", header_size, ", got ", payload_size);
		force_shutdown();
		return;
	}

	m_message_id = message_id;
	m_payload.clear();
}
void FetchClient::on_sync_data_message_payload(boost::uint64_t payload_offset, Poseidon::StreamBuffer payload){
	PROFILE_ME;
	LOG_MEDUSA_DEBUG("Fetch data message fragment: payload_offset = ", payload_offset, ", fragment_size = ", payload.size());

	m_payload.splice(payload);
}
void FetchClient::on_sync_data_message_end(boost::uint64_t payload_size){
	PROFILE_ME;
	LOG_MEDUSA_DEBUG("Fetch data message end: payload_size = ", payload_size);

	const AUTO(header_size, get_encrypted_header_size());
	if(m_payload.size() < header_size){
		LOG_MEDUSA_ERROR("Frame from fetch server is too small, expecting ", header_size);
		force_shutdown();
		return;
	}

	const AUTO(context, try_decrypt_header(m_payload, m_password));
	if(!context){
		LOG_MEDUSA_ERROR("Checksums mismatch. Maybe you provided a wrong password?");
		force_shutdown();
		return;
	}
	m_payload.discard(header_size);
	AUTO(plain, decrypt_payload(context, STD_MOVE(m_payload)));

	const AUTO_REF(fetch_uuid, context->uuid);
	LOG_MEDUSA_DEBUG("Fetch response: fetch_uuid = ", fetch_uuid, ", message_id = ", m_message_id);
	const AUTO(it, m_sessions.find(fetch_uuid));
	if(it == m_sessions.end()){
		LOG_MEDUSA_DEBUG("Proxy session has gone away: fetch_uuid = ", fetch_uuid);
		return;
	}
	const AUTO(session, it->second.lock());
	if(!session){
		LOG_MEDUSA_DEBUG("Shutting down expired proxy session: fetch_uuid = ", fetch_uuid);
		m_sessions.erase(it);
		send_data(fetch_uuid, Msg::CS_FetchClose(EPIPE));
		return;
	}
	switch(m_message_id){
		{{
#define ON_MESSAGE(Msg_, req_)	\
		}}	\
		break;	\
	case Msg_::ID: {	\
		Msg_ (req_)(plain);	\
		{ //
#define ON_RAW_MESSAGE(Msg_, req_)	\
		}}	\
		break;	\
	case Msg_::ID: {	\
		::Poseidon::StreamBuffer & (req_) = plain;	\
		{ //
//=============================================================================
	ON_MESSAGE(Msg::SC_FetchConnected, req){
		LOG_MEDUSA_DEBUG("Fetch connected: fetch_uuid = ", fetch_uuid, ", keep_alive = ", req.keep_alive);
		session->on_fetch_connected(req.keep_alive);
	}
	ON_RAW_MESSAGE(Msg::SC_FetchReceived, req){
		LOG_MEDUSA_DEBUG("Fetch received: fetch_uuid = ", fetch_uuid, ", size = ", req.size());
		session->on_fetch_received(STD_MOVE(req));
	}
	ON_MESSAGE(Msg::SC_FetchEnded, req){
		LOG_MEDUSA_DEBUG("Fetch ended: fetch_uuid = ", fetch_uuid);
		session->on_fetch_ended();
	}
	ON_MESSAGE(Msg::SC_FetchClosed, req){
		LOG_MEDUSA_DEBUG("Fetch closed: fetch_uuid = ", fetch_uuid,
			", cbpp_err_code = ", req.cbpp_err_code, ", sys_err_code = ", req.sys_err_code, ", err_msg = ", req.err_msg);
		try {
			session->on_fetch_closed(req.cbpp_err_code, req.sys_err_code, STD_MOVE(req.err_msg));
			session->shutdown_read();
			session->shutdown_write();
		} catch(std::exception &e){
			LOG_MEDUSA_ERROR("std::exception thrown: what = ", e.what());
			session->force_shutdown();
		}
		m_sessions.erase(it);
	}
//=============================================================================
		}}
		break;
	default:
		LOG_MEDUSA_ERROR("Unknown fetch response from server: message_id = ", m_message_id, ", size = ", plain.size());
		return;
	}
}

void FetchClient::on_sync_error_message(boost::uint16_t message_id, Poseidon::Cbpp::StatusCode status_code, std::string reason){
	PROFILE_ME;

	if((message_id != Poseidon::Cbpp::ControlMessage::ID) && (status_code != Msg::ST_OK)){
		LOG_MEDUSA_ERROR("Fetch error: message_id = ", message_id, ", status_code = ", status_code, ", reason = ", reason);
		force_shutdown();
	}

	Poseidon::Cbpp::Client::on_sync_error_message(message_id, status_code, STD_MOVE(reason));
}

bool FetchClient::connect(const boost::shared_ptr<ProxySession> &session, std::string host, unsigned port, bool use_ssl, bool keep_alive){
	PROFILE_ME;

	const AUTO(fetch_uuid, session->get_fetch_uuid());
	m_sessions[fetch_uuid] = session;
	return send_data(fetch_uuid, Msg::CS_FetchConnect(STD_MOVE(host), port, use_ssl, keep_alive));
}
bool FetchClient::send(const Poseidon::Uuid &fetch_uuid, Poseidon::StreamBuffer data){
	PROFILE_ME;

	if(m_sessions.find(fetch_uuid) == m_sessions.end()){
		LOG_MEDUSA_WARNING("Fetch client not connected? fetch_uuid = ", fetch_uuid);
		return false;
	}
	return send_data(fetch_uuid, Msg::CS_FetchSend::ID, STD_MOVE(data));
}
void FetchClient::close(const Poseidon::Uuid &fetch_uuid, int cbpp_err_code, int sys_err_code, const char *err_msg) NOEXCEPT {
	PROFILE_ME;

	const AUTO(it, m_sessions.find(fetch_uuid));
	if(it == m_sessions.end()){
		return;
	}

	const AUTO(session, it->second.lock());
	if(session){
		try {
			session->on_fetch_closed(cbpp_err_code, sys_err_code, err_msg);
			session->shutdown_read();
			session->shutdown_write();
		} catch(std::exception &e){
			LOG_MEDUSA_ERROR("std::exception thrown: what = ", e.what());
			session->force_shutdown();
		}
	}
	try {
		send_data(fetch_uuid, Msg::CS_FetchClose(sys_err_code));
	} catch(std::exception &e){
		LOG_MEDUSA_ERROR("std::exception thrown: what = ", e.what());
		force_shutdown();
	}
	m_sessions.erase(it);
}
void FetchClient::clear(int cbpp_err_code, int sys_err_code, const char *err_msg) NOEXCEPT {
	PROFILE_ME;

	for(AUTO(it, m_sessions.begin()); it != m_sessions.end(); ++it){
		const AUTO(session, it->second.lock());
		if(session){
			try {
				session->on_fetch_closed(cbpp_err_code, sys_err_code, err_msg);
				session->shutdown_read();
				session->shutdown_write();
			} catch(std::exception &e){
				LOG_MEDUSA_ERROR("std::exception thrown: what = ", e.what());
				session->force_shutdown();
			}
		}

		try {
			send_data(it->first, Msg::CS_FetchClose(sys_err_code));
		} catch(std::exception &e){
			LOG_MEDUSA_ERROR("std::exception thrown: what = ", e.what());
			force_shutdown();
		}
	}
	m_sessions.clear();
}

}
