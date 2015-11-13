#include "precompiled.hpp"
#include "proxy_session.hpp"
#include <poseidon/string.hpp>
#include <poseidon/job_base.hpp>
#include <poseidon/http/exception.hpp>
#include "singletons/fetch_client.hpp"
#include "msg/error_codes.hpp"

namespace Medusa {

namespace {
	const std::string STR_CONNECTION_ESTABLISHED = "Connection established";
	const std::string STR_KEEP_ALIVE             = "Keep-Alive";
	const std::string STR_CLOSE                  = "Close";
}

namespace Impl {
	void Impl::ProxySessionServerAdaptor::on_request_headers(
		Poseidon::Http::RequestHeaders request_headers, std::string transfer_encoding, boost::uint64_t content_length)
	{
		static_cast<ProxySession *>(this)->
			on_sync_server_request_headers(STD_MOVE(request_headers), STD_MOVE(transfer_encoding), content_length);
	}
	void Impl::ProxySessionServerAdaptor::on_request_entity(
		boost::uint64_t entity_offset, bool is_chunked, Poseidon::StreamBuffer entity)
	{
		static_cast<ProxySession *>(this)->
			on_sync_server_request_entity(entity_offset, is_chunked, STD_MOVE(entity));
	}
	bool Impl::ProxySessionServerAdaptor::on_request_end(
		boost::uint64_t content_length, bool is_chunked, Poseidon::OptionalMap headers)
	{
		return static_cast<ProxySession *>(this)->
			on_sync_server_request_end(content_length, is_chunked, STD_MOVE(headers));
	}

	long Impl::ProxySessionServerAdaptor::on_encoded_data_avail(
		Poseidon::StreamBuffer encoded)
	{
		PROFILE_ME;

		return static_cast<ProxySession *>(this)->send(STD_MOVE(encoded));
	}

	void Impl::ProxySessionClientAdaptor::on_response_headers(
		Poseidon::Http::ResponseHeaders response_headers, std::string transfer_encoding, boost::uint64_t content_length)
	{
		static_cast<ProxySession *>(this)->
			on_sync_client_response_headers(STD_MOVE(response_headers), STD_MOVE(transfer_encoding), content_length);
	}
	void Impl::ProxySessionClientAdaptor::on_response_entity(
		boost::uint64_t entity_offset, bool is_chunked, Poseidon::StreamBuffer entity)
	{
		static_cast<ProxySession *>(this)->
			on_sync_client_response_entity(entity_offset, is_chunked, STD_MOVE(entity));
	}
	bool Impl::ProxySessionClientAdaptor::on_response_end(
		boost::uint64_t content_length, bool is_chunked, Poseidon::OptionalMap headers)
	{
		return static_cast<ProxySession *>(this)->
			on_sync_client_response_end(content_length, is_chunked, STD_MOVE(headers));
	}

	long Impl::ProxySessionClientAdaptor::on_encoded_data_avail(Poseidon::StreamBuffer encoded){
		PROFILE_ME;

		const AUTO(fetch_client, static_cast<ProxySession *>(this)->m_fetch_client.lock());
		if(!fetch_client){
			return false;
		}
		return fetch_client->send(static_cast<ProxySession *>(this)->m_fetch_uuid, STD_MOVE(encoded));
	}
}

class ProxySession::CloseJob : public Poseidon::JobBase {
private:
	const boost::weak_ptr<ProxySession> m_session;
	const Poseidon::Uuid m_fetch_uuid;
	const boost::weak_ptr<FetchClient> m_fetch_client;
	const int m_err_code;

public:
	CloseJob(const boost::shared_ptr<ProxySession> &session, int err_code)
		: m_session(session), m_fetch_uuid(session->m_fetch_uuid), m_fetch_client(session->m_fetch_client)
		, m_err_code(err_code)
	{
	}

protected:
	boost::weak_ptr<const void> get_category() const FINAL {
		return m_session;
	}
	void perform() FINAL {
		PROFILE_ME;

		const AUTO(fetch_client, m_fetch_client.lock());
		if(!fetch_client){
			return;
		}
		fetch_client->close(m_fetch_uuid, Msg::ST_OK, m_err_code, "Requested by proxy client");
	}
};

class ProxySession::ReadAvailJob : public Poseidon::JobBase {
private:
	const boost::weak_ptr<ProxySession> m_session;

	Poseidon::StreamBuffer m_data;

public:
	ReadAvailJob(const boost::shared_ptr<ProxySession> &session, Poseidon::StreamBuffer data)
		: m_session(session), m_data(STD_MOVE(data))
	{
	}

protected:
	boost::weak_ptr<const void> get_category() const FINAL {
		return m_session;
	}
	void perform() FINAL {
		PROFILE_ME;

		const AUTO(session, m_session.lock());
		if(!session){
			return;
		}

		try {
			session->on_sync_read_avail(STD_MOVE(m_data));
		} catch(Poseidon::Http::Exception &e){
			LOG_MEDUSA_INFO("Http::Exception thrown: status_code = ", e.status_code(), ", what = ", e.what());
			session->shutdown(e.status_code(), e.headers(), e.what());
		} catch(std::exception &e){
			LOG_MEDUSA_INFO("std::exception thrown: what = ", e.what());
			session->shutdown(Poseidon::Http::ST_BAD_GATEWAY, VAL_INIT, e.what());
		}
	}
};

ProxySession::ProxySession(Poseidon::UniqueFile socket)
	: Poseidon::TcpSessionBase(STD_MOVE(socket))
	, m_fetch_uuid(Poseidon::Uuid::random()), m_fetch_client(FetchClient::require())
	, m_state(S_HTTP_HEADERS), m_header_size(0)
{
	LOG_MEDUSA_INFO("Accepted proxy request from ", get_remote_info(), ": fetch_uuid = ", m_fetch_uuid);
}
ProxySession::~ProxySession(){
	try {
		LOG_MEDUSA_INFO("Shut down proxy request from ", get_remote_info(), ": fetch_uuid = ", m_fetch_uuid);
	} catch(...){
		LOG_MEDUSA_WARNING("Unknown proxy request remote address? fetch_uuid = ", m_fetch_uuid);
	}
}

void ProxySession::on_sync_read_avail(Poseidon::StreamBuffer data){
	PROFILE_ME;
	LOG_MEDUSA_DEBUG("Received data from proxy client: size = ", data.size());

	try {
		const AUTO(fetch_client, m_fetch_client.lock());
		if(!fetch_client){
			DEBUG_THROW(Poseidon::Http::Exception,
				Poseidon::Http::ST_BAD_GATEWAY, sslit("Lost connection to fetch server"));
		}

		if(m_state >= S_TUNNEL_CONNECTING){
			if(!fetch_client->send(m_fetch_uuid, STD_MOVE(data))){
				DEBUG_THROW(Poseidon::Http::Exception,
					Poseidon::Http::ST_GATEWAY_TIMEOUT, sslit("Could not send data to fetch server"));
			}
		} else {
			if(m_state == S_HTTP_HEADERS){
				const AUTO(max_header_size, get_config<boost::uint64_t>("proxy_http_header_max_header_size", 16384));
				if(m_header_size > max_header_size){
					DEBUG_THROW(Poseidon::Http::Exception,
						Poseidon::Http::ST_REQUEST_ENTITY_TOO_LARGE, sslit("Max request header size exceeded"));
				}
				m_header_size += data.size();
			}

			Poseidon::Http::ServerReader::put_encoded_data(STD_MOVE(data), true);

			if(m_state >= S_TUNNEL_CONNECTING){
				Poseidon::StreamBuffer queue;
				queue.swap(Poseidon::Http::ServerReader::get_queue());
				if(!queue.empty()){
					if(!fetch_client->send(m_fetch_uuid, STD_MOVE(queue))){
						DEBUG_THROW(Poseidon::Http::Exception,
							Poseidon::Http::ST_GATEWAY_TIMEOUT, sslit("Could not send data to fetch server"));
					}
				}
			}
		}
	} catch(Poseidon::Http::Exception &e){
		LOG_MEDUSA_INFO("Http::Exception thrown: status_code = ", e.status_code(), ", what = ", e.what());
		shutdown(e.status_code(), e.headers(), e.what());
	} catch(std::exception &e){
		LOG_MEDUSA_INFO("std::exception thrown: what = ", e.what());
		shutdown(Poseidon::Http::ST_BAD_GATEWAY, VAL_INIT, e.what());
	}
}
void ProxySession::shutdown(Poseidon::Http::StatusCode status_code, Poseidon::OptionalMap headers, const char *what) NOEXCEPT {
	PROFILE_ME;

	if(m_state == S_TUNNEL_ESTABLISHED){
		LOG_MEDUSA_DEBUG("Don't send HTTP response to a tunnel session. Shut it down immediately.");
		force_shutdown();
		return;
	}

	try {
		headers.set(sslit("Connection"), "Close");
		headers.set(sslit("Proxy-Connection"), "Close");

		Poseidon::Http::ResponseHeaders response_headers;
		response_headers.version = 10001;
		response_headers.status_code = status_code;
		response_headers.reason = Poseidon::Http::get_status_code_desc(status_code).desc_short;
		response_headers.headers = STD_MOVE(headers);
		if(what[0] == (char)0xFF){
			Poseidon::Http::ServerWriter::put_default_response(STD_MOVE(response_headers));
		} else if(what[0] == 0){
			Poseidon::Http::ServerWriter::put_response(STD_MOVE(response_headers), Poseidon::StreamBuffer("No reason given"));
		} else {
			Poseidon::Http::ServerWriter::put_response(STD_MOVE(response_headers), Poseidon::StreamBuffer(what));
		}
		shutdown_read();
		shutdown_write();
	} catch(...){
		force_shutdown();
	}
}

void ProxySession::on_sync_server_request_headers(
	Poseidon::Http::RequestHeaders request_headers, std::string /* transfer_encoding */, boost::uint64_t content_length)
{
	PROFILE_ME;
	LOG_MEDUSA_DEBUG("Proxy request header: fetch_uuid = ", m_fetch_uuid,
		", URI = ", request_headers.uri);

	if(request_headers.uri[0] == '/'){
		DEBUG_THROW(Poseidon::Http::Exception,
			Poseidon::Http::ST_NOT_FOUND, sslit("What do you wanna get from a proxy server by relative URI? :>"));
	}

	LOG_MEDUSA_INFO("Fetch URI: ", request_headers.uri);

	AUTO_REF(headers, request_headers.headers);

	// TODO 代理服务器登录。

	std::string host;
	unsigned port = 80;
	bool use_ssl = false;

	request_headers.uri = Poseidon::trim(STD_MOVE(request_headers.uri));
	AUTO(pos, request_headers.uri.find_first_not_of("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"));
	if((pos != std::string::npos) && (pos + 3 <= request_headers.uri.size()) && (request_headers.uri.compare(pos, 3, "://", 3) == 0)){
		request_headers.uri.at(pos) = 0;
		LOG_MEDUSA_DEBUG("Request protocol = ", request_headers.uri.c_str());
		if(::strcasecmp(request_headers.uri.c_str(), "http") == 0){
			// noop
		} else if(::strcasecmp(request_headers.uri.c_str(), "https") == 0){
			port = 443;
			use_ssl = true;
		} else {
			LOG_MEDUSA_DEBUG("Unknown protocol: ", request_headers.uri.c_str());
			DEBUG_THROW(Poseidon::Http::Exception,
				Poseidon::Http::ST_BAD_REQUEST, sslit("Unknown protocol"));
		}
		request_headers.uri.erase(0, pos + 3);
	}
	pos = request_headers.uri.find('/');
	if(pos != std::string::npos){
		host = request_headers.uri.substr(0, pos);
		request_headers.uri.erase(0, pos);
	} else {
		host = STD_MOVE(request_headers.uri);
		request_headers.uri = "/";
	}
	if(host[0] == '['){
		pos = host.find(']');
		if(pos == std::string::npos){
			LOG_MEDUSA_DEBUG("Invalid IPv6 address: host = ", host);
			DEBUG_THROW(Poseidon::Http::Exception, Poseidon::Http::ST_BAD_REQUEST);
		}
		pos = host.find(':', pos + 1);
	} else {
		pos = host.find(':');
	}
	if(pos != std::string::npos){
		char *endptr;
		port = std::strtoul(host.c_str() + pos + 1, &endptr, 10);
		if(*endptr){
			LOG_MEDUSA_DEBUG("Invalid port in host string: host = ", host);
			DEBUG_THROW(Poseidon::Http::Exception, Poseidon::Http::ST_BAD_REQUEST);
		}
		host.erase(pos);
	}

	bool keep_alive = true;
	if(request_headers.verb != Poseidon::Http::V_CONNECT){
		const AUTO_REF(connection, headers.get("Proxy-Connection"));
		if(request_headers.version < 10001){
			keep_alive = (::strcasecmp(connection.c_str(), STR_KEEP_ALIVE.c_str()) == 0);
		} else {
			keep_alive = (::strcasecmp(connection.c_str(), STR_CLOSE.c_str()) != 0);
		}
	}

	const AUTO(fetch_client, m_fetch_client.lock());
	if(!fetch_client){
		LOG_MEDUSA_DEBUG("Lost connection to fetch server");
		DEBUG_THROW(Poseidon::Http::Exception,
			Poseidon::Http::ST_BAD_GATEWAY, sslit("Lost connection to fetch server"));
	}
	if(!fetch_client->connect(virtual_shared_from_this<ProxySession>(), STD_MOVE(host), port, use_ssl, keep_alive)){
		LOG_MEDUSA_DEBUG("Could not send data to fetch server");
		DEBUG_THROW(Poseidon::Http::Exception,
			Poseidon::Http::ST_BAD_GATEWAY, sslit("Could not send data to fetch server"));
	}

	if(request_headers.verb == Poseidon::Http::V_CONNECT){
		LOG_MEDUSA_DEBUG("Preparing tunnel...");
		m_state = ProxySession::S_TUNNEL_CONNECTING;
	} else {
		headers.erase("Prxoy-Authenticate");
		headers.erase("Proxy-Connection");
		headers.erase("Upgrade");

		headers.set(sslit("Connection"), "Close");
		headers.set(sslit("X-Forwarded-For"), get_remote_info().ip.get());

		bool succeeded;
		if(content_length == Poseidon::Http::ServerReader::CONTENT_CHUNKED){
			succeeded = Poseidon::Http::ClientWriter::put_chunked_header(STD_MOVE(request_headers));
		} else {
			succeeded = Poseidon::Http::ClientWriter::put_request_headers(STD_MOVE(request_headers));
		}
		if(!succeeded){
			LOG_MEDUSA_DEBUG("Lost connection to fetch server");
			DEBUG_THROW(Exception, sslit("Lost connection to fetch server"));
		}

		m_state = ProxySession::S_HTTP_ENTITY;
	}
}
void ProxySession::on_sync_server_request_entity(
	boost::uint64_t entity_offset, bool is_chunked, Poseidon::StreamBuffer entity)
{
	PROFILE_ME;
	LOG_MEDUSA_DEBUG("Proxy request entity: fetch_uuid = ", m_fetch_uuid,
		", entity_offset = ", entity_offset, ", is_chunked = ", is_chunked, ", entity_size = ", entity.size());

	if(m_state >= ProxySession::S_TUNNEL_CONNECTING){
		return;
	}

	if(is_chunked){
		if(!Poseidon::Http::ClientWriter::put_chunk(STD_MOVE(entity))){
			LOG_MEDUSA_DEBUG("Lost connection to fetch server");
			DEBUG_THROW(Exception, sslit("Lost connection to fetch server"));
		}
	} else {
		if(!Poseidon::Http::ClientWriter::put_entity(STD_MOVE(entity))){
			LOG_MEDUSA_DEBUG("Lost connection to fetch server");
			DEBUG_THROW(Exception, sslit("Lost connection to fetch server"));
		}
	}
}
bool ProxySession::on_sync_server_request_end(
	boost::uint64_t content_length, bool is_chunked, Poseidon::OptionalMap headers)
{
	PROFILE_ME;
	LOG_MEDUSA_DEBUG("Proxy request end: fetch_uuid = ", m_fetch_uuid,
		", content_length = ", content_length, ", is_chunked = ", is_chunked);

	if(m_state >= ProxySession::S_TUNNEL_CONNECTING){
		return false;
	}

	if(is_chunked){
		if(!Poseidon::Http::ClientWriter::put_chunked_trailer(STD_MOVE(headers))){
			LOG_MEDUSA_DEBUG("Lost connection to fetch server");
			DEBUG_THROW(Exception, sslit("Lost connection to fetch server"));
		}
	}

	m_state = ProxySession::S_HTTP_HEADERS;
	m_header_size = 0;
	return true;
}

void ProxySession::on_sync_client_response_headers(
	Poseidon::Http::ResponseHeaders response_headers, std::string /* transfer_encoding */, boost::uint64_t content_length)
{
	PROFILE_ME;
	LOG_MEDUSA_DEBUG("Proxy response header: fetch_uuid = ", m_fetch_uuid,
		", status_code = ", response_headers.status_code, ", reason = ", response_headers.reason);

	m_content_length = content_length;
	m_entity_offset = 0;

	response_headers.version = 10001;
	AUTO_REF(headers, response_headers.headers);
	headers.erase("Connection");
	headers.erase("Prxoy-Authenticate");
	headers.erase("Upgrade");
	headers.set(sslit("Proxy-Connection"), m_keep_alive ? STR_KEEP_ALIVE : STR_CLOSE);

	Poseidon::Http::ServerWriter::put_chunked_header(STD_MOVE(response_headers));
}
void ProxySession::on_sync_client_response_entity(
	boost::uint64_t entity_offset, bool is_chunked, Poseidon::StreamBuffer entity)
{
	PROFILE_ME;
	LOG_MEDUSA_DEBUG("Proxy response entity: fetch_uuid = ", m_fetch_uuid,
		", entity_offset = ", entity_offset, ", is_chunked = ", is_chunked, ", entity_size = ", entity.size());

	if(entity.empty()){
		return;
	}

	m_entity_offset += entity.size();

	if(!entity.empty()){
		Poseidon::Http::ServerWriter::put_chunk(STD_MOVE(entity));
	}
}
bool ProxySession::on_sync_client_response_end(
	boost::uint64_t content_length, bool is_chunked, Poseidon::OptionalMap headers)
{
	PROFILE_ME;
	LOG_MEDUSA_DEBUG("Proxy response end: fetch_uuid = ", m_fetch_uuid,
		", content_length = ", content_length, ", is_chunked = ", is_chunked);

	Poseidon::Http::ServerWriter::put_chunked_trailer(STD_MOVE(headers));

	return true;
}

void ProxySession::on_close(int err_code) NOEXCEPT {
	PROFILE_ME;
	LOG_MEDUSA_DEBUG("Proxy session closed: err_code = ", err_code);

	const AUTO(fetch_client, m_fetch_client.lock());
	if(fetch_client){
		try {
			Poseidon::enqueue_job(boost::make_shared<CloseJob>(
				virtual_shared_from_this<ProxySession>(), err_code));
		} catch(std::exception &e){
			LOG_MEDUSA_ERROR("std::exception thrown: what = ", e.what());
			fetch_client->force_shutdown();
		}
	}

	Poseidon::TcpSessionBase::on_close(err_code);
}

void ProxySession::on_read_avail(Poseidon::StreamBuffer data){
	PROFILE_ME;

	Poseidon::enqueue_job(boost::make_shared<ReadAvailJob>(
		virtual_shared_from_this<ProxySession>(), STD_MOVE(data)));
}

bool ProxySession::send(Poseidon::StreamBuffer data){
	PROFILE_ME;

	return Poseidon::TcpSessionBase::send(STD_MOVE(data));
}

void ProxySession::on_fetch_connected(bool keep_alive){
	PROFILE_ME;
	LOG_MEDUSA_DEBUG("Received connect success from fetch server: fetch_uuid = ", m_fetch_uuid, ", keep_alive = ", keep_alive);

	m_keep_alive = keep_alive;
	m_content_length = WAITING_FOR_HEADERS;

	if(m_state == S_TUNNEL_CONNECTING){
		Poseidon::Http::ResponseHeaders response_headers;
		response_headers.version = 10000;
		response_headers.status_code = Poseidon::Http::ST_OK;
		response_headers.reason = STR_CONNECTION_ESTABLISHED;
		response_headers.headers.set(sslit("Proxy-Connection"), STR_KEEP_ALIVE);
		Poseidon::Http::ServerWriter::put_response(STD_MOVE(response_headers), VAL_INIT);

		LOG_MEDUSA_DEBUG("Tunnel established!");
		m_state = S_TUNNEL_ESTABLISHED;
	}
}
void ProxySession::on_fetch_received(Poseidon::StreamBuffer data){
	PROFILE_ME;
	LOG_MEDUSA_DEBUG("Received data from fetch server: fetch_uuid = ", m_fetch_uuid, ", size = ", data.size());

	try {
		if(m_state == S_TUNNEL_ESTABLISHED){
			send(STD_MOVE(data));
		} else {
			Poseidon::Http::ClientReader::put_encoded_data(STD_MOVE(data));

			if(m_state == S_TUNNEL_ESTABLISHED){
				Poseidon::StreamBuffer queue;
				queue.swap(Poseidon::Http::ClientReader::get_queue());
				if(!queue.empty()){
					send(STD_MOVE(queue));
				}
			}
		}

		boost::uint64_t keep_alive_timeout;
		if(m_state < S_TUNNEL_CONNECTING){
			keep_alive_timeout = get_config<boost::uint64_t>("proxy_http_keep_alive_timeout", 15000);
		} else {
			keep_alive_timeout = get_config<boost::uint64_t>("proxy_tunnel_keep_alive_timeout", 300000);
		}
		set_timeout(keep_alive_timeout);
	} catch(std::exception &e){
		LOG_MEDUSA_INFO("std::exception thrown: what = ", e.what());
		shutdown(Poseidon::Http::ST_BAD_GATEWAY, VAL_INIT, e.what());
	}
}
void ProxySession::on_fetch_ended(){
	PROFILE_ME;
	LOG_MEDUSA_DEBUG("Received EOF response from fetch server: fetch_uuid = ", m_fetch_uuid);

	if(m_state >= S_TUNNEL_CONNECTING){
		LOG_MEDUSA_DEBUG("Shutting down tunnel...");
		shutdown_read();
		shutdown_write();
		return;
	}

	if(m_content_length == WAITING_FOR_HEADERS){
		LOG_MEDUSA_DEBUG("No valid HTTP headers received from remote server");
		shutdown(Poseidon::Http::ST_BAD_GATEWAY, VAL_INIT, "No valid HTTP headers received from remote server");
		return;
	}
	if((m_content_length < Poseidon::Http::ClientReader::CONTENT_LENGTH_MAX) && (m_entity_offset != m_content_length)){
		LOG_MEDUSA_DEBUG("Contents truncated: entity_offset = ", m_entity_offset, ", content_length = ", m_content_length);
		shutdown_read();
		shutdown_write();
		return;
	}

	if(Poseidon::Http::ClientReader::is_content_till_eof()){
		Poseidon::Http::ClientReader::terminate_content();
	}

	if(!m_keep_alive){
		LOG_MEDUSA_DEBUG("Proxy-Connection was set to Close. Shut down now.");
		shutdown_read();
		shutdown_write();
		return;
	}
}
void ProxySession::on_fetch_closed(int cbpp_err_code, int sys_err_code, std::string err_msg){
	PROFILE_ME;
	LOG_MEDUSA_DEBUG("Received close response from fetch server: fetch_uuid = ", m_fetch_uuid,
		", cbpp_err_code = ", cbpp_err_code, ", sys_err_code = ", sys_err_code, ", err_msg = ", err_msg);

	if(cbpp_err_code == Msg::ST_OK){
		shutdown_read();
		shutdown_write();
		return;
	}

	char temp[256];
	unsigned len = (unsigned)std::sprintf(temp, "Fetch error %d (sys error %d): ", cbpp_err_code, sys_err_code);
	err_msg.insert(err_msg.begin(), temp, temp + len);
	shutdown(Poseidon::Http::ST_BAD_GATEWAY, VAL_INIT, err_msg.c_str());
}

}
