#include "precompiled.hpp"
#include "proxy_session.hpp"
#include <poseidon/job_base.hpp>
#include <poseidon/http/server_reader.hpp>
#include <poseidon/http/server_writer.hpp>
#include <poseidon/http/client_reader.hpp>
#include <poseidon/http/client_writer.hpp>
#include <poseidon/http/exception.hpp>
#include <poseidon/singletons/job_dispatcher.hpp>
#include "singletons/fetch_client.hpp"
#include "msg/error_codes.hpp"
#include "fetch_session.hpp"

namespace Medusa {

class ProxySession::RequestRewriter : public Poseidon::Http::ServerReader, public Poseidon::Http::ClientWriter {
private:
	ProxySession *const m_session;

	boost::uint64_t m_flags;

	boost::uint64_t m_header_size;
	bool m_headers_accepted;
	bool m_has_request_entity;

public:
	explicit RequestRewriter(ProxySession *session)
		: m_session(session)
		, m_flags(0)
		, m_header_size(0), m_headers_accepted(false), m_has_request_entity(false)
	{
	}

protected:
	// ServerReader
	void on_request_headers(Poseidon::Http::RequestHeaders request_headers, boost::uint64_t /* content_length */) OVERRIDE {
		PROFILE_ME;

		m_flags = 0;

		if(request_headers.uri[0] == '/'){
			DEBUG_THROW(Poseidon::Http::Exception, Poseidon::Http::ST_FORBIDDEN);
		}
		LOG_MEDUSA_INFO("New fetch request: ", Poseidon::Http::get_string_from_verb(request_headers.verb), " ", request_headers.uri);

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
				DEBUG_THROW(Poseidon::Http::Exception, Poseidon::Http::ST_BAD_REQUEST);
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
			const AUTO_REF(connection, request_headers.headers.get("Proxy-Connection"));
			if(request_headers.version < 10001){
				keep_alive = (::strcasecmp(connection.c_str(), "Keep-Alive") == 0);
			} else {
				keep_alive = (::strcasecmp(connection.c_str(), "Close") != 0);
			}
		}
		if(keep_alive){
			Poseidon::add_flags(m_flags, FetchSession::FL_KEEP_ALIVE);
		}

		if(request_headers.verb == Poseidon::Http::V_CONNECT){
			Poseidon::add_flags(m_flags, FetchSession::FL_TUNNEL);
		}

		const AUTO(fetch_client, m_session->m_fetch_client.lock());
		if(!fetch_client){
			LOG_MEDUSA_DEBUG("Lost connection to fetch server");
			DEBUG_THROW(Poseidon::Http::Exception, Poseidon::Http::ST_BAD_GATEWAY);
		}
		if(!fetch_client->connect(m_session->virtual_shared_from_this<ProxySession>(), STD_MOVE(host), port, use_ssl, m_flags)){
			LOG_MEDUSA_DEBUG("Could not send data to fetch server");
			DEBUG_THROW(Poseidon::Http::Exception, Poseidon::Http::ST_BAD_GATEWAY);
		}

		if(request_headers.verb != Poseidon::Http::V_CONNECT){
			request_headers.headers.erase("Prxoy-Authenticate");
			request_headers.headers.erase("Proxy-Connection");
			request_headers.headers.erase("Upgrade");
			request_headers.headers.erase("Connection");

			m_has_request_entity = false;
			if(request_headers.verb == Poseidon::Http::V_POST){
				m_has_request_entity = true;
			} else if(request_headers.verb == Poseidon::Http::V_PUT){
				m_has_request_entity = true;
			}
			if(m_has_request_entity){
				AUTO(transfer_encoding, request_headers.headers.get("Transfer-Encoding"));
				if(!transfer_encoding.empty()){
					transfer_encoding += ", ";
				}
				transfer_encoding += "chunked";
				request_headers.headers.set(Poseidon::sslit("Transfer-Encoding"), STD_MOVE(transfer_encoding));
			} else {
				request_headers.headers.erase("Content-Length");
				request_headers.headers.erase("Transfer-Encoding");
			}

			AUTO(x_forwarded_for, request_headers.headers.get("X-Forwarded-For"));
			if(!x_forwarded_for.empty()){
				x_forwarded_for += ", ";
			}
			x_forwarded_for += m_session->get_remote_info().ip.get();
			request_headers.headers.set(Poseidon::sslit("X-Forwarded-For"), STD_MOVE(x_forwarded_for));

			request_headers.headers.set(Poseidon::sslit("Connection"), "Close");

			if(m_has_request_entity){
				if(!Poseidon::Http::ClientWriter::put_chunked_header(STD_MOVE(request_headers))){
					LOG_MEDUSA_DEBUG("Lost connection to fetch server");
					DEBUG_THROW(Poseidon::Exception, Poseidon::sslit("Lost connection to fetch server"));
				}
			} else {
				if(!Poseidon::Http::ClientWriter::put_request(STD_MOVE(request_headers), Poseidon::StreamBuffer())){
					LOG_MEDUSA_DEBUG("Lost connection to fetch server");
					DEBUG_THROW(Poseidon::Exception, Poseidon::sslit("Lost connection to fetch server"));
				}
			}
			++(m_session->m_request_counter);
		}
	}
	void on_request_entity(boost::uint64_t /* entity_offset */, Poseidon::StreamBuffer entity) OVERRIDE {
		PROFILE_ME;

		if(m_has_request_entity){
			if(!Poseidon::Http::ClientWriter::put_chunk(STD_MOVE(entity))){
				LOG_MEDUSA_DEBUG("Lost connection to fetch server");
				DEBUG_THROW(Poseidon::Exception, Poseidon::sslit("Lost connection to fetch server"));
			}
		}
	}
	bool on_request_end(boost::uint64_t /* content_length */, Poseidon::OptionalMap headers) OVERRIDE {
		PROFILE_ME;

		if(m_has_request_entity){
			if(!Poseidon::Http::ClientWriter::put_chunked_trailer(STD_MOVE(headers))){
				LOG_MEDUSA_DEBUG("Lost connection to fetch server");
				DEBUG_THROW(Poseidon::Exception, Poseidon::sslit("Lost connection to fetch server"));
			}
		}

		m_header_size = 0;
		m_headers_accepted = false;
		m_has_request_entity = false;

		return true;
	}

	// ClientWriter
	long on_encoded_data_avail(Poseidon::StreamBuffer encoded) OVERRIDE {
		PROFILE_ME;

		const AUTO(fetch_client, m_session->m_fetch_client.lock());
		if(!fetch_client || !fetch_client->send(m_session->m_fetch_uuid, STD_MOVE(encoded))){
			LOG_MEDUSA_DEBUG("Lost connection to fetch server");
			DEBUG_THROW(Poseidon::Exception, Poseidon::sslit("Lost connection to fetch server"));
		}
		return true;
	}

public:
	void put_encoded_data(Poseidon::StreamBuffer data){
		PROFILE_ME;

		if(Poseidon::has_any_flags_of(m_flags, FetchSession::FL_TUNNEL)){
			on_encoded_data_avail(STD_MOVE(data));
		} else {
			m_header_size += data.size();
			Poseidon::Http::ServerReader::put_encoded_data(STD_MOVE(data));
			if(!m_headers_accepted){
				const AUTO(max_header_size, get_config<boost::uint64_t>("proxy_http_header_max_header_size", 16384));
				if(m_header_size > max_header_size){
					LOG_MEDUSA_WARNING("Too many HTTP headers: remote = ", m_session->get_remote_info(),
						", header_size = ", m_header_size, ", max_header_size = ", max_header_size);
					DEBUG_THROW(Poseidon::Http::Exception, Poseidon::Http::ST_BAD_REQUEST);
				}
			}
			if(Poseidon::has_any_flags_of(m_flags, FetchSession::FL_TUNNEL)){
				AUTO_REF(queue, Poseidon::Http::ServerReader::get_queue());
				if(!queue.empty()){
					on_encoded_data_avail(STD_MOVE(queue));
				}
			}
		}
	}
};

class ProxySession::ResponseRewriter : public Poseidon::Http::ClientReader, public Poseidon::Http::ServerWriter {
private:
	ProxySession *const m_session;

	boost::uint64_t m_flags;

	bool m_headers_received;

public:
	explicit ResponseRewriter(ProxySession *session)
		: m_session(session)
		, m_flags(0)
		, m_headers_received(false)
	{
	}

protected:
	// ClientReader
	void on_response_headers(Poseidon::Http::ResponseHeaders response_headers, boost::uint64_t /* content_length */) OVERRIDE {
		PROFILE_ME;

		response_headers.version = 10001;
		response_headers.headers.erase("Connection");
		response_headers.headers.erase("Prxoy-Authenticate");
		response_headers.headers.erase("Upgrade");
		response_headers.headers.erase("Connection");
		if(Poseidon::has_none_flags_of(m_flags, FetchSession::FL_KEEP_ALIVE)){
			response_headers.headers.set(Poseidon::sslit("Proxy-Connection"), "Close");
		} else {
			response_headers.headers.set(Poseidon::sslit("Proxy-Connection"), "Keep-Alive");
		}
		Poseidon::Http::ServerWriter::put_chunked_header(STD_MOVE(response_headers));
	}
	void on_response_entity(boost::uint64_t /* entity_offset */, Poseidon::StreamBuffer entity) OVERRIDE {
		PROFILE_ME;

		if(!entity.empty()){
			Poseidon::Http::ServerWriter::put_chunk(STD_MOVE(entity));
		}
	}
	bool on_response_end(boost::uint64_t /* content_length */, Poseidon::OptionalMap headers) OVERRIDE {
		PROFILE_ME;

		Poseidon::Http::ServerWriter::put_chunked_trailer(STD_MOVE(headers));

		m_headers_received = false;

		return true;
	}

	// ServerWriter
	long on_encoded_data_avail(Poseidon::StreamBuffer encoded) OVERRIDE {
		PROFILE_ME;

		return m_session->send(STD_MOVE(encoded));
	}

public:
	void put_flags(boost::uint64_t flags){
		PROFILE_ME;

		m_flags = flags;

		if(Poseidon::has_any_flags_of(m_flags, FetchSession::FL_TUNNEL)){
			Poseidon::Http::ResponseHeaders response_headers = { };
			response_headers.version = 10001;
			response_headers.status_code = Poseidon::Http::ST_OK;
			response_headers.reason = "Connection established";
			response_headers.headers.set(Poseidon::sslit("Proxy-Connection"), "Keep-Alive");
			Poseidon::Http::ServerWriter::put_response(STD_MOVE(response_headers), VAL_INIT);
		}
	}
	void put_encoded_data(Poseidon::StreamBuffer data){
		PROFILE_ME;

		if(Poseidon::has_any_flags_of(m_flags, FetchSession::FL_TUNNEL)){
			on_encoded_data_avail(STD_MOVE(data));
		} else {
			Poseidon::Http::ClientReader::put_encoded_data(STD_MOVE(data));
			if(Poseidon::has_any_flags_of(m_flags, FetchSession::FL_TUNNEL)){
				AUTO_REF(queue, Poseidon::Http::ClientReader::get_queue());
				if(!queue.empty()){
					on_encoded_data_avail(STD_MOVE(queue));
				}
			}
		}

		boost::uint64_t keep_alive_timeout;
		if(Poseidon::has_any_flags_of(m_flags, FetchSession::FL_TUNNEL)){
			keep_alive_timeout = get_config<boost::uint64_t>("proxy_tunnel_keep_alive_timeout", 300000);
		} else {
			keep_alive_timeout = get_config<boost::uint64_t>("proxy_http_keep_alive_timeout", 15000);
		}
		m_session->set_timeout(keep_alive_timeout);
	}
	void put_eof(){
		PROFILE_ME;

		if(Poseidon::Http::ClientReader::is_content_till_eof()){
			Poseidon::Http::ClientReader::terminate_content();
		}

		if(Poseidon::has_none_flags_of(m_flags, FetchSession::FL_KEEP_ALIVE)){
			m_session->shutdown_read();
			m_session->shutdown_write();
		}

		--(m_session->m_request_counter);
		if((m_session->m_request_counter == 0) && (m_session->has_been_shutdown_read())){
			m_session->shutdown_write();
		}
	}
	void put_default_response_if_not_tunnel(Poseidon::Http::StatusCode status_code){
		PROFILE_ME;

		if(Poseidon::has_any_flags_of(m_flags, FetchSession::FL_TUNNEL)){
			// Don't send anything.
		} else {
			Poseidon::Http::ResponseHeaders response_headers = { };
			response_headers.version = 10001;
			response_headers.status_code = status_code;
			response_headers.reason = Poseidon::Http::get_status_code_desc(status_code).desc_short;
			response_headers.headers.set(Poseidon::sslit("Connection"), "Close");
			response_headers.headers.set(Poseidon::sslit("Proxy-Connection"), "Close");
			Poseidon::Http::ServerWriter::put_default_response(STD_MOVE(response_headers));
		}
	}
};

class ProxySession::ReadHupJob : public Poseidon::JobBase {
private:
	const boost::weak_ptr<Poseidon::TcpSessionBase> m_category;
	const boost::weak_ptr<ProxySession> m_weak_session;

public:
	explicit ReadHupJob(const boost::shared_ptr<ProxySession> &session)
		: m_category(session), m_weak_session(session)
	{
	}

protected:
	boost::weak_ptr<const void> get_category() const FINAL {
		return m_category;
	}
	void perform() FINAL {
		PROFILE_ME;

		const AUTO(session, m_weak_session.lock());
		if(!session){
			return;
		}

		if(session->m_request_counter == 0){
			session->shutdown_write();
		}
	}
};

class ProxySession::CloseJob : public Poseidon::JobBase {
private:
	const boost::weak_ptr<Poseidon::TcpSessionBase> m_category;
	const boost::weak_ptr<ProxySession> m_weak_session;

	Poseidon::Uuid m_fetch_uuid;
	boost::weak_ptr<FetchClient> m_fetch_client;
	int m_err_code;

public:
	CloseJob(const boost::shared_ptr<ProxySession> &session, int err_code)
		: m_category(session), m_weak_session(session)
		, m_fetch_uuid(session->m_fetch_uuid), m_fetch_client(session->m_fetch_client), m_err_code(err_code)
	{
	}

protected:
	boost::weak_ptr<const void> get_category() const FINAL {
		return m_category;
	}
	void perform() FINAL {
		PROFILE_ME;

		const AUTO(fetch_client, m_fetch_client.lock());
		if(fetch_client){
			fetch_client->close(m_fetch_uuid, Msg::ST_OK, m_err_code, "Proxy client closed the connection");
		}
	}
};

class ProxySession::ReadAvailJob : public Poseidon::JobBase {
private:
	const boost::weak_ptr<Poseidon::TcpSessionBase> m_category;
	const boost::weak_ptr<ProxySession> m_weak_session;

	Poseidon::StreamBuffer m_data;

public:
	ReadAvailJob(const boost::shared_ptr<ProxySession> &session, Poseidon::StreamBuffer data)
		: m_category(session), m_weak_session(session)
		, m_data(STD_MOVE(data))
	{
	}

protected:
	boost::weak_ptr<const void> get_category() const FINAL {
		return m_category;
	}
	void perform() FINAL {
		PROFILE_ME;

		const AUTO(session, m_weak_session.lock());
		if(!session || session->has_been_shutdown_write()){
			return;
		}
		LOG_MEDUSA_DEBUG("Received data from proxy client: remote = ", session->get_remote_info(), ", size = ", m_data.size());

		try {
			AUTO_REF(rewriter, session->get_request_rewriter());
			rewriter.put_encoded_data(STD_MOVE(m_data));
		} catch(Poseidon::Http::Exception &e){
			LOG_MEDUSA_ERROR("Http::Exception thrown: status_code = ", e.get_status_code(), ", what = ", e.what());
			session->shutdown(e.get_status_code());
		} catch(std::exception &e){
			LOG_MEDUSA_ERROR("std::exception thrown: what = ", e.what());
			session->shutdown(Poseidon::Http::ST_INTERNAL_SERVER_ERROR);
		}
	}
};

ProxySession::ProxySession(Poseidon::UniqueFile socket)
	: Poseidon::TcpSessionBase(STD_MOVE(socket))
	, m_fetch_uuid(Poseidon::Uuid::random()), m_fetch_client(FetchClient::require())
	, m_request_counter(0)
{
	LOG_MEDUSA_INFO("ProxySession constructor: remote = ", get_remote_info(), ", fetch_uuid = ", m_fetch_uuid);
}
ProxySession::~ProxySession(){
	LOG_MEDUSA_INFO("ProxySession destructor: remote = ", get_remote_info_nothrow(), ", fetch_uuid = ", m_fetch_uuid);
}

ProxySession::RequestRewriter &ProxySession::get_request_rewriter(){
	PROFILE_ME;

	if(!m_request_rewriter){
		m_request_rewriter.reset(new RequestRewriter(this));
	}
	return *m_request_rewriter;
}
ProxySession::ResponseRewriter &ProxySession::get_response_rewriter(){
	PROFILE_ME;

	if(!m_response_rewriter){
		m_response_rewriter.reset(new ResponseRewriter(this));
	}
	return *m_response_rewriter;
}
void ProxySession::shutdown(unsigned http_status_code) NOEXCEPT {
	PROFILE_ME;

	try {
		AUTO_REF(rewriter, get_response_rewriter());
		rewriter.put_default_response_if_not_tunnel(http_status_code);
		shutdown_read();
		shutdown_write();
	} catch(std::exception &e){
		LOG_MEDUSA_ERROR("std::exception thrown: what = ", e.what());
		force_shutdown();
	}
}

void ProxySession::on_read_hup() NOEXCEPT {
	PROFILE_ME;
	LOG_MEDUSA_DEBUG("Proxy session read hang up.");

	try {
		Poseidon::JobDispatcher::enqueue(
			boost::make_shared<ReadHupJob>(
				virtual_shared_from_this<ProxySession>()),
			VAL_INIT);
	} catch(std::exception &e){
		LOG_MEDUSA_ERROR("std::exception thrown: what = ", e.what());
		force_shutdown();
	}

	Poseidon::TcpSessionBase::on_read_hup();
}
void ProxySession::on_close(int err_code) NOEXCEPT {
	PROFILE_ME;
	LOG_MEDUSA_DEBUG("Proxy session closed: err_code = ", err_code);

	try {
		Poseidon::JobDispatcher::enqueue(
			boost::make_shared<CloseJob>(
				virtual_shared_from_this<ProxySession>(), err_code),
			VAL_INIT);
	} catch(std::exception &e){
		LOG_MEDUSA_ERROR("std::exception thrown: what = ", e.what());
	}

	Poseidon::TcpSessionBase::on_close(err_code);
}
void ProxySession::on_read_avail(Poseidon::StreamBuffer data){
	PROFILE_ME;

	Poseidon::JobDispatcher::enqueue(
		boost::make_shared<ReadAvailJob>(
			virtual_shared_from_this<ProxySession>(), STD_MOVE(data)),
		VAL_INIT);
}
bool ProxySession::send(Poseidon::StreamBuffer data){
	PROFILE_ME;

	return Poseidon::TcpSessionBase::send(STD_MOVE(data));
}

void ProxySession::on_fetch_connected(boost::uint64_t flags){
	PROFILE_ME;
	LOG_MEDUSA_DEBUG("Received connect success from fetch server: fetch_uuid = ", m_fetch_uuid, ", flags = ", flags);

	try {
		AUTO_REF(rewriter, get_response_rewriter());
		rewriter.put_flags(flags);
	} catch(std::exception &e){
		LOG_MEDUSA_ERROR("std::exception thrown: what = ", e.what());
		force_shutdown();
	}
}
void ProxySession::on_fetch_received(Poseidon::StreamBuffer data){
	PROFILE_ME;
	LOG_MEDUSA_DEBUG("Received data from fetch server: fetch_uuid = ", m_fetch_uuid, ", size = ", data.size());

	try {
		AUTO_REF(rewriter, get_response_rewriter());
		rewriter.put_encoded_data(STD_MOVE(data));
	} catch(std::exception &e){
		LOG_MEDUSA_ERROR("std::exception thrown: what = ", e.what());
		force_shutdown();
	}
}
void ProxySession::on_fetch_ended(){
	PROFILE_ME;
	LOG_MEDUSA_DEBUG("Received EOF response from fetch server: fetch_uuid = ", m_fetch_uuid);

	try {
		AUTO_REF(rewriter, get_response_rewriter());
		rewriter.put_eof();
	} catch(std::exception &e){
		LOG_MEDUSA_ERROR("std::exception thrown: what = ", e.what());
		force_shutdown();
	}
}
void ProxySession::on_fetch_closed(int cbpp_err_code, int sys_err_code, const char *err_msg) NOEXCEPT {
	PROFILE_ME;
	LOG_MEDUSA_DEBUG("Received close response from fetch server: fetch_uuid = ", m_fetch_uuid,
		", cbpp_err_code = ", cbpp_err_code, ", sys_err_code = ", sys_err_code, ", err_msg = ", err_msg);

	if(cbpp_err_code == 0){
		// Proxy-Connection: Close
		shutdown_read();
		shutdown_write();
	} else {
		shutdown(Poseidon::Http::ST_BAD_GATEWAY);
	}
}

}
