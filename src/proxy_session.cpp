#include "precompiled.hpp"
#include "proxy_session.hpp"
#include <poseidon/string.hpp>
#include <poseidon/job_base.hpp>
#include <poseidon/http/client_reader.hpp>
#include <poseidon/http/client_writer.hpp>
#include <poseidon/http/exception.hpp>
#include <poseidon/http/const_strings.hpp>
#include "singletons/fetch_client.hpp"
#include "msg/error_codes.hpp"

namespace Medusa {

class ProxySession::CloseJob : public Poseidon::JobBase {
private:
	const boost::weak_ptr<ProxySession> m_session;
	const Poseidon::Uuid m_fetchUuid;
	const boost::weak_ptr<FetchClient> m_fetchClient;
	const int m_errCode;

public:
	CloseJob(const boost::shared_ptr<ProxySession> &session, int errCode)
		: m_session(session), m_fetchUuid(session->m_fetchUuid), m_fetchClient(session->m_fetchClient)
		, m_errCode(errCode)
	{
	}

protected:
	boost::weak_ptr<const void> getCategory() const FINAL {
		return m_session;
	}
	void perform() const FINAL {
		PROFILE_ME;

		const AUTO(fetchClient, m_fetchClient.lock());
		if(!fetchClient){
			return;
		}
		fetchClient->close(m_fetchUuid, m_errCode);
	}
};

class ProxySession::ReadAvailJob : public Poseidon::JobBase {
private:
	const boost::weak_ptr<ProxySession> m_session;

	mutable Poseidon::StreamBuffer m_data;

public:
	ReadAvailJob(const boost::shared_ptr<ProxySession> &session, Poseidon::StreamBuffer data)
		: m_session(session), m_data(STD_MOVE(data))
	{
	}

protected:
	boost::weak_ptr<const void> getCategory() const FINAL {
		return m_session;
	}
	void perform() const FINAL {
		PROFILE_ME;

		const AUTO(session, m_session.lock());
		if(!session){
			return;
		}

		try {
			session->onSyncReadAvail(STD_MOVE(m_data));
		} catch(TryAgainLater &){
			LOG_MEDUSA_FATAL("You are not allowed to throw TryAgainLater here.");
			std::abort();
		} catch(Poseidon::Http::Exception &e){
			LOG_MEDUSA_INFO("Http::Exception thrown: statusCode = ", e.statusCode(), ", what = ", e.what());
			session->shutdown(e.statusCode(), e.headers(), e.what());
		} catch(std::exception &e){
			LOG_MEDUSA_INFO("std::exception thrown: what = ", e.what());
			session->shutdown(Poseidon::Http::ST_BAD_GATEWAY, VAL_INIT, e.what());
		}
	}
};

class ProxySession::ClientAdaptor : public Poseidon::Http::ClientReader, public Poseidon::Http::ClientWriter {
private:
	ProxySession *const m_session;

public:
	explicit ClientAdaptor(ProxySession *session)
		: m_session(session)
	{
	}

protected:
	void onResponseHeaders(Poseidon::Http::ResponseHeaders responseHeaders,
		std::string transferEncoding, boost::uint64_t /* contentLength */) OVERRIDE
	{
		PROFILE_ME;

		responseHeaders.version = 10001;

		AUTO_REF(headers, responseHeaders.headers);

		headers.erase("Connection");
		headers.erase("Prxoy-Authenticate");
		headers.erase("Upgrade");
		headers.erase("Content-Length");
		if(transferEncoding.empty()){
			headers.set("Transfer-Encoding", "chunked");
		}
		if(m_session->m_keepAlive){
			headers.set("Proxy-Connection", "Keep-Alive");
		} else {
			headers.set("Proxy-Connection", "Close");
		}
		m_session->Poseidon::Http::ServerWriter::putChunkedHeader(STD_MOVE(responseHeaders));
	}
	void onResponseEntity(boost::uint64_t /* entityOffset */, bool /* isChunked */, Poseidon::StreamBuffer entity) OVERRIDE {
		PROFILE_ME;

		if(entity.empty()){
			return;
		}

		m_session->Poseidon::Http::ServerWriter::putChunk(STD_MOVE(entity));
	}
	bool onResponseEnd(boost::uint64_t /* contentLength */, bool /* isChunked */, Poseidon::OptionalMap headers) OVERRIDE {
		PROFILE_ME;

		m_session->Poseidon::Http::ServerWriter::putChunkedTrailer(STD_MOVE(headers));

		return true;
	}

	long onEncodedDataAvail(Poseidon::StreamBuffer encoded) OVERRIDE {
		PROFILE_ME;

		const AUTO(fetchClient, m_session->m_fetchClient.lock());
		if(!fetchClient){
			return false;
		}
		return fetchClient->send(m_session->m_fetchUuid, STD_MOVE(encoded));
	}
};

ProxySession::ProxySession(Poseidon::UniqueFile socket)
	: Poseidon::TcpSessionBase(STD_MOVE(socket))
	, m_fetchUuid(Poseidon::Uuid::random()), m_fetchClient(FetchClient::require())
	, m_client(new ClientAdaptor(this))
	, m_state(S_HTTP_HEADERS), m_headerSize(0)
{
	LOG_MEDUSA_INFO("Accepted proxy request from ", getRemoteInfo());
}
ProxySession::~ProxySession(){
	try {
		LOG_MEDUSA_INFO("Shut down proxy request from ", getRemoteInfo());
	} catch(...){
		LOG_MEDUSA_WARNING("Unknown proxy request remote address?");
	}
}

void ProxySession::onSyncReadAvail(Poseidon::StreamBuffer data){
	PROFILE_ME;
	LOG_MEDUSA_DEBUG("Received data from proxy client: size = ", data.size());

	try {
		const AUTO(fetchClient, m_fetchClient.lock());
		if(!fetchClient){
			DEBUG_THROW(Poseidon::Http::Exception,
				Poseidon::Http::ST_BAD_GATEWAY, sslit("Lost connection to fetch server"));
		}

		if(m_state >= S_TUNNEL_CONNECTING){
			if(!fetchClient->send(m_fetchUuid, STD_MOVE(data))){
				DEBUG_THROW(Poseidon::Http::Exception,
					Poseidon::Http::ST_GATEWAY_TIMEOUT, sslit("Could not send data to fetch server"));
			}
		} else {
			if(m_state == S_HTTP_HEADERS){
				const AUTO(maxHeaderSize, getConfig<boost::uint64_t>("proxy_http_header_max_header_size", 16384));
				if(m_headerSize > maxHeaderSize){
					DEBUG_THROW(Poseidon::Http::Exception,
						Poseidon::Http::ST_REQUEST_ENTITY_TOO_LARGE, sslit("Max request header size exceeded"));
				}
				m_headerSize += data.size();
			}

			Poseidon::Http::ServerReader::putEncodedData(STD_MOVE(data));

			if(m_state >= S_TUNNEL_CONNECTING){
				Poseidon::StreamBuffer queue;
				queue.swap(Poseidon::Http::ServerReader::getQueue());
				if(!queue.empty()){
					if(!fetchClient->send(m_fetchUuid, STD_MOVE(queue))){
						DEBUG_THROW(Poseidon::Http::Exception,
							Poseidon::Http::ST_GATEWAY_TIMEOUT, sslit("Could not send data to fetch server"));
					}
				}
			}
		}
	} catch(Poseidon::Http::Exception &e){
		LOG_MEDUSA_INFO("Http::Exception thrown: statusCode = ", e.statusCode(), ", what = ", e.what());
		shutdown(e.statusCode(), e.headers(), e.what());
	} catch(std::exception &e){
		LOG_MEDUSA_INFO("std::exception thrown: what = ", e.what());
		shutdown(Poseidon::Http::ST_BAD_GATEWAY, VAL_INIT, e.what());
	}
}
void ProxySession::shutdown(Poseidon::Http::StatusCode statusCode, Poseidon::OptionalMap headers, const char *what) NOEXCEPT {
	PROFILE_ME;

	if(m_state == S_TUNNEL_ESTABLISHED){
		LOG_MEDUSA_DEBUG("Don't send HTTP response to a tunnel session. Shut it down immediately");
		forceShutdown();
		return;
	}

	try {
		headers.set("Proxy-Connection", "Close");

		Poseidon::Http::ResponseHeaders responseHeaders;
		responseHeaders.version = 10001;
		responseHeaders.statusCode = statusCode;
		responseHeaders.reason = Poseidon::Http::getStatusCodeDesc(statusCode).descShort;
		responseHeaders.headers = STD_MOVE(headers);
		if(what[0] == (char)0xFF){
			Poseidon::Http::ServerWriter::putDefaultResponse(STD_MOVE(responseHeaders));
		} else {
			Poseidon::Http::ServerWriter::putResponse(STD_MOVE(responseHeaders), Poseidon::StreamBuffer(what));
		}
		shutdownRead();
		shutdownWrite();
	} catch(...){
		forceShutdown();
	}
}

void ProxySession::onClose(int errCode) NOEXCEPT {
	PROFILE_ME;
	LOG_MEDUSA_DEBUG("Proxy session closed: errCode = ", errCode);

	const AUTO(fetchClient, m_fetchClient.lock());
	if(fetchClient){
		try {
			Poseidon::enqueueJob(boost::make_shared<CloseJob>(
				virtualSharedFromThis<ProxySession>(), errCode));
		} catch(std::exception &e){
			LOG_MEDUSA_ERROR("std::exception thrown: what = ", e.what());
			fetchClient->forceShutdown();
		}
	}

	Poseidon::TcpSessionBase::onClose(errCode);
}

void ProxySession::onReadAvail(Poseidon::StreamBuffer data){
	PROFILE_ME;

	Poseidon::enqueueJob(boost::make_shared<ReadAvailJob>(
		virtualSharedFromThis<ProxySession>(), STD_MOVE(data)));
}

bool ProxySession::send(Poseidon::StreamBuffer data){
	PROFILE_ME;

	return Poseidon::TcpSessionBase::send(STD_MOVE(data));
}

void ProxySession::onRequestHeaders(Poseidon::Http::RequestHeaders requestHeaders,
	std::string transferEncoding, boost::uint64_t contentLength)
{
	PROFILE_ME;
	LOG_MEDUSA_DEBUG("Proxy request header: fetchUuid = ", m_fetchUuid,
		", URI = ", requestHeaders.uri);

	if(requestHeaders.uri[0] == '/'){
		shutdown(Poseidon::Http::ST_OK, VAL_INIT,
			sslit("What do you wanna get from a proxy server by a relative URI? :>"));
		return;
	}

	AUTO_REF(headers, requestHeaders.headers);

	// TODO 代理服务器登录。

	std::string host;
	unsigned port = 80;
	bool useSsl = false;

	requestHeaders.uri = Poseidon::trim(STD_MOVE(requestHeaders.uri));
	AUTO(pos, requestHeaders.uri.find_first_not_of("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"));
	if((pos != std::string::npos) && (pos + 3 <= requestHeaders.uri.size()) && (requestHeaders.uri.compare(pos, 3, "://", 3) == 0)){
		requestHeaders.uri.at(pos) = 0;
		LOG_MEDUSA_DEBUG("Request protocol = ", requestHeaders.uri.c_str());
		if(::strcasecmp(requestHeaders.uri.c_str(), "http") == 0){
			// noop
		} else if(::strcasecmp(requestHeaders.uri.c_str(), "https") == 0){
			port = 443;
			useSsl = true;
		} else {
			LOG_MEDUSA_DEBUG("Unknown protocol: ", requestHeaders.uri.c_str());
			DEBUG_THROW(Poseidon::Http::Exception,
				Poseidon::Http::ST_BAD_REQUEST, sslit("Unknown protocol"));
		}
		requestHeaders.uri.erase(0, pos + 3);
	}
	pos = requestHeaders.uri.find('/');
	if(pos != std::string::npos){
		host = requestHeaders.uri.substr(0, pos);
		requestHeaders.uri.erase(0, pos);
	} else {
		host = STD_MOVE(requestHeaders.uri);
		requestHeaders.uri = "/";
	}
	pos = host.find(':');
	if(pos != std::string::npos){
		char *endptr;
		port = std::strtoul(host.c_str() + pos + 1, &endptr, 10);
		if(*endptr){
			LOG_MEDUSA_DEBUG("Invalid port in host string: host = ", host);
			DEBUG_THROW(Poseidon::Http::Exception, Poseidon::Http::ST_BAD_REQUEST);
		}
		host.erase(pos);
	}

	bool keepAlive = true;
	if(requestHeaders.verb != Poseidon::Http::V_CONNECT){
		const AUTO_REF(connection, headers.get("Proxy-Connection"));
		if(requestHeaders.version < 10001){
			keepAlive = (::strcasecmp(connection.c_str(), "Keep-Alive") == 0);
		} else {
			keepAlive = (::strcasecmp(connection.c_str(), "Close") != 0);
		}
	}

	const AUTO(fetchClient, m_fetchClient.lock());
	if(!fetchClient){
		LOG_MEDUSA_DEBUG("Lost connection to fetch server");
		DEBUG_THROW(Poseidon::Http::Exception,
			Poseidon::Http::ST_BAD_GATEWAY, sslit("Lost connection to fetch server"));
	}
	if(!fetchClient->connect(virtualSharedFromThis<ProxySession>(), STD_MOVE(host), port, useSsl, keepAlive)){
		LOG_MEDUSA_DEBUG("Could not send data to fetch server");
		DEBUG_THROW(Poseidon::Http::Exception,
			Poseidon::Http::ST_BAD_GATEWAY, sslit("Could not send data to fetch server"));
	}

	if(requestHeaders.verb != Poseidon::Http::V_CONNECT){
		headers.erase("Prxoy-Authenticate");
		headers.erase("Proxy-Connection");
		headers.erase("Upgrade");

		headers.set("Connection", "Close");
		headers.set("X-Forwarded-For", getRemoteInfo().ip.get());

		if(contentLength == 0){
			headers.set("Content-Length", Poseidon::Http::STR_0);
			headers.erase("Transfer-Encoding");
			if(!m_client->putRequest(STD_MOVE(requestHeaders))){
				LOG_MEDUSA_DEBUG("Lost connection to fetch server");
				DEBUG_THROW(Exception, sslit("Lost connection to fetch server"));
			}
			m_state = S_HTTP_IDENTITY;
		} else {
			headers.erase("Content-Length");
			if(transferEncoding.empty()){
				headers.set("Transfer-Encoding", "chunked");
			}
			if(!m_client->putChunkedHeader(STD_MOVE(requestHeaders))){
				LOG_MEDUSA_DEBUG("Lost connection to fetch server");
				DEBUG_THROW(Exception, sslit("Lost connection to fetch server"));
			}
			m_state = S_HTTP_CHUNKED;
		}
	} else {
		LOG_MEDUSA_DEBUG("Preparing tunnel...");
		m_state = S_TUNNEL_CONNECTING;
	}
}
void ProxySession::onRequestEntity(boost::uint64_t entityOffset, bool isChunked, Poseidon::StreamBuffer entity){
	PROFILE_ME;
	LOG_MEDUSA_DEBUG("Proxy request entity: fetchUuid = ", m_fetchUuid,
		", entityOffset = ", entityOffset, ", isChunked = ", isChunked, ", entitySize = ", entity.size());

	if(m_state >= S_TUNNEL_CONNECTING){
		return;
	}

	if(m_state == S_HTTP_IDENTITY){
		if(!entity.empty()){
			LOG_MEDUSA_ERROR("We only send empty bodies in identity mode, but entity is not empty.");
			DEBUG_THROW(Exception, sslit("Corrupted proxy session"));
		}
	} else if(m_state == S_HTTP_CHUNKED){
		if(!m_client->putChunk(STD_MOVE(entity))){
			LOG_MEDUSA_DEBUG("Lost connection to fetch server");
			DEBUG_THROW(Exception, sslit("Lost connection to fetch server"));
		}
	} else {
		LOG_MEDUSA_ERROR("Unexpected proxy session state: ", m_state);
		DEBUG_THROW(Exception, sslit("Unexpected proxy session state"));
	}
}
bool ProxySession::onRequestEnd(boost::uint64_t contentLength, bool isChunked, Poseidon::OptionalMap headers){
	PROFILE_ME;
	LOG_MEDUSA_DEBUG("Proxy request end: fetchUuid = ", m_fetchUuid,
		", contentLength = ", contentLength, ", isChunked = ", isChunked);

	if(m_state >= S_TUNNEL_CONNECTING){
		return false;
	}

	if(m_state == S_HTTP_IDENTITY){
		// noop
	} else if(m_state == S_HTTP_CHUNKED){
		if(!m_client->putChunkedTrailer(STD_MOVE(headers))){
			LOG_MEDUSA_DEBUG("Lost connection to fetch server");
			DEBUG_THROW(Exception, sslit("Lost connection to fetch server"));
		}
	} else {
		LOG_MEDUSA_ERROR("Unexpected proxy session state: ", m_state);
		DEBUG_THROW(Exception, sslit("Unexpected proxy session state"));
	}

	m_state = S_HTTP_HEADERS;
	m_headerSize = 0;
	return true;
}

long ProxySession::onEncodedDataAvail(Poseidon::StreamBuffer encoded){
	PROFILE_ME;

	return TcpSessionBase::send(STD_MOVE(encoded));
}

void ProxySession::onFetchConnected(bool keepAlive){
	PROFILE_ME;
	LOG_MEDUSA_DEBUG("Received connect success from fetch server, fetchUuid = ", m_fetchUuid, ", keepAlive = ", keepAlive);

	m_keepAlive = keepAlive;

	if(m_state == S_TUNNEL_CONNECTING){
		Poseidon::Http::ResponseHeaders responseHeaders;
		responseHeaders.version = 10001;
		responseHeaders.statusCode = Poseidon::Http::ST_OK;
		responseHeaders.reason = "Connection Established";
		Poseidon::Http::ServerWriter::putResponse(STD_MOVE(responseHeaders), VAL_INIT);

		LOG_MEDUSA_DEBUG("Tunnel established!");
		m_state = S_TUNNEL_ESTABLISHED;
	}
}
void ProxySession::onFetchReceived(Poseidon::StreamBuffer data){
	PROFILE_ME;
	LOG_MEDUSA_DEBUG("Received data from fetch server, fetchUuid = ", m_fetchUuid, ", size = ", data.size());

	try {
		if(m_state == S_TUNNEL_ESTABLISHED){
			send(STD_MOVE(data));
		} else {
			m_client->putEncodedData(STD_MOVE(data));

			if(m_state == S_TUNNEL_ESTABLISHED){
				Poseidon::StreamBuffer queue;
				queue.swap(m_client->getQueue());
				if(!queue.empty()){
					send(STD_MOVE(queue));
				}
			}
		}

		boost::uint64_t keepAliveTimeout;
		if(m_state < S_TUNNEL_CONNECTING){
			keepAliveTimeout = getConfig<boost::uint64_t>("proxy_http_keep_alive_timeout", 15000);
		} else {
			keepAliveTimeout = getConfig<boost::uint64_t>("proxy_tunnel_keep_alive_timeout", 300000);
		}
		setTimeout(keepAliveTimeout);
	} catch(std::exception &e){
		LOG_MEDUSA_INFO("std::exception thrown: what = ", e.what());
		shutdown(Poseidon::Http::ST_BAD_GATEWAY, VAL_INIT, e.what());
	}
}
void ProxySession::onFetchEnded(){
	PROFILE_ME;
	LOG_MEDUSA_DEBUG("Received EOF response from fetch server: fetch end, fetchUuid = ", m_fetchUuid);

	if(m_state >= S_TUNNEL_CONNECTING){
		LOG_MEDUSA_DEBUG("Shutting down tunnel...");
		shutdownRead();
		shutdownWrite();
		return;
	}

	if(m_client->isContentTillEof()){
		m_client->terminateContent();
	}

	AUTO_REF(queue, m_client->getQueue());
	if(!queue.empty()){
		LOG_MEDUSA_DEBUG("Invalid response from remote server. Terminate the connection.");
		shutdownRead();
		shutdownWrite();
		return;
	}

	if(!m_keepAlive){
		shutdownRead();
		shutdownWrite();
		return;
	}
}
void ProxySession::onFetchClosed(int cbppErrCode, int sysErrCode, std::string errMsg){
	PROFILE_ME;
	LOG_MEDUSA_DEBUG("Received close response from fetch server: fetch close, fetchUuid = ", m_fetchUuid,
		", cbppErrCode = ", cbppErrCode, ", sysErrCode = ", sysErrCode, ", errMsg = ", errMsg);

	if(cbppErrCode == Msg::ST_OK){
		shutdownRead();
		shutdownWrite();
		return;
	}

	shutdown(Poseidon::Http::ST_BAD_GATEWAY, VAL_INIT, errMsg.c_str());
}

}
