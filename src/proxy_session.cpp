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
	void Impl::ProxySessionServerAdaptor::onRequestHeaders(
		Poseidon::Http::RequestHeaders requestHeaders, std::string transferEncoding, boost::uint64_t contentLength)
	{
		static_cast<ProxySession *>(this)->
			onSyncServerRequestHeaders(STD_MOVE(requestHeaders), STD_MOVE(transferEncoding), contentLength);
	}
	void Impl::ProxySessionServerAdaptor::onRequestEntity(
		boost::uint64_t entityOffset, bool isChunked, Poseidon::StreamBuffer entity)
	{
		static_cast<ProxySession *>(this)->
			onSyncServerRequestEntity(entityOffset, isChunked, STD_MOVE(entity));
	}
	bool Impl::ProxySessionServerAdaptor::onRequestEnd(
		boost::uint64_t contentLength, bool isChunked, Poseidon::OptionalMap headers)
	{
		return static_cast<ProxySession *>(this)->
			onSyncServerRequestEnd(contentLength, isChunked, STD_MOVE(headers));
	}

	long Impl::ProxySessionServerAdaptor::onEncodedDataAvail(
		Poseidon::StreamBuffer encoded)
	{
		PROFILE_ME;

		return static_cast<ProxySession *>(this)->send(STD_MOVE(encoded));
	}

	void Impl::ProxySessionClientAdaptor::onResponseHeaders(
		Poseidon::Http::ResponseHeaders responseHeaders, std::string transferEncoding, boost::uint64_t contentLength)
	{
		static_cast<ProxySession *>(this)->
			onSyncClientResponseHeaders(STD_MOVE(responseHeaders), STD_MOVE(transferEncoding), contentLength);
	}
	void Impl::ProxySessionClientAdaptor::onResponseEntity(
		boost::uint64_t entityOffset, bool isChunked, Poseidon::StreamBuffer entity)
	{
		static_cast<ProxySession *>(this)->
			onSyncClientResponseEntity(entityOffset, isChunked, STD_MOVE(entity));
	}
	bool Impl::ProxySessionClientAdaptor::onResponseEnd(
		boost::uint64_t contentLength, bool isChunked, Poseidon::OptionalMap headers)
	{
		return static_cast<ProxySession *>(this)->
			onSyncClientResponseEnd(contentLength, isChunked, STD_MOVE(headers));
	}

	long Impl::ProxySessionClientAdaptor::onEncodedDataAvail(Poseidon::StreamBuffer encoded){
		PROFILE_ME;

		const AUTO(fetchClient, static_cast<ProxySession *>(this)->m_fetchClient.lock());
		if(!fetchClient){
			return false;
		}
		return fetchClient->send(static_cast<ProxySession *>(this)->m_fetchUuid, STD_MOVE(encoded));
	}
}

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
	void perform() FINAL {
		PROFILE_ME;

		const AUTO(fetchClient, m_fetchClient.lock());
		if(!fetchClient){
			return;
		}
		fetchClient->close(m_fetchUuid, Msg::ST_OK, m_errCode, "Requested by proxy client");
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
	boost::weak_ptr<const void> getCategory() const FINAL {
		return m_session;
	}
	void perform() FINAL {
		PROFILE_ME;

		const AUTO(session, m_session.lock());
		if(!session){
			return;
		}

		try {
			session->onSyncReadAvail(STD_MOVE(m_data));
		} catch(Poseidon::Http::Exception &e){
			LOG_MEDUSA_INFO("Http::Exception thrown: statusCode = ", e.statusCode(), ", what = ", e.what());
			session->shutdown(e.statusCode(), e.headers(), e.what());
		} catch(std::exception &e){
			LOG_MEDUSA_INFO("std::exception thrown: what = ", e.what());
			session->shutdown(Poseidon::Http::ST_BAD_GATEWAY, VAL_INIT, e.what());
		}
	}
};

ProxySession::ProxySession(Poseidon::UniqueFile socket)
	: Poseidon::TcpSessionBase(STD_MOVE(socket))
	, m_fetchUuid(Poseidon::Uuid::random()), m_fetchClient(FetchClient::require())
	, m_state(S_HTTP_HEADERS), m_headerSize(0)
{
	LOG_MEDUSA_INFO("Accepted proxy request from ", getRemoteInfo(), ": fetchUuid = ", m_fetchUuid);
}
ProxySession::~ProxySession(){
	try {
		LOG_MEDUSA_INFO("Shut down proxy request from ", getRemoteInfo(), ": fetchUuid = ", m_fetchUuid);
	} catch(...){
		LOG_MEDUSA_WARNING("Unknown proxy request remote address? fetchUuid = ", m_fetchUuid);
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

			Poseidon::Http::ServerReader::putEncodedData(STD_MOVE(data), true);

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
		LOG_MEDUSA_DEBUG("Don't send HTTP response to a tunnel session. Shut it down immediately.");
		forceShutdown();
		return;
	}

	try {
		headers.set(sslit("Connection"), "Close");
		headers.set(sslit("Proxy-Connection"), "Close");

		Poseidon::Http::ResponseHeaders responseHeaders;
		responseHeaders.version = 10001;
		responseHeaders.statusCode = statusCode;
		responseHeaders.reason = Poseidon::Http::getStatusCodeDesc(statusCode).descShort;
		responseHeaders.headers = STD_MOVE(headers);
		if(what[0] == (char)0xFF){
			Poseidon::Http::ServerWriter::putDefaultResponse(STD_MOVE(responseHeaders));
		} else if(what[0] == 0){
			Poseidon::Http::ServerWriter::putResponse(STD_MOVE(responseHeaders), Poseidon::StreamBuffer("No reason given"));
		} else {
			Poseidon::Http::ServerWriter::putResponse(STD_MOVE(responseHeaders), Poseidon::StreamBuffer(what));
		}
		shutdownRead();
		shutdownWrite();
	} catch(...){
		forceShutdown();
	}
}

void ProxySession::onSyncServerRequestHeaders(
	Poseidon::Http::RequestHeaders requestHeaders, std::string /* transferEncoding */, boost::uint64_t contentLength)
{
	PROFILE_ME;
	LOG_MEDUSA_DEBUG("Proxy request header: fetchUuid = ", m_fetchUuid,
		", URI = ", requestHeaders.uri);

	if(requestHeaders.uri[0] == '/'){
		DEBUG_THROW(Poseidon::Http::Exception,
			Poseidon::Http::ST_NOT_FOUND, sslit("What do you wanna get from a proxy server by relative URI? :>"));
	}

	LOG_MEDUSA_INFO("Fetch URI: ", requestHeaders.uri);

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

	bool keepAlive = true;
	if(requestHeaders.verb != Poseidon::Http::V_CONNECT){
		const AUTO_REF(connection, headers.get("Proxy-Connection"));
		if(requestHeaders.version < 10001){
			keepAlive = (::strcasecmp(connection.c_str(), STR_KEEP_ALIVE.c_str()) == 0);
		} else {
			keepAlive = (::strcasecmp(connection.c_str(), STR_CLOSE.c_str()) != 0);
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

	if(requestHeaders.verb == Poseidon::Http::V_CONNECT){
		LOG_MEDUSA_DEBUG("Preparing tunnel...");
		m_state = ProxySession::S_TUNNEL_CONNECTING;
	} else {
		headers.erase("Prxoy-Authenticate");
		headers.erase("Proxy-Connection");
		headers.erase("Upgrade");

		headers.set(sslit("Connection"), "Close");
		headers.set(sslit("X-Forwarded-For"), getRemoteInfo().ip.get());

		bool succeeded;
		if(contentLength == Poseidon::Http::ServerReader::CONTENT_CHUNKED){
			succeeded = Poseidon::Http::ClientWriter::putChunkedHeader(STD_MOVE(requestHeaders));
		} else {
			succeeded = Poseidon::Http::ClientWriter::putRequestHeaders(STD_MOVE(requestHeaders));
		}
		if(!succeeded){
			LOG_MEDUSA_DEBUG("Lost connection to fetch server");
			DEBUG_THROW(Exception, sslit("Lost connection to fetch server"));
		}

		m_state = ProxySession::S_HTTP_ENTITY;
	}
}
void ProxySession::onSyncServerRequestEntity(
	boost::uint64_t entityOffset, bool isChunked, Poseidon::StreamBuffer entity)
{
	PROFILE_ME;
	LOG_MEDUSA_DEBUG("Proxy request entity: fetchUuid = ", m_fetchUuid,
		", entityOffset = ", entityOffset, ", isChunked = ", isChunked, ", entitySize = ", entity.size());

	if(m_state >= ProxySession::S_TUNNEL_CONNECTING){
		return;
	}

	if(isChunked){
		if(!Poseidon::Http::ClientWriter::putChunk(STD_MOVE(entity))){
			LOG_MEDUSA_DEBUG("Lost connection to fetch server");
			DEBUG_THROW(Exception, sslit("Lost connection to fetch server"));
		}
	} else {
		if(!Poseidon::Http::ClientWriter::putEntity(STD_MOVE(entity))){
			LOG_MEDUSA_DEBUG("Lost connection to fetch server");
			DEBUG_THROW(Exception, sslit("Lost connection to fetch server"));
		}
	}
}
bool ProxySession::onSyncServerRequestEnd(
	boost::uint64_t contentLength, bool isChunked, Poseidon::OptionalMap headers)
{
	PROFILE_ME;
	LOG_MEDUSA_DEBUG("Proxy request end: fetchUuid = ", m_fetchUuid,
		", contentLength = ", contentLength, ", isChunked = ", isChunked);

	if(m_state >= ProxySession::S_TUNNEL_CONNECTING){
		return false;
	}

	if(isChunked){
		if(!Poseidon::Http::ClientWriter::putChunkedTrailer(STD_MOVE(headers))){
			LOG_MEDUSA_DEBUG("Lost connection to fetch server");
			DEBUG_THROW(Exception, sslit("Lost connection to fetch server"));
		}
	}

	m_state = ProxySession::S_HTTP_HEADERS;
	m_headerSize = 0;
	return true;
}

void ProxySession::onSyncClientResponseHeaders(
	Poseidon::Http::ResponseHeaders responseHeaders, std::string /* transferEncoding */, boost::uint64_t contentLength)
{
	PROFILE_ME;
	LOG_MEDUSA_DEBUG("Proxy response header: fetchUuid = ", m_fetchUuid,
		", statusCode = ", responseHeaders.statusCode, ", reason = ", responseHeaders.reason);

	m_contentLength = contentLength;
	m_entityOffset = 0;

	responseHeaders.version = 10001;
	AUTO_REF(headers, responseHeaders.headers);
	headers.erase("Connection");
	headers.erase("Prxoy-Authenticate");
	headers.erase("Upgrade");
	headers.set(sslit("Proxy-Connection"), m_keepAlive ? STR_KEEP_ALIVE : STR_CLOSE);

	Poseidon::Http::ServerWriter::putChunkedHeader(STD_MOVE(responseHeaders));
}
void ProxySession::onSyncClientResponseEntity(
	boost::uint64_t entityOffset, bool isChunked, Poseidon::StreamBuffer entity)
{
	PROFILE_ME;
	LOG_MEDUSA_DEBUG("Proxy response entity: fetchUuid = ", m_fetchUuid,
		", entityOffset = ", entityOffset, ", isChunked = ", isChunked, ", entitySize = ", entity.size());

	if(entity.empty()){
		return;
	}

	m_entityOffset += entity.size();

	if(!entity.empty()){
		Poseidon::Http::ServerWriter::putChunk(STD_MOVE(entity));
	}
}
bool ProxySession::onSyncClientResponseEnd(
	boost::uint64_t contentLength, bool isChunked, Poseidon::OptionalMap headers)
{
	PROFILE_ME;
	LOG_MEDUSA_DEBUG("Proxy response end: fetchUuid = ", m_fetchUuid,
		", contentLength = ", contentLength, ", isChunked = ", isChunked);

	Poseidon::Http::ServerWriter::putChunkedTrailer(STD_MOVE(headers));

	return true;
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

void ProxySession::onFetchConnected(bool keepAlive){
	PROFILE_ME;
	LOG_MEDUSA_DEBUG("Received connect success from fetch server: fetchUuid = ", m_fetchUuid, ", keepAlive = ", keepAlive);

	m_keepAlive = keepAlive;
	m_contentLength = WAITING_FOR_HEADERS;

	if(m_state == S_TUNNEL_CONNECTING){
		Poseidon::Http::ResponseHeaders responseHeaders;
		responseHeaders.version = 10000;
		responseHeaders.statusCode = Poseidon::Http::ST_OK;
		responseHeaders.reason = STR_CONNECTION_ESTABLISHED;
		responseHeaders.headers.set(sslit("Proxy-Connection"), STR_KEEP_ALIVE);
		Poseidon::Http::ServerWriter::putResponse(STD_MOVE(responseHeaders), VAL_INIT);

		LOG_MEDUSA_DEBUG("Tunnel established!");
		m_state = S_TUNNEL_ESTABLISHED;
	}
}
void ProxySession::onFetchReceived(Poseidon::StreamBuffer data){
	PROFILE_ME;
	LOG_MEDUSA_DEBUG("Received data from fetch server: fetchUuid = ", m_fetchUuid, ", size = ", data.size());

	try {
		if(m_state == S_TUNNEL_ESTABLISHED){
			send(STD_MOVE(data));
		} else {
			Poseidon::Http::ClientReader::putEncodedData(STD_MOVE(data));

			if(m_state == S_TUNNEL_ESTABLISHED){
				Poseidon::StreamBuffer queue;
				queue.swap(Poseidon::Http::ClientReader::getQueue());
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
	LOG_MEDUSA_DEBUG("Received EOF response from fetch server: fetchUuid = ", m_fetchUuid);

	if(m_state >= S_TUNNEL_CONNECTING){
		LOG_MEDUSA_DEBUG("Shutting down tunnel...");
		shutdownRead();
		shutdownWrite();
		return;
	}

	if(m_contentLength == WAITING_FOR_HEADERS){
		LOG_MEDUSA_DEBUG("No valid HTTP headers received from remote server");
		shutdown(Poseidon::Http::ST_BAD_GATEWAY, VAL_INIT, "No valid HTTP headers received from remote server");
		return;
	}
	if((m_contentLength < Poseidon::Http::ClientReader::CONTENT_LENGTH_MAX) && (m_entityOffset != m_contentLength)){
		LOG_MEDUSA_DEBUG("Contents truncated: entityOffset = ", m_entityOffset, ", contentLength = ", m_contentLength);
		shutdownRead();
		shutdownWrite();
		return;
	}

	if(Poseidon::Http::ClientReader::isContentTillEof()){
		Poseidon::Http::ClientReader::terminateContent();
	}

	if(!m_keepAlive){
		LOG_MEDUSA_DEBUG("Proxy-Connection was set to Close. Shut down now.");
		shutdownRead();
		shutdownWrite();
		return;
	}
}
void ProxySession::onFetchClosed(int cbppErrCode, int sysErrCode, std::string errMsg){
	PROFILE_ME;
	LOG_MEDUSA_DEBUG("Received close response from fetch server: fetchUuid = ", m_fetchUuid,
		", cbppErrCode = ", cbppErrCode, ", sysErrCode = ", sysErrCode, ", errMsg = ", errMsg);

	if(cbppErrCode == Msg::ST_OK){
		shutdownRead();
		shutdownWrite();
		return;
	}

	char temp[256];
	unsigned len = (unsigned)std::sprintf(temp, "Fetch error %d (sys error %d): ", cbppErrCode, sysErrCode);
	errMsg.insert(errMsg.begin(), temp, temp + len);
	shutdown(Poseidon::Http::ST_BAD_GATEWAY, VAL_INIT, errMsg.c_str());
}

}
