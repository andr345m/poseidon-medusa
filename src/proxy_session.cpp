#include "precompiled.hpp"
#include "proxy_session.hpp"
#include <poseidon/string.hpp>
#include <poseidon/http/client_reader.hpp>
#include <poseidon/http/client_writer.hpp>
#include <poseidon/http/exception.hpp>
#include "singletons/fetch_client.hpp"
#include "msg/cs_fetch.hpp"
#include "msg/sc_fetch.hpp"

namespace Medusa {

/*
		safeForward(Poseidon::StreamBuffer(data, size));
		return;
	}

		const AUTO(maxHeaderSize, getConfig<boost::uint64_t>("proxy_http_header_max_header_size", 16384));
		if(m_headerSize > maxHeaderSize){
			DEBUG_THROW(Exception, ST_REQUEST_ENTITY_TOO_LARGE);
		}

		Poseidon::Http::ServerReader::putEncodedData(StreamBuffer(data, size));
	} catch(Poseidon::Http::Exception &e){
		LOG_MEDUSA_DEBUG("Http::Exception thrown in HTTP parser: statusCode = ", e.statusCode());
		sendDefault(e.statuaCode, e.headers());
		shutdownRead();
		shutdownWrite();
		return;
	}

	if(m_tunnelEstablished){
		AUTO_REF(queue, Poseidon::Http::ServerReader::::getQueue());
		if(!queue.empty()){
			safeForward(STD_MOVE(queue));
		}
	}



void ProxySession::onRequestHeaders(Poseidon::Http::RequestHeaders requestHeaders,
	std::string  transferEncoding , boost::uint64_t contentLength)
{
	PROFILE_ME;

	m_chunked = (contentLength == CONTENT_CHUNKED);

	const AUTO_REF(expect, requestHeaders.headers.get("Expect"));
	if(!expect.empty()){
		if(::strcasecmp(expect.c_str(), "100-continue") == 0){
			sendDefault(Poseidon::ST_CONTINUE):
		}
	}

	// TODO 添加代理服务器认证。

	std::string host;
	unsigned port = 80;
	bool useSsl = false;

	reqh.uri = Poseidon::trim(STD_MOVE(reqh.uri));
	AUTO(pos, reqh.uri.find_first_not_of("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"));
	if((pos != std::string::npos) && (pos + 3 <= reqh.uri.size()) && (reqh.uri.compare(pos, 3, "://", 3) == 0)){
		reqh.uri.at(pos) = 0;
		LOG_MEDUSA_DEBUG("Request protocol = ", reqh.uri.c_str());
		if(::strcasecmp(reqh.uri.c_str(), "http") == 0){
			// noop
		} else if(::strcasecmp(reqh.uri.c_str(), "https") == 0){
			msg.port = 443;
			msg.useSsl = true;
		} else {
			LOG_MEDUSA_DEBUG("Unknown protocol: ", reqh.uri.c_str());
			DEBUG_THROW(Poseidon::Http::Exception, Poseidon::Http::ST_BAD_REQUEST);
		}
		reqh.uri.erase(0, pos + 3);
	}
	pos = reqh.uri.find('/');
	if(pos != std::string::npos){
		host = reqh.uri.substr(0, pos);
		reqh.uri.erase(0, pos);
	} else {
		host = STD_MOVE(reqh.uri);
		reqh.uri = "/";
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
	safeForward(Msg::CS_FetchConnect(STD_MOVE(host), port, useSsl));

	
	msg.xff = getRemoteInfo().ip.get();
	msg.verb = reqh.verb;
	msg.uri = STD_MOVE(uri);

	for(AUTO(it, reqh.getParams.begin()); it != reqh.getParams.end(); ++it){
		msg.getParams.push_back(VAL_INIT);
		msg.getParams.back().name = it->first.get();
		msg.getParams.back().value = STD_MOVE(it->second);
	}

	for(AUTO(it, reqh.headers.begin()); it != reqh.headers.end(); ++it){
		msg.headers.push_back(VAL_INIT);
		msg.headers.back().name = it->first.get();
		msg.headers.back().value = STD_MOVE(it->second);
	}

	for(AUTO(it, transferEncoding.begin()); it != transferEncoding.end(); ++it){
		msg.transferEncoding.push_back(VAL_INIT);
		msg.transferEncoding.back().value = STD_MOVE(*it);
	}

	const AUTO(fetch, m_fetchClient.lock());
	if(!fetch){
		LOG_MEDUSA_DEBUG("Lost connection to fetch server");
		DEBUG_THROW(Poseidon::Http::Exception, Poseidon::Http::ST_SERVICE_UNAVAILABLE);
	}
	fetch->link(virtualSharedFromThis<ProxySession>());

	if(!fetch->send(m_uuid, msg)){
		LOG_MEDUSA_DEBUG("Error sending data to fetch server");
		DEBUG_THROW(Poseidon::Http::Exception, Poseidon::Http::ST_SERVICE_UNAVAILABLE);
	}

	requestHeaders.headers.erase("Proxy-

	m_headerSize = 0;
}
void ProxySession::onRequestEntity(boost::uint64_t  entityOffset , Poseidon::StreamBuffer entity){
	PROFILE_ME;

	safeForward(STD_MOVE(entity));
}
bool ProxySession::onRequestEnd(boost::uint64_t  contentLength , Poseidon::OptionalMap headers){
	PROFILE_ME;

	
}

long ProxySession::onEncodedDataAvail(Poseidon::StreamBuffer encoded){
	PROFILE_ME;

	return Poseidon::TcpSessionBase::send(STD_MOVE(encoded));
}

class ProxySession::TunnelLowLevelSession : public Poseidon::Http::UpgradedLowLevelSessionBase {
private:
	const boost::weak_ptr<ProxySession> m_parent;

public:
	TunnelLowLevelSession(const boost::shared_ptr<ProxySession> &parent)
		: Poseidon::Http::UpgradedLowLevelSessionBase(parent, std::string())
		, m_parent(STD_MOVE(parent))
	{
	}

protected:
	void onReadAvail(const void *data, std::size_t size) OVERRIDE {
		const AUTO(parent, m_parent.lock());
		if(!parent){
			return;
		}
		const AUTO(fetch, parent->m_fetchClient.lock());
		if(!fetch){
			LOG_MEDUSA_INFO("Lost connection to fetch server");
			forceShutdown();
			return;
		}

		fetch->send(parent->m_uuid, Msg::CS_FetchTunnelSend::ID, Poseidon::StreamBuffer(data, size));
		setTimeout(getConfig<boost::uint64_t>("proxy_tunnel_keep_alive_timeout", 300000));
	}
};

ProxySession::ProxySession(Poseidon::UniqueFile socket)
	: Poseidon::Http::LowLevelSession(STD_MOVE(socket))
	, m_uuid(Poseidon::Uuid::random()), m_fetchClient(FetchClient::require())
{
}
ProxySession::~ProxySession(){
	const AUTO(fetch, m_fetchClient.lock());
	if(fetch){
		fetch->unlink(m_uuid);
	}
}

void ProxySession::onClose(int errCode) NOEXCEPT {
	PROFILE_ME;
	LOG_MEDUSA_DEBUG("Proxy session closed: errCode = ", errCode);

	const AUTO(fetch, m_fetchClient.lock());
	if(fetch){
		try {
			fetch->send(m_uuid, Msg::CS_FetchClose(errCode));
		} catch(std::exception &e){
			LOG_MEDUSA_ERROR("std::exception thrown: what = ", e.what());
			fetch->forceShutdown();
		}
	}

	Poseidon::Http::LowLevelSession::onClose(errCode);
}

boost::shared_ptr<Poseidon::Http::UpgradedLowLevelSessionBase> ProxySession::onLowLevelRequestHeaders(
	Poseidon::Http::RequestHeaders &reqh,
	const std::vector<std::string> &transferEncoding, boost::uint64_t contentLength)
{
	PROFILE_ME;
	LOG_MEDUSA_DEBUG("Proxy HTTP request from ", getRemoteInfo());

	return VAL_INIT;
}

void ProxySession::onLowLevelRequest(Poseidon::Http::RequestHeaders  reqh ,
	std::vector<std::string>  transferEncoding , Poseidon::StreamBuffer entity)
{
	PROFILE_ME;

	const AUTO(fetch, m_fetchClient.lock());
	if(!fetch){
		LOG_MEDUSA_DEBUG("Lost connection to fetch server");
		forceShutdown();
		return;
	}

	if(!fetch->send(m_uuid, Msg::CS_FetchHttpSend::ID, STD_MOVE(entity))){
		LOG_MEDUSA_DEBUG("Error sending data to fetch server");
		forceShutdown();
		return;
	}
	setTimeout(getConfig<boost::uint64_t>("proxy_http_keep_alive_timeout", 15000));
}
void ProxySession::onLowLevelError(Poseidon::Http::StatusCode  statusCode , Poseidon::OptionalMap  headers ){
	PROFILE_ME;

	forceShutdown();
}

bool ProxySession::sendRaw(Poseidon::StreamBuffer bytes){
 	PROFILE_ME;

	return Poseidon::TcpSessionBase::send(STD_MOVE(bytes));
}
*/

class ProxySession::HttpClient/* : private Poseidon::Http::ClientReader, private Poseidon::Http::ClientWriter */{
private:
	ProxySession *const m_parent;

public:
	explicit HttpClient(ProxySession *parent)
		: m_parent(parent)
	{
	}
/*
protected:
	// ClientReader
	void onResponseHeaders(Poseidon::Http::ResponseHeaders responseHeaders, std::string transferEncoding, boost::uint64_t contentLength){
	}
	void onResponseEntity(boost::uint64_t entityOffset, Poseidon::StreamBuffer entity){
	}
	bool onResponseEnd(boost::uint64_t contentLength, bool isChunked, Poseidon::OptionalMap headers){
	}

	// ClientWriter
	long onEncodedDataAvail(Poseidon::StreamBuffer encoded){
	}
*/
public:
};

ProxySession::ProxySession(Poseidon::UniqueFile socket)
	: Poseidon::TcpSessionBase(STD_MOVE(socket))
	, m_fetchUuid(Poseidon::Uuid::random()), m_fetchClient(FetchClient::require()), m_httpClient(new HttpClient(this))
	, m_state(S_HTTP), m_headerSize(0)
{
}
ProxySession::~ProxySession(){
	const AUTO(fetch, m_fetchClient.lock());
	if(fetch){
		fetch->unlink(m_fetchUuid);
	}
}

void ProxySession::safeForward(Poseidon::StreamBuffer data){
	PROFILE_ME;

	try {
		const AUTO(fetch, m_fetchClient.lock());
		if(!fetch){
			LOG_MEDUSA_DEBUG("Lost connection to fetch server");
			DEBUG_THROW(Exception, sslit("Lost connection to fetch server"));
		}
		if(!fetch->send(m_fetchUuid, Msg::CS_FetchSend::ID, STD_MOVE(data))){
			LOG_MEDUSA_DEBUG("Error sending data to fetch server");
			DEBUG_THROW(Exception, sslit("Error sending data to fetch server"));
		}
	} catch(...){
		forceShutdown();
		throw;
	}
}

void ProxySession::onClose(int errCode) NOEXCEPT {
	PROFILE_ME;
	LOG_MEDUSA_DEBUG("Proxy session closed: errCode = ", errCode);

	const AUTO(fetch, m_fetchClient.lock());
	if(fetch){
		try {
			fetch->send(m_fetchUuid, Msg::CS_FetchClose(errCode));
		} catch(std::exception &e){
			LOG_MEDUSA_ERROR("std::exception thrown: what = ", e.what());
			fetch->forceShutdown();
		}
	}

	Poseidon::TcpSessionBase::onClose(errCode);
}

void ProxySession::onReadAvail(const void *data, std::size_t size){
	PROFILE_ME;
/*
	if(m_state ){
		safeForward(Poseidon::StreamBuffer(data, size));
		return;
	}

	try {
		const AUTO(maxHeaderSize, getConfig<boost::uint64_t>("proxy_http_header_max_header_size"));
		if(m_headerSize > maxHeaderSize){
			DEBUG_THROW(Exception, ST_REQUEST_ENTITY_TOO_LARGE);
		}

		Poseidon::Http::ServerReader::putEncodedData(StreamBuffer(data, size));
	} catch(Poseidon::Http::Exception &e){
		LOG_MEDUSA_DEBUG("Http::Exception thrown in HTTP parser: statusCode = ", e.statusCode());
		sendDefault(e.statusCode(), e.headers());
		shutdownRead();
		shutdownWrite();
		return;
	}

	if(m_tunnelEstablished){
		AUTO_REF(queue, ServerReader::getQueue());
		if(!queue.empty()){
			safeForward(Poseidon::StreamBuffer(data, size));
		}
	}
*/
}

void ProxySession::onRequestHeaders(Poseidon::Http::RequestHeaders requestHeaders, std::string transferEncoding, boost::uint64_t contentLength){
}
void ProxySession::onRequestEntity(boost::uint64_t entityOffset, Poseidon::StreamBuffer entity){
}
bool ProxySession::onRequestEnd(boost::uint64_t contentLength, bool isChunked, Poseidon::OptionalMap headers){
	return 0;
}

long ProxySession::onEncodedDataAvail(Poseidon::StreamBuffer encoded){
	return 0;
}

void ProxySession::onFetchConnect(){
	PROFILE_ME;
	LOG_MEDUSA_DEBUG("Fetch connect");

	
}
void ProxySession::onFetchReceive(Poseidon::StreamBuffer data){
	PROFILE_ME;
	LOG_MEDUSA_DEBUG("Fetch receive: dataSize = ", data.size());

}
void ProxySession::onFetchEnd(int errCode){
	PROFILE_ME;
	LOG_MEDUSA_DEBUG("Fetch end: errCode = ", errCode);

	if(errCode != 0){
		forceShutdown();
		return;
	}

}
void ProxySession::onFetchClose(int cbppErrCode, int sysErrCode, std::string errMsg) NOEXCEPT {
	PROFILE_ME;
	LOG_MEDUSA_DEBUG("Fetch close: cbppErrCode = ", cbppErrCode, ", sysErrCode = ", sysErrCode, ", errMsg = ", errMsg);

	forceShutdown();
}

}
