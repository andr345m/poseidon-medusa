#include "precompiled.hpp"
#include "proxy_session.hpp"
#include <poseidon/mutex.hpp>
#include <poseidon/http/upgraded_low_level_session_base.hpp>
#include <poseidon/http/exception.hpp>
#include <poseidon/http/utilities.hpp>
#include "singletons/fetch_client.hpp"
#include "msg/fetch.hpp"

namespace Medusa {

namespace {
	Poseidon::Mutex g_mapMutex;
	std::map<Poseidon::Uuid, ProxySession *> g_sessionMap;
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
		const AUTO(fetch, parent->m_fetch.lock());
		if(!fetch){
			LOG_MEDUSA_INFO("Lost connection to fetch server");
			forceShutdown();
			return;
		}

		fetch->send(parent->m_uuid, Msg::CS_FetchSend(std::string(static_cast<const char *>(data), size)));
		setTimeout(getConfig()->get<boost::uint64_t>("proxy_tunnel_keep_alive_timeout", 300000));
	}
};

boost::shared_ptr<ProxySession> ProxySession::findByUuid(const Poseidon::Uuid &uuid){
	PROFILE_ME;

	const Poseidon::Mutex::UniqueLock lock(g_mapMutex);
	const AUTO(it, g_sessionMap.find(uuid));
	if(it == g_sessionMap.end()){
		return VAL_INIT;
	}
	return it->second->virtualSharedFromThis<ProxySession>();
}
void ProxySession::shutdownAll(bool force){
	PROFILE_ME;

	const Poseidon::Mutex::UniqueLock lock(g_mapMutex);
	while(!g_sessionMap.empty()){
		if(force){
			g_sessionMap.begin()->second->forceShutdown();
		} else {
			g_sessionMap.begin()->second->shutdownRead();
			g_sessionMap.begin()->second->shutdownWrite();
		}
		g_sessionMap.erase(g_sessionMap.begin());
	}
}

ProxySession::ProxySession(Poseidon::UniqueFile socket)
	: Poseidon::Http::LowLevelSession(STD_MOVE(socket))
	, m_uuid(Poseidon::Uuid::random()), m_fetch(FetchClient::require())
	, m_tunnelEstablished(false)
{
	const Poseidon::Mutex::UniqueLock lock(g_mapMutex);
	g_sessionMap[m_uuid] = this;
}
ProxySession::~ProxySession(){
	const Poseidon::Mutex::UniqueLock lock(g_mapMutex);
	g_sessionMap.erase(m_uuid);
}

void ProxySession::onClose(int errCode) NOEXCEPT {
	PROFILE_ME;

	const AUTO(fetch, m_fetch.lock());
	if(fetch){
		try {
			fetch->send(m_uuid, Msg::CS_FetchClose(errCode));
		} catch(std::exception &e){
			LOG_MEDUSA_ERROR("std::exception thrown: what = ", e.what());
		}
	}

	Poseidon::Http::LowLevelSession::onClose(errCode);
}

boost::shared_ptr<Poseidon::Http::UpgradedLowLevelSessionBase>
	ProxySession::onLowLevelRequestHeaders(Poseidon::Http::RequestHeaders &requestHeaders, boost::uint64_t contentLength)
{
	PROFILE_ME;

	if(contentLength == CONTENT_CHUNKED){
		LOG_MEDUSA_DEBUG("Proxy HTTP chunked request: verb = ", Poseidon::Http::getStringFromVerb(requestHeaders.verb),
			", URI = ", requestHeaders.uri);
	} else {
		LOG_MEDUSA_DEBUG("Proxy HTTP request: verb = ", Poseidon::Http::getStringFromVerb(requestHeaders.verb),
			", URI = ", requestHeaders.uri, ", contentLength = ", contentLength);
	}

	const AUTO(fetch, m_fetch.lock());
	if(!fetch){
		LOG_MEDUSA_INFO("Lost connection to fetch server");
		DEBUG_THROW(Poseidon::Http::Exception, Poseidon::Http::ST_SERVICE_UNAVAILABLE);
	}

	std::string host;
	unsigned port;
	bool useSsl;

	if(::strncasecmp(requestHeaders.uri.c_str(), "https://", 8) == 0){
		requestHeaders.uri.erase(0, 8);
		host = STD_MOVE(requestHeaders.uri);
		port = 443;
		useSsl = true;
	} else {
		if(::strncasecmp(requestHeaders.uri.c_str(), "http://", 7) == 0){
			requestHeaders.uri.erase(0, 7);
		}
		host = STD_MOVE(requestHeaders.uri);
		port = 80;
		useSsl = false;
	}
	AUTO(pos, host.find('/'));
	if(pos != std::string::npos){
		requestHeaders.uri = host.substr(pos);
		host.erase(pos);
	} else {
		requestHeaders.uri = "/";
	}
	pos = host.find(':');
	if(pos != std::string::npos){
		port = boost::lexical_cast<unsigned>(host.substr(pos + 1));
		host.erase(pos);
	}
	LOG_MEDUSA_DEBUG("Request: host:port = ", host, ':', port, ", useSsl = ", useSsl, ", URI = ", requestHeaders.uri);
	fetch->send(m_uuid, Msg::CS_FetchConnect(STD_MOVE(host), port, useSsl));
	setTimeout(getConfig()->get<boost::uint64_t>("proxy_http_keep_alive_timeout", 15000));

	if(requestHeaders.verb == Poseidon::Http::V_CONNECT){
		return boost::make_shared<TunnelLowLevelSession>(virtualSharedFromThis<ProxySession>());
	}

	Poseidon::StreamBuffer data;

	data.put(Poseidon::Http::getStringFromVerb(requestHeaders.verb));
	data.put(' ');
	data.put(requestHeaders.uri);
	if(!requestHeaders.getParams.empty()){
		data.put('?');
		data.put(Poseidon::Http::urlEncodedFromOptionalMap(requestHeaders.getParams));
	}
	char temp[64];
	const unsigned verMajor = requestHeaders.version / 10000, verMinor = requestHeaders.version % 10000;
	unsigned len = (unsigned)std::sprintf(temp, " HTTP/%u.%u\r\n", verMajor, verMinor);
	data.put(temp, len);

	AUTO_REF(headers, requestHeaders.headers);
	{
		AUTO(it, headers.begin());
		while(it != headers.end()){
			if(std::strncmp(it->first, "Proxy-", 6) != 0){
				++it;
				continue;
			}
			headers.erase(it++);
		}

		it = headers.create("X-Forwarded-For");
		if(!it->second.empty()){
			it->second += ',';
		}
		it->second += getRemoteInfo().ip.get();

		if(contentLength != CONTENT_CHUNKED){
			headers.set("Content-Length", boost::lexical_cast<std::string>(contentLength));
		}
	}
	for(AUTO(it, headers.begin()); it != headers.end(); ++it){
		data.put(it->first.get());
		data.put(": ");
		data.put(it->second.data(), it->second.size());
		data.put("\r\n");
	}
	data.put("\r\n");

	if(!fetch->send(m_uuid, Msg::CS_FetchSend(data.dump()))){
		LOG_MEDUSA_INFO("Error sending data to fetch server");
		DEBUG_THROW(Poseidon::Http::Exception, Poseidon::Http::ST_SERVICE_UNAVAILABLE);
	}

	return VAL_INIT;
}

void ProxySession::onLowLevelRequest(Poseidon::Http::RequestHeaders requestHeaders, Poseidon::StreamBuffer entity){
	PROFILE_ME;

	const AUTO(fetch, m_fetch.lock());
	if(!fetch){
		LOG_MEDUSA_INFO("Lost connection to fetch server");
		DEBUG_THROW(Poseidon::Http::Exception, Poseidon::Http::ST_SERVICE_UNAVAILABLE);
	}

	AUTO_REF(headers, requestHeaders.headers);
	const AUTO_REF(transferEncodingStr, headers.get("Transfer-Encoding"));
	if(!transferEncodingStr.empty()){
		// 只有一个 chunk。
		char str[256];
		unsigned len = (unsigned)std::sprintf(str, "%llx\r\n", (unsigned long long)entity.size());

		Poseidon::StreamBuffer temp;
		temp.swap(entity);
		entity.put(str, len);
		entity.splice(temp);
		entity.put("\r\n0\r\n\r\n");
	}

	if(!fetch->send(m_uuid, Msg::CS_FetchSend(entity.dump()))){
		LOG_MEDUSA_INFO("Error sending data to fetch server");
		DEBUG_THROW(Poseidon::Http::Exception, Poseidon::Http::ST_SERVICE_UNAVAILABLE);
	}
}
void ProxySession::onLowLevelError(Poseidon::Http::StatusCode statusCode, Poseidon::OptionalMap headers){
	PROFILE_ME;

	sendDefault(statusCode, STD_MOVE(headers));
	shutdownRead();
	shutdownWrite();
}

bool ProxySession::notifyFetchConnected(){
	PROFILE_ME;

	const AUTO(tunnelSession, boost::dynamic_pointer_cast<TunnelLowLevelSession>(getUpgradedSession()));
	if(tunnelSession && !m_tunnelEstablished){
		sendDefault(Poseidon::Http::ST_OK);
		m_tunnelEstablished = true;
		return true;
	}
	return false;
}

bool ProxySession::sendRaw(Poseidon::StreamBuffer bytes){
	PROFILE_ME;

	return Poseidon::TcpSessionBase::send(STD_MOVE(bytes));
}

}
