#include "precompiled.hpp"
#include "proxy_session.hpp"
#include <poseidon/http/upgraded_low_level_session_base.hpp>
#include <poseidon/http/exception.hpp>
#include "singletons/fetch_client.hpp"
#include "msg/fetch.hpp"

namespace Medusa {

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

		fetch->send(parent->m_uuid, Msg::CS_FetchSend::ID, Poseidon::StreamBuffer(data, size));
		setTimeout(getConfig()->get<boost::uint64_t>("proxy_tunnel_keep_alive_timeout", 300000));
	}
};

ProxySession::ProxySession(Poseidon::UniqueFile socket)
	: Poseidon::Http::LowLevelSession(STD_MOVE(socket))
	, m_uuid(Poseidon::Uuid::random()), m_fetch(FetchClient::require())
	, m_tunnelEstablished(false)
{
}
ProxySession::~ProxySession(){
	const AUTO(fetch, m_fetch.lock());
	if(fetch){
		fetch->unlink(m_uuid);
	}
}

void ProxySession::onClose(int errCode) NOEXCEPT {
	PROFILE_ME;
	LOG_MEDUSA_DEBUG("Proxy session closed: errCode = ", errCode);

	const AUTO(fetch, m_fetch.lock());
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
	Poseidon::Http::RequestHeaders &requestHeaders,
	const std::vector<std::string> & /* transferEncoding */, boost::uint64_t /* contentLength */)
{
	PROFILE_ME;
	LOG_MEDUSA_DEBUG("Proxy HTTP request from ", getRemoteInfo());

	Msg::CS_FetchRequestHeaders msg;
	msg.host = STD_MOVE(requestHeaders.uri);
	if(::strncasecmp(msg.host.c_str(), "https://", 8) == 0){
		msg.host.erase(0, 8);
		msg.port = 443;
		msg.useSsl = true;
	} else {
		if(::strncasecmp(msg.host.c_str(), "http://", 7) == 0){
			msg.host.erase(0, 7);
		}
		msg.port = 80;
		msg.useSsl = false;
	}
	AUTO(pos, msg.host.find('/'));
	if(pos != std::string::npos){
		msg.uri = msg.host.substr(pos);
		msg.host.erase(pos);
	} else {
		msg.uri = "/";
	}
	pos = msg.host.find(':');
	if(pos != std::string::npos){
		char *endptr;
		msg.port = std::strtoul(msg.host.c_str() + pos + 1, &endptr, 10);
		if(*endptr){
			LOG_MEDUSA_DEBUG("Invalid port in host string: ", msg.host);
			DEBUG_THROW(Poseidon::Http::Exception, Poseidon::Http::ST_BAD_REQUEST);
		}
		msg.host.erase(pos);
	}
	msg.xff = getRemoteInfo().ip.get();
	msg.verb = requestHeaders.verb;
	msg.uri = requestHeaders.uri;
	for(AUTO(it, requestHeaders.getParams.begin()); it != requestHeaders.getParams.end(); ++it){
		msg.getParams.push_back(VAL_INIT);
		msg.getParams.back().name = it->first.get();
		msg.getParams.back().value = STD_MOVE(it->second);
	}
	for(AUTO(it, requestHeaders.headers.begin()); it != requestHeaders.headers.end(); ++it){
		msg.headers.push_back(VAL_INIT);
		msg.headers.back().name = it->first.get();
		msg.headers.back().value = STD_MOVE(it->second);
	}

	const AUTO(fetch, m_fetch.lock());
	if(!fetch){
		LOG_MEDUSA_DEBUG("Lost connection to fetch server");
		DEBUG_THROW(Poseidon::Http::Exception, Poseidon::Http::ST_SERVICE_UNAVAILABLE);
	}
	fetch->link(virtualSharedFromThis<ProxySession>());
	if(!fetch->send(m_uuid, msg)){
		LOG_MEDUSA_DEBUG("Error sending data to fetch server");
		DEBUG_THROW(Poseidon::Http::Exception, Poseidon::Http::ST_SERVICE_UNAVAILABLE);
	}

	return VAL_INIT;
}

void ProxySession::onLowLevelRequest(Poseidon::Http::RequestHeaders /* requestHeaders */,
	std::vector<std::string> /* transferEncoding */, Poseidon::StreamBuffer entity)
{
	PROFILE_ME;

	const AUTO(fetch, m_fetch.lock());
	if(!fetch){
		LOG_MEDUSA_DEBUG("Lost connection to fetch server");
		forceShutdown();
		return;
	}
	if(!fetch->send(m_uuid, Msg::CS_FetchSend::ID, STD_MOVE(entity))){
		LOG_MEDUSA_DEBUG("Error sending data to fetch server");
		forceShutdown();
		return;
	}
}
void ProxySession::onLowLevelError(Poseidon::Http::StatusCode /* statusCode */, Poseidon::OptionalMap /* headers */){
	PROFILE_ME;

	forceShutdown();
}

bool ProxySession::sendRaw(Poseidon::StreamBuffer bytes){
	PROFILE_ME;

	return Poseidon::TcpSessionBase::send(STD_MOVE(bytes));
}

}
