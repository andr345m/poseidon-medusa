#include "precompiled.hpp"
#include "proxy_http_session.hpp"
#include <poseidon/http/upgraded_session_base.hpp>
#include <poseidon/tcp_session_base.hpp>

namespace Medusa {

// class ProxyHttpSession::ProxyImpl : public Poseidon::

ProxyHttpSession::ProxyHttpSession(Poseidon::UniqueFile socket)
	: Base(STD_MOVE(socket))
{
}
ProxyHttpSession::~ProxyHttpSession(){
}

void ProxyHttpSession::onReadHup() NOEXCEPT {
	const AUTO(upgradedSession, getUpgradedSession());
	if(upgradedSession){
		const AUTO(client, upgradedSession->virtualSharedFromThis<Poseidon::TcpSessionBase>());
		if(client){
			client->forceShutdown(); // noexcept
		}
	}
}
boost::shared_ptr<Poseidon::Http::UpgradedSessionBase> ProxyHttpSession::onRequestHeaders(
	const Poseidon::Http::RequestHeaders &requestHeaders, boost::uint64_t contentLength)
{
	if(requestHeaders.verb == Poseidon::Http::V_CONNECT){
	}
	if(requestHeaders.uri[0] != '/'){
	}
	return Base::onRequestHeaders(requestHeaders, contentLength);
}

void ProxyHttpSession::onRequest(const Poseidon::Http::RequestHeaders &requestHeaders, const Poseidon::StreamBuffer &entity){
	(void)requestHeaders;
	(void)entity;

	sendDefault(Poseidon::Http::ST_FORBIDDEN, true);
}

}
