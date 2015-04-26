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
boost::shared_ptr<Poseidon::Http::UpgradedSessionBase> ProxyHttpSession::onHeader(
	const Poseidon::Http::Header &header, boost::uint64_t contentLength)
{
	return Base::onHeader(header, contentLength);
}

void ProxyHttpSession::onRequest(const Poseidon::Http::Header &header, const Poseidon::StreamBuffer &entity){
	(void)header;
	(void)entity;

	sendDefault(Poseidon::Http::ST_FORBIDDEN, true);
}

}
