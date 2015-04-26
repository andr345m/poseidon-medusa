#include "precompiled.hpp"
#include "proxy_http_server.hpp"
#include "proxy_http_session.hpp"

namespace Medusa {

ProxyHttpServer::ProxyHttpServer(const Poseidon::IpPort &bindAddr)
	: Base(bindAddr, NULLPTR, NULLPTR)
{
}
ProxyHttpServer::~ProxyHttpServer(){
}

boost::shared_ptr<Poseidon::TcpSessionBase> ProxyHttpServer::onClientConnect(Poseidon::UniqueFile client) const {
	return boost::make_shared<ProxyHttpSession>(STD_MOVE(client));
}

}
