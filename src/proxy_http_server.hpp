#ifndef MEDUSA_PROXY_HTTP_SERVER_HPP_
#define MEDUSA_PROXY_HTTP_SERVER_HPP_

#include <poseidon/tcp_server_base.hpp>

namespace Medusa {

class ProxyHttpSession;

class ProxyHttpServer : public Poseidon::TcpServerBase {
public:
	typedef Poseidon::TcpServerBase Base;

public:
	explicit ProxyHttpServer(const Poseidon::IpPort &bindAddr);
	~ProxyHttpServer();

protected:
	boost::shared_ptr<Poseidon::TcpSessionBase> onClientConnect(Poseidon::UniqueFile client) const OVERRIDE;
};

}

#endif
