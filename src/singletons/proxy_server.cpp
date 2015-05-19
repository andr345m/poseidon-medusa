#include "../precompiled.hpp"
#include <poseidon/tcp_server_base.hpp>
#include <poseidon/singletons/epoll_daemon.hpp>
#include "../proxy_session.hpp"

namespace Medusa {

namespace {
	class ProxyServer : public Poseidon::TcpServerBase {
	public:
		explicit ProxyServer(const Poseidon::IpPort &bindAddr)
			: Poseidon::TcpServerBase(bindAddr, NULLPTR, NULLPTR)
		{
		}

	public:
		boost::shared_ptr<Poseidon::TcpSessionBase> onClientConnect(Poseidon::UniqueFile client) const OVERRIDE {
//			return boost::make_shared<ProxySession>(STD_MOVE(client));
return {};
		}
	};
}

MODULE_RAII(handles){
	AUTO(bind, getConfig<std::string>("proxy_server_bind", "0.0.0.0"));
	AUTO(port, getConfig<unsigned>("proxy_server_port", 5322));

	const Poseidon::IpPort bindAddr(SharedNts(bind), port);
	LOG_MEDUSA_INFO("Creating proxy HTTP server on ", bindAddr);
	AUTO(server, boost::make_shared<ProxyServer>(bindAddr));
	Poseidon::EpollDaemon::registerServer(server);
	handles.push(STD_MOVE_IDN(server));
}

}
