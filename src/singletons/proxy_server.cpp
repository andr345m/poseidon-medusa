#include "../precompiled.hpp"
#include <poseidon/tcp_server_base.hpp>
#include <poseidon/singletons/epoll_daemon.hpp>
#include "../proxy_session.hpp"

namespace Medusa {

namespace {
	class ProxyServer : public Poseidon::TcpServerBase {
	public:
		explicit ProxyServer(const Poseidon::IpPort &bind_addr)
			: Poseidon::TcpServerBase(bind_addr, NULLPTR, NULLPTR)
		{
		}

	public:
		boost::shared_ptr<Poseidon::TcpSessionBase> on_client_connect(Poseidon::UniqueFile client) const OVERRIDE {
			return boost::make_shared<ProxySession>(STD_MOVE(client));
		}
	};
}

MODULE_RAII(handles){
	AUTO(bind, get_config<std::string>("proxy_server_bind", "0.0.0.0"));
	AUTO(port, get_config<unsigned>("proxy_server_port", 5322));

	const Poseidon::IpPort bind_addr(Poseidon::SharedNts(bind), port);
	LOG_MEDUSA_INFO("Creating proxy HTTP server on ", bind_addr);
	AUTO(server, boost::make_shared<ProxyServer>(bind_addr));
	Poseidon::EpollDaemon::register_server(server);
	handles.push(STD_MOVE_IDN(server));
}

}
