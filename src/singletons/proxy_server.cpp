#include "../precompiled.hpp"
#include <poseidon/tcp_server_base.hpp>
#include <poseidon/singletons/epoll_daemon.hpp>
#include <poseidon/http/authorization.hpp>
#include "../proxy_session.hpp"

namespace Medusa {

namespace {
	class ProxyServer : public Poseidon::TcpServerBase {
	private:
		const boost::shared_ptr<const Poseidon::Http::AuthInfo> m_auth_info;

	public:
		ProxyServer(const Poseidon::IpPort &bind_addr, std::vector<std::string> auth)
			: Poseidon::TcpServerBase(bind_addr, NULLPTR, NULLPTR)
			, m_auth_info(Poseidon::Http::create_auth_info(STD_MOVE(auth)))
		{
		}

	public:
		boost::shared_ptr<Poseidon::TcpSessionBase> on_client_connect(Poseidon::Move<Poseidon::UniqueFile> client) const OVERRIDE {
			return boost::make_shared<ProxySession>(STD_MOVE(client), m_auth_info);
		}
	};
}

MODULE_RAII(handles){
	AUTO(bind, get_config<std::string>   ("proxy_server_bind", "0.0.0.0"));
	AUTO(port, get_config<unsigned>      ("proxy_server_port", 5322));
	AUTO(auth, get_config_v<std::string> ("proxy_http_auth_user_pass"));
	if(auth.empty()){
		LOG_MEDUSA_FATAL("You must provide at least one proxy_server_auth_user_pass.");
		DEBUG_THROW_ASSERT(false);
	}
	const Poseidon::IpPort bind_addr(Poseidon::SharedNts(bind), port);
	LOG_MEDUSA_INFO("Creating proxy HTTP server on ", bind_addr);
	AUTO(server, boost::make_shared<ProxyServer>(bind_addr, STD_MOVE(auth)));
	Poseidon::EpollDaemon::add_socket(server);
	handles.push(STD_MOVE_IDN(server));
}

}
