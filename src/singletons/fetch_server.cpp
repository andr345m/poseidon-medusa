#include "../precompiled.hpp"
#include <poseidon/tcp_server_base.hpp>
#include <poseidon/singletons/epoll_daemon.hpp>
#include "../fetch_session.hpp"

namespace Medusa {

namespace {
	class FetchServer : public Poseidon::TcpServerBase {
	private:
		const std::string m_password;

	public:
		FetchServer(const Poseidon::IpPort &bind_addr,
			const std::string &cert, const std::string &private_key, std::string password)
			: Poseidon::TcpServerBase(bind_addr, cert.c_str(), private_key.c_str())
			, m_password(STD_MOVE(password))
		{
		}

	public:
		boost::shared_ptr<Poseidon::TcpSessionBase> on_client_connect(Poseidon::UniqueFile client) const OVERRIDE {
			return boost::make_shared<FetchSession>(STD_MOVE(client), m_password);
		}
	};
}

MODULE_RAII(handles){
	AUTO(bind, get_config<std::string> ("fetch_server_bind",        "127.0.0.1"));
	AUTO(port, get_config<unsigned>    ("fetch_server_port",        5326));
	AUTO(cert, get_config<std::string> ("fetch_server_certificate", ""));
	AUTO(pkey, get_config<std::string> ("fetch_server_private_key", ""));
	AUTO(pass, get_config<std::string> ("fetch_server_password",    "password"));

	const Poseidon::IpPort bind_addr(Poseidon::SharedNts(bind), port);
	LOG_MEDUSA_INFO("Creating fetch CBPP server on ", bind_addr);
	AUTO(server, boost::make_shared<FetchServer>(bind_addr, cert, pkey, STD_MOVE(pass)));
	Poseidon::EpollDaemon::register_server(server);
	handles.push(STD_MOVE_IDN(server));
}

}
