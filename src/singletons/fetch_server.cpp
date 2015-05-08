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
		FetchServer(const Poseidon::IpPort &bindAddr,
			const std::string &cert, const std::string &privateKey, std::string password)
			: Poseidon::TcpServerBase(bindAddr, cert.c_str(), privateKey.c_str())
			, m_password(STD_MOVE(password))
		{
		}

	public:
		boost::shared_ptr<Poseidon::TcpSessionBase> onClientConnect(Poseidon::UniqueFile client) const OVERRIDE {
			return boost::make_shared<FetchSession>(STD_MOVE(client), m_password);
		}
	};
}

MODULE_RAII(handles){
	AUTO(bind, getConfig()->get<std::string>("fetch_server_bind", "127.0.0.1"));
	AUTO(port, getConfig()->get<unsigned>("fetch_server_port", 5326));
	AUTO(cert, getConfig()->get<std::string>("fetch_server_certificate"));
	AUTO(pkey, getConfig()->get<std::string>("fetch_server_private_key"));
	AUTO(pass, getConfig()->get<std::string>("fetch_server_password"));

	const Poseidon::IpPort bindAddr(SharedNts(bind), port);
	LOG_MEDUSA_INFO("Creating fetch CBPP server on ", bindAddr);
	AUTO(server, boost::make_shared<FetchServer>(bindAddr, cert, pkey, STD_MOVE(pass)));
	Poseidon::EpollDaemon::registerServer(server);
	handles.push(STD_MOVE_IDN(server));
}

}
