#include "precompiled.hpp"
#include <poseidon/singletons/epoll_daemon.hpp>
#include "proxy_http_server.hpp"
// #include "admin_http_server.hpp"

namespace Medusa {

DEFINE_MODULE_CONFIG("medusa.conf")

MODULE_RAII {
	AUTO(bind, getConfig()->get<std::string>("proxy_http_server_bind", "0.0.0.0"));
	AUTO(port, getConfig()->get<unsigned>("proxy_http_server_port", 5322));

	const Poseidon::IpPort bindAddr(SharedNts(bind), port);
	LOG_MEDUSA_INFO("Creating proxy HTTP server on ", bindAddr);
	AUTO(server, boost::make_shared<ProxyHttpServer>(bindAddr));
	Poseidon::EpollDaemon::registerServer(server);
	return STD_MOVE_IDN(server);
}
/*
MODULE_RAII {
	AUTO(bind, getConfig()->get<std::string>("admin_http_server_bind"));
	AUTO(port, getConfig()->get<unsigned>("admin_http_server_port", 5333));
	AUTO(cert, getConfig()->get<std::string>("admin_http_server_certificate"));
	AUTO(pkey, getConfig()->get<std::string>("admin_http_server_private_key"));
	AUTO(auth, getConfig()->getAll<std::string>("admin_http_auth_user_pass"));

	const Poseidon::IpPort bindAddr(SharedNts(bind), port);
	LOG_MEDUSA_INFO("Creating admin HTTP server on ", bindAddr);
	AUTO(server, boost::make_shared<AdminHttpServer>(bindAddr, cert, pkey, STD_MOVE(auth)));
	Poseidon::EpollDaemon::registerServer(server);
	return STD_MOVE_IDN(server);
}
*/
}
