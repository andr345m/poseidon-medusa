#ifndef MEDUSA_SINGLETONS_DNS_DAEMON_HPP_
#define MEDUSA_SINGLETONS_DNS_DAEMON_HPP_

#include <string>
#include <boost/function.hpp>
#include <poseidon/fwd.hpp>

namespace Medusa {

struct DnsDaemon {
	static void syncLookUp(Poseidon::SockAddr &sockAddr, const std::string &host, unsigned port);

private:
	DnsDaemon();
};

}

#endif
