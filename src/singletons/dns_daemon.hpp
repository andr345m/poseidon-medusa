#ifndef MEDUSA_SINGLETONS_DNS_DAEMON_HPP_
#define MEDUSA_SINGLETONS_DNS_DAEMON_HPP_

#include <string>
#include <boost/function.hpp>
#include <poseidon/sock_addr.hpp>

namespace Medusa {

struct DnsDaemon {
	typedef boost::function<
		void (const std::string &host, unsigned port, const Poseidon::SockAddr &addr)
		> SuccessCallback;

	typedef boost::function<
		// gaiCode 是 getaddrinfo() 的返回值，errCode 是 errno 当时的值。
		void (const std::string &host, unsigned port, int gaiCode, int errCode, const char *errMsg)
		> FailureCallback;

	static void asyncLookup(std::string host, unsigned port, SuccessCallback success, FailureCallback failure);

private:
	DnsDaemon();
};

}

#endif
