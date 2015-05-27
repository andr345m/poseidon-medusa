#ifndef MEDUSA_SINGLETONS_DNS_DAEMON_HPP_
#define MEDUSA_SINGLETONS_DNS_DAEMON_HPP_

#include <string>
#include <boost/function.hpp>
#include <poseidon/sock_addr.hpp>

namespace Medusa {

struct DnsDaemon {
	typedef boost::function<
		void (const std::string &host, unsigned port,
			// gaiCode 是 getaddrinfo() 的返回值。
			int gaiCode, const Poseidon::SockAddr &addr, const char *errMsg)
		> Callback;

	typedef boost::function<
		void ()
		> ExceptionCallback;

	// except 不是线程安全的。
	static void asyncLookup(std::string host, unsigned port, Callback callback,
		ExceptionCallback except = ExceptionCallback(), bool isLowLevel = false);

private:
	DnsDaemon();
};

}

#endif
