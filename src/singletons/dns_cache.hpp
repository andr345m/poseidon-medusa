#ifndef MEDUSA_SINGLETONS_DNS_CACHE_HPP_
#define MEDUSA_SINGLETONS_DNS_CACHE_HPP_

#include <string>
#include <poseidon/shared_nts.hpp>

namespace Medusa {

struct DnsCache {
	// 可能抛出 Poseidon::JobBase::TryAgainLater。
	static Poseidon::SharedNts lookUp(const Poseidon::SharedNts &hostName);
	static Poseidon::SharedNts lookUp(const char *hostName){
		return lookUp(Poseidon::SharedNts::view(hostName));
	}
	static Poseidon::SharedNts lookUp(const std::string &hostName){
		return lookUp(Poseidon::SharedNts::view(hostName.c_str()));
	}

private:
	DnsCache();
};

}

#endif
