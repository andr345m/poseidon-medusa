#include "../precompiled.hpp"
#include "dns_cache.hpp"
#include <poseidon/job_base.hpp>
#include <poseidon/mutex.hpp>
#include <poseidon/thread.hpp>
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>

namespace Medusa {
/*
namespace {
	
}

int getaddrinfo(const char *node, const char *service,
	const struct addrinfo *hints,
	struct addrinfo **res);

struct addrinfo {
int              ai_flags;
int              ai_family;		AF_UNSPEC
int              ai_socktype;	SOCK_STREAM
int              ai_protocol;
socklen_t        ai_addrlen;
struct sockaddr *ai_addr;
char            *ai_canonname;
struct addrinfo *ai_next;
};
void freeaddrinfo(struct addrinfo *res);

const char *gai_strerror(int errcode);
*/
Poseidon::SharedNts DnsCache::lookUp(const Poseidon::SharedNts &hostName){
	return SSLIT("");
}

}
