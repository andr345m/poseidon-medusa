#include "precompiled.hpp"
#include "proxy_session.hpp"
#include "singletons/fetch_client.hpp"
#include "msg/fetch.hpp"

namespace Medusa {

ProxySession::ProxySession(Poseidon::UniqueFile socket)
	: Poseidon::Http::LowLevelSession(STD_MOVE(socket))
{
}
ProxySession::~ProxySession(){
}

void ProxySession::onClose(int errCode) NOEXCEPT {
	PROFILE_ME;

}

boost::shared_ptr<Poseidon::Http::UpgradedLowLevelSessionBase>
	ProxySession::onLowLevelRequestHeaders(Poseidon::Http::RequestHeaders &requestHeaders, boost::uint64_t contentLength)
{
	PROFILE_ME;

	return VAL_INIT;
}

void ProxySession::onLowLevelRequest(Poseidon::Http::RequestHeaders requestHeaders, Poseidon::StreamBuffer entity){
	PROFILE_ME;

}
void ProxySession::onLowLevelError(Poseidon::Http::StatusCode statusCode, Poseidon::OptionalMap headers){
	PROFILE_ME;

}

}
