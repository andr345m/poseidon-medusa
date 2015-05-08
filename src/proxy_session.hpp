#ifndef MEDUSA_PROXY_SESSION_HPP_
#define MEDUSA_PROXY_SESSION_HPP_

#include <poseidon/http/low_level_session.hpp>

namespace Medusa {

class ProxySession : public Poseidon::Http::LowLevelSession {
public:
	explicit ProxySession(Poseidon::UniqueFile socket);
	~ProxySession();

protected:
	void onClose(int errCode) NOEXCEPT OVERRIDE;

	boost::shared_ptr<Poseidon::Http::UpgradedLowLevelSessionBase>
		onLowLevelRequestHeaders(Poseidon::Http::RequestHeaders &requestHeaders, boost::uint64_t contentLength) OVERRIDE;

	void onLowLevelRequest(Poseidon::Http::RequestHeaders requestHeaders, Poseidon::StreamBuffer entity) OVERRIDE;
	void onLowLevelError(Poseidon::Http::StatusCode statusCode, Poseidon::OptionalMap headers) OVERRIDE;
};

}

#endif
