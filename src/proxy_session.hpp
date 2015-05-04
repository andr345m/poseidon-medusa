#ifndef MEDUSA_PROXY_SESSION_HPP_
#define MEDUSA_PROXY_SESSION_HPP_

#include <poseidon/http/session.hpp>

namespace Medusa {

class ProxySession : public Poseidon::Http::Session {
private:
	class TunnelSession;

public:
	explicit ProxySession(Poseidon::UniqueFile socket);
	~ProxySession();

protected:
	boost::shared_ptr<Poseidon::Http::UpgradedSessionBase> onRequestHeaders(
		Poseidon::Http::RequestHeaders &requestHeaders, boost::uint64_t contentLength) OVERRIDE;

	void onRequest(
		const Poseidon::Http::RequestHeaders &requestHeaders, const Poseidon::StreamBuffer &entity) OVERRIDE;
};

}

#endif
