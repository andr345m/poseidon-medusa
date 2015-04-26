#ifndef MEDUSA_PROXY_HTTP_SESSION_HPP_
#define MEDUSA_PROXY_HTTP_SESSION_HPP_

#include <poseidon/http/session.hpp>

namespace Medusa {

class ProxyHttpSession : public Poseidon::Http::Session {
private:
	class HttpImpl;
	class TunnelImpl;

public:
	typedef Poseidon::Http::Session Base;

public:
	explicit ProxyHttpSession(Poseidon::UniqueFile socket);
	~ProxyHttpSession();

protected:
	void onReadHup() NOEXCEPT OVERRIDE;
	boost::shared_ptr<Poseidon::Http::UpgradedSessionBase> onHeader(
		const Poseidon::Http::Header &header, boost::uint64_t contentLength) OVERRIDE;

	void onRequest(const Poseidon::Http::Header &header, const Poseidon::StreamBuffer &entity) OVERRIDE;
};

}

#endif
