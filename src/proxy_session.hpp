#ifndef MEDUSA_PROXY_SESSION_HPP_
#define MEDUSA_PROXY_SESSION_HPP_

#include <poseidon/http/low_level_session.hpp>
#include <poseidon/uuid.hpp>

namespace Medusa {

class FetchClient;

class ProxySession : public Poseidon::Http::LowLevelSession {
private:
	class TunnelLowLevelSession;

public:
	static boost::shared_ptr<ProxySession> findByUuid(const Poseidon::Uuid &uuid);
	static void shutdownAll(bool force);

private:
	const Poseidon::Uuid m_uuid;
	const boost::weak_ptr<FetchClient> m_fetch;

public:
	explicit ProxySession(Poseidon::UniqueFile socket);
	~ProxySession();

protected:
	void onClose(int errCode) NOEXCEPT OVERRIDE;

	boost::shared_ptr<Poseidon::Http::UpgradedLowLevelSessionBase>
		onLowLevelRequestHeaders(Poseidon::Http::RequestHeaders &requestHeaders, boost::uint64_t contentLength) OVERRIDE;

	void onLowLevelRequest(Poseidon::Http::RequestHeaders requestHeaders, Poseidon::StreamBuffer entity) OVERRIDE;
	void onLowLevelError(Poseidon::Http::StatusCode statusCode, Poseidon::OptionalMap headers) OVERRIDE;

public:
	const Poseidon::Uuid &getUuid() const {
		return m_uuid;
	}
};

}

#endif
