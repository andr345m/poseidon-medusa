#ifndef MEDUSA_PROXY_SESSION_HPP_
#define MEDUSA_PROXY_SESSION_HPP_

#include <poseidon/tcp_session_base.hpp>
//#include <poseidon/http/reader.hpp>
//#include <poseidon/http/writer.hpp>
#include <poseidon/uuid.hpp>

namespace Medusa {

class FetchClient;

class ProxySession : public Poseidon::TcpSessionBase {
private:
	const Poseidon::Uuid m_uuid;
	const boost::weak_ptr<FetchClient> m_fetch;

public:
	explicit ProxySession(Poseidon::UniqueFile socket);
	~ProxySession();

protected:
	void onClose(int errCode) NOEXCEPT OVERRIDE;

	// TcpSessionBase
	void onReadAvail(const void *data, std::size_t size) OVERRIDE;
};

}

#endif
