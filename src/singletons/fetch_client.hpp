#ifndef MEDUSA_FETCH_CLIENT_HPP_
#define MEDUSA_FETCH_CLIENT_HPP_

#include <map>
#include <boost/scoped_ptr.hpp>
#include <poseidon/cbpp/low_level_client.hpp>
#include <poseidon/uuid.hpp>
#include <poseidon/mutex.hpp>

namespace Medusa {

class EncryptionContext;
class ProxySession;

class FetchClient : public Poseidon::Cbpp::LowLevelClient {
public:
	static boost::shared_ptr<FetchClient> get();
	static boost::shared_ptr<FetchClient> require();

private:
	const std::string m_password;

	boost::uint16_t m_messageId;
	boost::uint64_t m_payloadLen;
	Poseidon::StreamBuffer m_payload;
	boost::scoped_ptr<EncryptionContext> m_decContext;

	mutable Poseidon::Mutex m_sessionMutex;
	std::map<Poseidon::Uuid, boost::weak_ptr<ProxySession> > m_sessions;

private:
	FetchClient(const Poseidon::IpPort &addr, bool useSsl, boost::uint64_t keepAliveTimeout, std::string password);

public:
	~FetchClient();

private:
	void onLowLevelPlainMessage(const Poseidon::Uuid &fetchUuid, boost::uint16_t messageId, Poseidon::StreamBuffer plain);

protected:
	void onLowLevelResponse(boost::uint16_t messageId, boost::uint64_t payloadLen) OVERRIDE;
	void onLowLevelPayload(boost::uint64_t payloadOffset, Poseidon::StreamBuffer payload) OVERRIDE;

	void onLowLevelError(boost::uint16_t messageId, Poseidon::Cbpp::StatusCode statusCode, std::string reason) OVERRIDE;

public:
	boost::shared_ptr<ProxySession> getSession(const Poseidon::Uuid &fetchUuid);
	void link(const boost::shared_ptr<ProxySession> &session);
	void unlink(const Poseidon::Uuid &fetchUuid) NOEXCEPT;

	bool send(const Poseidon::Uuid &fetchUuid, boost::uint16_t messageId, Poseidon::StreamBuffer plain);

	template<class MsgT>
	bool send(const Poseidon::Uuid &fetchUuid, const MsgT &msg){
		return send(fetchUuid, MsgT::ID, Poseidon::StreamBuffer(msg));
	}
};

}

#endif
