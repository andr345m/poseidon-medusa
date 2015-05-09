#ifndef MEDUSA_FETCH_CLIENT_HPP_
#define MEDUSA_FETCH_CLIENT_HPP_

#include <boost/scoped_ptr.hpp>
#include <poseidon/uuid.hpp>
#include <poseidon/cbpp/low_level_client.hpp>

namespace Medusa {

class EncryptionContext;

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

private:
	FetchClient(const Poseidon::IpPort &addr, boost::uint64_t keepAliveTimeout, bool useSsl, std::string password);

public:
	~FetchClient();

private:
	void onLowLevelPlainMessage(const Poseidon::Uuid &sessionUuid, boost::uint16_t messageId, Poseidon::StreamBuffer plain);

protected:
	void onLowLevelResponse(boost::uint16_t messageId, boost::uint64_t payloadLen) OVERRIDE;
	void onLowLevelPayload(boost::uint64_t payloadOffset, Poseidon::StreamBuffer payload) OVERRIDE;

	void onLowLevelError(boost::uint16_t messageId, Poseidon::Cbpp::StatusCode statusCode, std::string reason) OVERRIDE;

public:
	bool send(const Poseidon::Uuid &sessionUuid, boost::uint16_t messageId, Poseidon::StreamBuffer plain);

	template<class MsgT>
	bool send(const Poseidon::Uuid &sessionUuid, const MsgT &msg){
		return send(sessionUuid, MsgT::ID, Poseidon::StreamBuffer(msg));
	}
};

}

#endif
