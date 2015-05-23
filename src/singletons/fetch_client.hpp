#ifndef MEDUSA_FETCH_CLIENT_HPP_
#define MEDUSA_FETCH_CLIENT_HPP_

#include <map>
#include <poseidon/fwd.hpp>
#include <poseidon/cbpp/client.hpp>
#include <poseidon/uuid.hpp>

namespace Medusa {

class ProxySession;

class FetchClient : public Poseidon::Cbpp::Client {
public:
	static boost::shared_ptr<FetchClient> get();
	static boost::shared_ptr<FetchClient> require();

private:
	const std::string m_password;

	unsigned m_messageId;
	Poseidon::StreamBuffer m_payload;

	std::map<Poseidon::Uuid, boost::weak_ptr<ProxySession> > m_sessions;

private:
	FetchClient(const Poseidon::IpPort &addr, bool useSsl, boost::uint64_t keepAliveInterval, std::string password);

public:
	~FetchClient();

private:
	bool send(const Poseidon::Uuid &fetchUuid, boost::uint16_t messageId, Poseidon::StreamBuffer plain);
	bool sendControl(Poseidon::Cbpp::ControlCode controlCode, boost::int64_t vintParam, std::string stringParam);

	template<typename MsgT>
	bool send(const Poseidon::Uuid &fetchUuid, const MsgT &msg){
		return send(fetchUuid, MsgT::ID, Poseidon::StreamBuffer(msg));
	}

protected:
	void onSyncDataMessageHeader(boost::uint16_t messageId, boost::uint64_t payloadSize) OVERRIDE;
	void onSyncDataMessagePayload(boost::uint64_t payloadOffset, const Poseidon::StreamBuffer &payload) OVERRIDE;
	void onSyncDataMessageEnd(boost::uint64_t payloadSize) OVERRIDE;

	void onSyncErrorMessage(boost::uint16_t messageId, Poseidon::Cbpp::StatusCode statusCode, const std::string &reason) OVERRIDE;

public:
	bool connect(const boost::shared_ptr<ProxySession> &session, std::string host, unsigned port, bool useSsl, bool keepAlive);
	bool send(const Poseidon::Uuid &fetchUuid, Poseidon::StreamBuffer data);
	void close(const Poseidon::Uuid &fetchUuid, int errCode) NOEXCEPT;
};

}

#endif
