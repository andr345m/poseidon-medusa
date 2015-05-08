#ifndef MEDUSA_FETCH_SESSION_HPP_
#define MEDUSA_FETCH_SESSION_HPP_

#include <map>
#include <boost/cstdint.hpp>
#include <poseidon/uuid.hpp>
#include <poseidon/mutex.hpp>
#include <poseidon/stream_buffer.hpp>
#include <poseidon/cbpp/low_level_session.hpp>

namespace Medusa {

class FetchSession : public Poseidon::Cbpp::LowLevelSession {
private:
	struct ClientControl;

private:
	const std::string m_password;

	mutable Poseidon::Mutex m_clientMutex;
	std::map<boost::uint64_t, ClientControl> m_clients;

public:
	FetchSession(Poseidon::UniqueFile socket, std::string password);
	~FetchSession();

private:
	void shutdownAllClients(bool force) NOEXCEPT;

	void onLowLevelPlainMessage(const Poseidon::Uuid &sessionId, boost::uint16_t messageId, Poseidon::StreamBuffer plain);

protected:
	void onClose(int errCode) NOEXCEPT OVERRIDE;

	void onLowLevelRequest(boost::uint16_t messageId, Poseidon::StreamBuffer payload) OVERRIDE;
	void onLowLevelControl(Poseidon::Cbpp::ControlCode controlCode, boost::int64_t intParam, std::string strParam) OVERRIDE;

	void onLowLevelError(boost::uint16_t messageId, Poseidon::Cbpp::StatusCode statusCode, const char *reason) OVERRIDE;

public:
	bool send(const Poseidon::Uuid &sessionId, boost::uint16_t messageId, Poseidon::StreamBuffer plain);

	template<class MsgT>
	bool send(const Poseidon::Uuid &sessionId, const MsgT &msg){
		return send(sessionId, MsgT::ID, Poseidon::StreamBuffer(msg));
	}

	bool sendError(boost::uint16_t messageId, Poseidon::Cbpp::StatusCode statusCode, std::string reason);
};

}

#endif
