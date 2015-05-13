#ifndef MEDUSA_FETCH_SESSION_HPP_
#define MEDUSA_FETCH_SESSION_HPP_

#include <map>
#include <boost/cstdint.hpp>
#include <poseidon/cbpp/session.hpp>
#include <poseidon/uuid.hpp>
#include <poseidon/stream_buffer.hpp>

namespace Medusa {

class FetchSession : public Poseidon::Cbpp::Session {
private:
	class ClientControl;

	class HttpClient;
	class TunnelClient;

private:
	static void gcTimerProc(const boost::weak_ptr<FetchSession> &weakSession, boost::uint64_t now, boost::uint64_t period);

private:
	const std::string m_password;

	boost::shared_ptr<Poseidon::TimerItem> m_gcTimer;

	std::map<Poseidon::Uuid, boost::shared_ptr<ClientControl> > m_clients;

public:
	FetchSession(Poseidon::UniqueFile socket, std::string password);
	~FetchSession();

private:
	void onGcTimer(boost::uint64_t now, boost::uint64_t period);

	void onPlainMessage(const Poseidon::Uuid &fetchUuid, boost::uint16_t messageId, Poseidon::StreamBuffer plain);

protected:
	void onRequest(boost::uint16_t messageId, const Poseidon::StreamBuffer &payload) OVERRIDE;

public:
	bool send(const Poseidon::Uuid &fetchUuid, boost::uint16_t messageId, Poseidon::StreamBuffer plain);

	template<class MsgT>
	bool send(const Poseidon::Uuid &fetchUuid, const MsgT &msg){
		return send(fetchUuid, MsgT::ID, Poseidon::StreamBuffer(msg));
	}

	bool sendError(boost::uint16_t messageId, Poseidon::Cbpp::StatusCode statusCode, std::string reason);
};

}

#endif
