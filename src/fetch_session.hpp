#ifndef MEDUSA_FETCH_SESSION_HPP_
#define MEDUSA_FETCH_SESSION_HPP_

#include <map>
#include <boost/cstdint.hpp>
#include <poseidon/tcp_session_base.hpp>
#include <poseidon/cbpp/reader.hpp>
#include <poseidon/cbpp/writer.hpp>
#include <poseidon/cbpp/status_codes.hpp>
#include <poseidon/uuid.hpp>

namespace Medusa {

class FetchSession : public Poseidon::TcpSessionBase, private Poseidon::Cbpp::Reader, private Poseidon::Cbpp::Writer {
private:
	class Client;
	class ClientControl;

private:
	static void timerProc(const boost::weak_ptr<FetchSession> &weakSession, boost::uint64_t now, boost::uint64_t period);

private:
	const std::string m_password;

	boost::shared_ptr<Poseidon::TimerItem> m_timer;

	std::map<Poseidon::Uuid, ClientControl> m_clients;

public:
	FetchSession(Poseidon::UniqueFile socket, std::string password);
	~FetchSession();

private:
	void onTimer(boost::uint64_t now, boost::uint64_t period);

	void onPlainMessage(const Poseidon::Uuid &fetchUuid, boost::uint16_t messageId, Poseidon::StreamBuffer plain);

protected:
	// TcpSessionBase
	void onReadAvail(const void *data, std::size_t size) OVERRIDE;

	// Reader
	void onDataMessageHeader(boost::uint16_t messageId, boost::uint64_t payloadSize) OVERRIDE;
	void onDataMessagePayload(boost::uint64_t payloadOffset, Poseidon::StreamBuffer payload) OVERRIDE;
	bool onDataMessageEnd(boost::uint64_t payloadSize) OVERRIDE;

	bool onControlMessage(Poseidon::Cbpp::ControlCode controlCode, boost::int64_t vintParam, std::string stringParam) OVERRIDE;

	// Writer
	long onEncodedDataAvail(Poseidon::StreamBuffer encoded) OVERRIDE;

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
