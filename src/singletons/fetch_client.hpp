#ifndef MEDUSA_FETCH_CLIENT_HPP_
#define MEDUSA_FETCH_CLIENT_HPP_

#include <map>
#include <poseidon/fwd.hpp>
#include <poseidon/tcp_client_base.hpp>
#include <poseidon/cbpp/reader.hpp>
#include <poseidon/cbpp/writer.hpp>
#include <poseidon/mutex.hpp>
#include <poseidon/uuid.hpp>

namespace Medusa {

class ProxySession;

class FetchClient : public Poseidon::TcpClientBase, private Poseidon::Cbpp::Reader, private Poseidon::Cbpp::Writer {
private:
	class Impl;

public:
	static boost::shared_ptr<FetchClient> get();
	static boost::shared_ptr<FetchClient> require();

private:
	const boost::uint64_t m_keepAliveInterval;
	const std::string m_password;

	unsigned m_messageId;
	Poseidon::StreamBuffer m_payload;

	mutable Poseidon::Mutex m_mutex;
	boost::shared_ptr<Poseidon::TimerItem> m_keepAliveTimer;
	std::map<Poseidon::Uuid, boost::weak_ptr<ProxySession> > m_sessions;

private:
	FetchClient(const Poseidon::IpPort &addr, bool useSsl, boost::uint64_t keepAliveInterval, std::string password);

public:
	~FetchClient();

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
	boost::shared_ptr<ProxySession> getSession(const Poseidon::Uuid &fetchUuid) const;
	void link(const boost::shared_ptr<ProxySession> &session);
	void unlink(const Poseidon::Uuid &fetchUuid, int errCode) NOEXCEPT;

	bool send(const Poseidon::Uuid &fetchUuid, boost::uint16_t messageId, Poseidon::StreamBuffer plain);
	bool sendControl(Poseidon::Cbpp::ControlCode controlCode, boost::int64_t vintParam, std::string stringParam);

	template<class MsgT>
	bool send(const Poseidon::Uuid &fetchUuid, const MsgT &msg){
		return send(fetchUuid, MsgT::ID, Poseidon::StreamBuffer(msg));
	}
};

}

#endif
