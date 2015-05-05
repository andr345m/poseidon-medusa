#ifndef MEDUSA_FETCH_SESSION_HPP_
#define MEDUSA_FETCH_SESSION_HPP_

#include <map>
#include <boost/cstdint.hpp>
#include <poseidon/mutex.hpp>
#include <poseidon/stream_buffer.hpp>
#include <poseidon/cbpp/session.hpp>

namespace Medusa {

class FetchSession : public Poseidon::Cbpp::Session {
private:
	class FetchClient;

private:
	const std::string m_password;

	mutable Poseidon::Mutex m_clientMutex;
	std::map<boost::uint64_t, boost::weak_ptr<FetchClient> > m_clients;

public:
	FetchSession(Poseidon::UniqueFile socket, std::string password);
	~FetchSession();

private:
	void unlockedShutdownAllClients(bool force) NOEXCEPT;

	void onDecryptedRequest(boost::uint64_t context, boost::uint16_t messageId, std::string data);

protected:
	void onClose(int errCode) NOEXCEPT OVERRIDE;

	void onRequest(boost::uint16_t messageId, const Poseidon::StreamBuffer &payload) OVERRIDE;

public:
	bool send(boost::uint64_t context, boost::uint16_t messageId, std::string data);

	template<typename MsgT>
	bool send(boost::uint64_t context, const MsgT &msg){
		return send(context, MsgT::ID, Poseidon::StreamBuffer(msg).dump());
	}
};

}

#endif
