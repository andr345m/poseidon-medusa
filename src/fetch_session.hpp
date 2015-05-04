#ifndef MEDUSA_FETCH_SESSION_HPP_
#define MEDUSA_FETCH_SESSION_HPP_

#include <poseidon/cbpp/session.hpp>

namespace Medusa {

class FetchSession : public Poseidon::Cbpp::Session {
private:
	class FetchClient;
	class FetchJob;

private:
	const std::string m_password;

	boost::weak_ptr<FetchClient> m_client;

public:
	FetchSession(Poseidon::UniqueFile socket, std::string password);
	~FetchSession();

protected:
	void onRequest(boost::uint16_t messageId, const Poseidon::StreamBuffer &payload) OVERRIDE;

public:
	bool send(Poseidon::StreamBuffer payload);
};

}

#endif
