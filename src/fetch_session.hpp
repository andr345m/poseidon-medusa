#ifndef MEDUSA_FETCH_SESSION_HPP_
#define MEDUSA_FETCH_SESSION_HPP_

#include <poseidon/cbpp/session.hpp>

namespace Medusa {

class FetchSession : public Poseidon::Cbpp::Session {
private:
	std::string m_password;

public:
	FetchSession(Poseidon::UniqueFile socket, std::string password);
	~FetchSession();

protected:
	void onRequest(boost::uint16_t messageId, const Poseidon::StreamBuffer &payload) OVERRIDE;
};

}

#endif
