#ifndef MEDUSA_FETCH_SESSION_HPP_
#define MEDUSA_FETCH_SESSION_HPP_

#include <map>
#include <boost/cstdint.hpp>
#include <poseidon/cbpp/session.hpp>

namespace Medusa {

class FetchSession : public Poseidon::Cbpp::Session {
private:
	class FetchClient;
	class FetchJob;

private:
	const std::string m_password;

	std::map<boost::uint64_t, boost::weak_ptr<FetchClient> > m_fetchClients;

public:
	FetchSession(Poseidon::UniqueFile socket, std::string password);
	~FetchSession();

protected:
	void onRequest(boost::uint16_t messageId, const Poseidon::StreamBuffer &payload) OVERRIDE;

public:
	bool sendSuccess(boost::uint64_t context, Poseidon::StreamBuffer payload);
	bool sendFailure(boost::uint64_t context, long errCode, Poseidon::StreamBuffer payload);
};

}

#endif
