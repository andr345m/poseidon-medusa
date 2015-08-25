#ifndef MEDUSA_FETCH_SESSION_HPP_
#define MEDUSA_FETCH_SESSION_HPP_

#include <map>
#include <boost/cstdint.hpp>
#include <poseidon/fwd.hpp>
#include <poseidon/cbpp/session.hpp>

namespace Medusa {

class FetchSession : public Poseidon::Cbpp::Session {
private:
	class Channel;

private:
	static void syncGcTimerProc(const boost::weak_ptr<FetchSession> &weak, boost::uint64_t now) NOEXCEPT;

private:
	const std::string m_password;

	boost::shared_ptr<Poseidon::TimerItem> m_gcTimer;

	std::map<Poseidon::Uuid, boost::shared_ptr<Channel> > m_channels;

public:
	FetchSession(Poseidon::UniqueFile socket, std::string password);
	~FetchSession();

private:
	void onSyncGcTimer(boost::uint64_t now);

protected:
	void onSyncDataMessage(boost::uint16_t messageId, const Poseidon::StreamBuffer &payload) OVERRIDE;

public:
	bool send(const Poseidon::Uuid &fetchUuid, boost::uint16_t messageId, Poseidon::StreamBuffer plain);

	template<typename MsgT>
	bool send(const Poseidon::Uuid &fetchUuid, const MsgT &msg){
		return send(fetchUuid, MsgT::ID, Poseidon::StreamBuffer(msg));
	}
};

}

#endif
