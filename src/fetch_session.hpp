#ifndef MEDUSA_FETCH_SESSION_HPP_
#define MEDUSA_FETCH_SESSION_HPP_

#include <poseidon/cbpp/fwd.hpp>
#include <poseidon/cbpp/session.hpp>
#include <poseidon/uuid.hpp>
#include <boost/cstdint.hpp>
#include <boost/container/map.hpp>

namespace Medusa {

class FetchSession : public Poseidon::Cbpp::Session {
public:
	enum {
		FL_KEEP_ALIVE = 0x0001,
		FL_TUNNEL     = 0x0002,
	};

private:
	class OriginClient;
	class Channel;

private:
	static void timer_proc(const boost::weak_ptr<FetchSession> &weak) NOEXCEPT;

private:
	const std::string m_password;

	boost::container::map<Poseidon::Uuid, boost::shared_ptr<Channel> > m_channels;
	boost::shared_ptr<Poseidon::TimerItem> m_timer;

public:
	FetchSession(Poseidon::UniqueFile socket, std::string password);
	~FetchSession() OVERRIDE;

protected:
	void on_sync_data_message(boost::uint16_t message_id, Poseidon::StreamBuffer payload) OVERRIDE;
	void on_sync_timer();
	bool send(const Poseidon::Uuid &fetch_uuid, const Poseidon::Cbpp::MessageBase &msg);
};

}

#endif
