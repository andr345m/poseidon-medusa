#ifndef MEDUSA_FETCH_SESSION_HPP_
#define MEDUSA_FETCH_SESSION_HPP_

#include <map>
#include <boost/cstdint.hpp>
#include <poseidon/fwd.hpp>
#include <poseidon/cbpp/fwd.hpp>
#include <poseidon/cbpp/session.hpp>

namespace Medusa {

class FetchSession : public Poseidon::Cbpp::Session {
private:
	class Channel;

private:
	static void sync_gc_timer_proc(const boost::weak_ptr<FetchSession> &weak, boost::uint64_t now) NOEXCEPT;

private:
	const std::string m_password;

	boost::shared_ptr<Poseidon::TimerItem> m_gc_timer;

	std::map<Poseidon::Uuid, boost::shared_ptr<Channel> > m_channels;

public:
	FetchSession(Poseidon::UniqueFile socket, std::string password);
	~FetchSession();

private:
	void on_sync_gc_timer(boost::uint64_t now);

protected:
	void on_sync_data_message(boost::uint16_t message_id, Poseidon::StreamBuffer payload) OVERRIDE;

public:
	bool send_explicit(const Poseidon::Uuid &fetch_uuid, boost::uint16_t message_id, Poseidon::StreamBuffer plain);
	bool send(const Poseidon::Uuid &fetch_uuid, const Poseidon::Cbpp::MessageBase &msg);
};

}

#endif
