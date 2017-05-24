#ifndef MEDUSA_FETCH_CLIENT_HPP_
#define MEDUSA_FETCH_CLIENT_HPP_

#include <poseidon/fwd.hpp>
#include <poseidon/cbpp/fwd.hpp>
#include <poseidon/cbpp/client.hpp>
#include <poseidon/uuid.hpp>
#include <boost/container/map.hpp>

namespace Medusa {

class ProxySession;

class FetchClient : public Poseidon::Cbpp::Client {
private:
	const std::string m_password;

	boost::container::map<Poseidon::Uuid, boost::weak_ptr<ProxySession> > m_sessions;

public:
	FetchClient(const Poseidon::SockAddr &sock_addr, bool use_ssl, bool verify_peer, std::string password);
	~FetchClient() OVERRIDE;

protected:
	void on_sync_data_message(boost::uint16_t message_id, Poseidon::StreamBuffer payload) OVERRIDE;
	bool send(const Poseidon::Uuid &fetch_uuid, const Poseidon::Cbpp::MessageBase &msg);

public:
	bool fetch_connect(const boost::shared_ptr<ProxySession> &session, std::string host, unsigned port, bool use_ssl, boost::uint64_t flags);
	bool fetch_send(const boost::shared_ptr<ProxySession> &session, Poseidon::StreamBuffer send_queue);
	void fetch_close(const Poseidon::Uuid &fetch_uuid, int err_code, const char *err_msg) NOEXCEPT;
};

}

#endif
