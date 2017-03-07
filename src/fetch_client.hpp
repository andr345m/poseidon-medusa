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

private:
	bool send_explicit(const Poseidon::Uuid &fetch_uuid, boost::uint16_t message_id, Poseidon::StreamBuffer plain);
	bool send(const Poseidon::Uuid &fetch_uuid, const Poseidon::Cbpp::MessageBase &msg);

protected:
	void on_sync_data_message(boost::uint16_t message_id, Poseidon::StreamBuffer payload) OVERRIDE;

public:
	bool connect(const boost::shared_ptr<ProxySession> &session, std::string host, unsigned port, bool use_ssl, boost::uint64_t flags);
	bool send(const Poseidon::Uuid &fetch_uuid, Poseidon::StreamBuffer data);
	void close(const Poseidon::Uuid &fetch_uuid, int cbpp_err_code, int sys_err_code, const char *err_msg) NOEXCEPT;
};

}

#endif
