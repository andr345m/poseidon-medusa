#ifndef MEDUSA_FETCH_CLIENT_HPP_
#define MEDUSA_FETCH_CLIENT_HPP_

#include <map>
#include <poseidon/fwd.hpp>
#include <poseidon/cbpp/fwd.hpp>
#include <poseidon/cbpp/client.hpp>
#include <poseidon/uuid.hpp>

namespace Medusa {

class ProxySession;

class FetchClient : public Poseidon::Cbpp::Client {
private:
	class CloseJob;

public:
	static boost::shared_ptr<FetchClient> get();
	static boost::shared_ptr<FetchClient> require();

private:
	const std::string m_password;

	std::map<Poseidon::Uuid, boost::weak_ptr<ProxySession> > m_sessions;

private:
	FetchClient(const Poseidon::IpPort &addr, bool use_ssl, boost::uint64_t keep_alive_interval, std::string password);

public:
	~FetchClient();

private:
	bool send_data_explicit(const Poseidon::Uuid &fetch_uuid, boost::uint16_t message_id, Poseidon::StreamBuffer plain);
	bool send_data(const Poseidon::Uuid &fetch_uuid, const Poseidon::Cbpp::MessageBase &msg);
	bool send_control(Poseidon::Cbpp::ControlCode control_code, boost::int64_t vint_param, const char *string_param);

protected:
	void on_close(int err_code) NOEXCEPT OVERRIDE;

	void on_sync_data_message(boost::uint16_t message_id, Poseidon::StreamBuffer payload) OVERRIDE;
	void on_sync_error_message(boost::uint16_t message_id, Poseidon::Cbpp::StatusCode status_code, std::string reason) OVERRIDE;

public:
	bool connect(const boost::shared_ptr<ProxySession> &session, std::string host, unsigned port, bool use_ssl, bool keep_alive);
	bool send(const Poseidon::Uuid &fetch_uuid, Poseidon::StreamBuffer data);
	void close(const Poseidon::Uuid &fetch_uuid, int cbpp_err_code, int sys_err_code, const char *err_msg) NOEXCEPT;
	void clear(int cbpp_err_code, int sys_err_code, const char *err_msg) NOEXCEPT;
};

}

#endif
