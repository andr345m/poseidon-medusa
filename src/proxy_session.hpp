#ifndef MEDUSA_PROXY_SESSION_HPP_
#define MEDUSA_PROXY_SESSION_HPP_

#include <poseidon/tcp_session_base.hpp>
#include <poseidon/uuid.hpp>
#include <boost/scoped_ptr.hpp>
#include <boost/shared_ptr.hpp>

namespace Medusa {

class FetchClient;

class ProxySession : public Poseidon::TcpSessionBase {
public:
	enum {
		FL_KEEP_ALIVE = 0x0001,
		FL_TUNNEL     = 0x0002,
	};

private:
	class RequestRewriter;
	class ResponseRewriter;

	class ReadHupJob;
	class CloseJob;
	class ReadAvailJob;

private:
	const Poseidon::Uuid m_fetch_uuid;

	boost::scoped_ptr<RequestRewriter> m_request_rewriter;
	boost::weak_ptr<FetchClient> m_weak_fetch_client;
	boost::scoped_ptr<ResponseRewriter> m_response_rewriter;
	unsigned long m_request_counter;

public:
	explicit ProxySession(Poseidon::UniqueFile socket);
	~ProxySession() OVERRIDE;

private:
	RequestRewriter &get_request_rewriter();
	ResponseRewriter &get_response_rewriter();
	void shutdown(unsigned http_status_code, const char *err_msg) NOEXCEPT;

protected:
	void on_read_hup() NOEXCEPT OVERRIDE;
	void on_close(int err_code) NOEXCEPT OVERRIDE;
	void on_receive(Poseidon::StreamBuffer data) OVERRIDE;
	bool send(Poseidon::StreamBuffer data) OVERRIDE;

public:
	const Poseidon::Uuid &get_fetch_uuid() const {
		return m_fetch_uuid;
	}

	void on_fetch_connected(boost::uint64_t flags);
	void on_fetch_received(Poseidon::StreamBuffer data);
	void on_fetch_ended();
	void on_fetch_closed(int err_code, const char *err_msg) NOEXCEPT;
};

}

#endif
