#ifndef MEDUSA_PROXY_SESSION_HPP_
#define MEDUSA_PROXY_SESSION_HPP_

#include <poseidon/tcp_session_base.hpp>
#include <poseidon/http/server_reader.hpp>
#include <poseidon/http/server_writer.hpp>
#include <poseidon/http/client_reader.hpp>
#include <poseidon/http/client_writer.hpp>
#include <poseidon/uuid.hpp>

namespace Medusa {

class FetchClient;

namespace Impl {
	class ProxySessionServerAdaptor : public Poseidon::Http::ServerReader, public Poseidon::Http::ServerWriter {
	protected:
		// ServerReader
		void on_request_headers(Poseidon::Http::RequestHeaders request_headers,
			std::string transfer_encoding, boost::uint64_t content_length) OVERRIDE;
		void on_request_entity(boost::uint64_t entity_offset, bool is_chunked, Poseidon::StreamBuffer entity) OVERRIDE;
		bool on_request_end(boost::uint64_t content_length, bool is_chunked, Poseidon::OptionalMap headers) OVERRIDE;

		// ServerWriter
		long on_encoded_data_avail(Poseidon::StreamBuffer encoded) OVERRIDE;
	};

	class ProxySessionClientAdaptor : public Poseidon::Http::ClientReader, public Poseidon::Http::ClientWriter {
	protected:
		// ClientReader
		void on_response_headers(Poseidon::Http::ResponseHeaders response_headers,
			std::string transfer_encoding, boost::uint64_t content_length) OVERRIDE;
		void on_response_entity(boost::uint64_t entity_offset, bool is_chunked, Poseidon::StreamBuffer entity) OVERRIDE;
		bool on_response_end(boost::uint64_t content_length, bool is_chunked, Poseidon::OptionalMap headers) OVERRIDE;

		// ClientWriter
		long on_encoded_data_avail(Poseidon::StreamBuffer encoded) OVERRIDE;
	};
}

class ProxySession : public Poseidon::TcpSessionBase, private Impl::ProxySessionServerAdaptor, private Impl::ProxySessionClientAdaptor {
	friend ProxySessionServerAdaptor;
	friend ProxySessionClientAdaptor;

private:
	class CloseJob;
	class ReadAvailJob;

private:
	enum State {
		S_HTTP_HEADERS          = 0,
		S_HTTP_ENTITY           = 1,
		S_TUNNEL_CONNECTING     = 2,
		S_TUNNEL_ESTABLISHED    = 3,
	};

	enum {
		WAITING_FOR_HEADERS     = (boost::uint64_t)-128,
	};

private:
	const Poseidon::Uuid m_fetch_uuid;
	const boost::weak_ptr<FetchClient> m_fetch_client;

	State m_state;
	boost::uint64_t m_header_size;

	bool m_keep_alive;
	boost::uint64_t m_content_length;
	boost::uint64_t m_entity_offset;

public:
	explicit ProxySession(Poseidon::UniqueFile socket);
	~ProxySession();

private:
	void on_sync_read_avail(Poseidon::StreamBuffer data);
	void shutdown(Poseidon::Http::StatusCode status_code, Poseidon::OptionalMap headers, const char *what) NOEXCEPT;

	void on_sync_server_request_headers(Poseidon::Http::RequestHeaders request_headers,
		std::string transfer_encoding, boost::uint64_t content_length);
	void on_sync_server_request_entity(boost::uint64_t entity_offset, bool is_chunked, Poseidon::StreamBuffer entity);
	bool on_sync_server_request_end(boost::uint64_t content_length, bool is_chunked, Poseidon::OptionalMap headers);

	void on_sync_client_response_headers(Poseidon::Http::ResponseHeaders response_headers,
		std::string transfer_encoding, boost::uint64_t content_length);
	void on_sync_client_response_entity(boost::uint64_t entity_offset, bool is_chunked, Poseidon::StreamBuffer entity);
	bool on_sync_client_response_end(boost::uint64_t content_length, bool is_chunked, Poseidon::OptionalMap headers);

protected:
	void on_close(int err_code) NOEXCEPT OVERRIDE;

	void on_read_avail(Poseidon::StreamBuffer data) OVERRIDE;

	bool send(Poseidon::StreamBuffer data) OVERRIDE;

public:
	const Poseidon::Uuid &get_fetch_uuid() const {
		return m_fetch_uuid;
	}

	void on_fetch_connected(bool keep_alive);
	void on_fetch_received(Poseidon::StreamBuffer data);
	void on_fetch_ended();
	void on_fetch_closed(int cbpp_err_code, int sys_err_code, std::string err_msg);
};

}

#endif
