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
		void onRequestHeaders(Poseidon::Http::RequestHeaders requestHeaders,
			std::string transferEncoding, boost::uint64_t contentLength) OVERRIDE;
		void onRequestEntity(boost::uint64_t entityOffset, bool isChunked, Poseidon::StreamBuffer entity) OVERRIDE;
		bool onRequestEnd(boost::uint64_t contentLength, bool isChunked, Poseidon::OptionalMap headers) OVERRIDE;

		// ServerWriter
		long onEncodedDataAvail(Poseidon::StreamBuffer encoded) OVERRIDE;
	};

	class ProxySessionClientAdaptor : public Poseidon::Http::ClientReader, public Poseidon::Http::ClientWriter {
	protected:
		// ClientReader
		void onResponseHeaders(Poseidon::Http::ResponseHeaders responseHeaders,
			std::string transferEncoding, boost::uint64_t contentLength) OVERRIDE;
		void onResponseEntity(boost::uint64_t entityOffset, bool isChunked, Poseidon::StreamBuffer entity) OVERRIDE;
		bool onResponseEnd(boost::uint64_t contentLength, bool isChunked, Poseidon::OptionalMap headers) OVERRIDE;

		// ClientWriter
		long onEncodedDataAvail(Poseidon::StreamBuffer encoded) OVERRIDE;
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
		S_HTTP_HEADERS			= 0,
		S_HTTP_ENTITY			= 1,
		S_TUNNEL_CONNECTING		= 2,
		S_TUNNEL_ESTABLISHED	= 3,
	};

	enum {
		WAITING_FOR_HEADERS		= (boost::uint64_t)-128,
	};

private:
	const Poseidon::Uuid m_fetchUuid;
	const boost::weak_ptr<FetchClient> m_fetchClient;

	State m_state;
	boost::uint64_t m_headerSize;

	bool m_keepAlive;
	boost::uint64_t m_contentLength;
	boost::uint64_t m_entityOffset;

public:
	explicit ProxySession(Poseidon::UniqueFile socket);
	~ProxySession();

private:
	void onSyncReadAvail(Poseidon::StreamBuffer data);
	void shutdown(Poseidon::Http::StatusCode statusCode, Poseidon::OptionalMap headers, const char *what) NOEXCEPT;

	void onSyncServerRequestHeaders(Poseidon::Http::RequestHeaders requestHeaders,
		std::string transferEncoding, boost::uint64_t contentLength);
	void onSyncServerRequestEntity(boost::uint64_t entityOffset, bool isChunked, Poseidon::StreamBuffer entity);
	bool onSyncServerRequestEnd(boost::uint64_t contentLength, bool isChunked, Poseidon::OptionalMap headers);

	void onSyncClientResponseHeaders(Poseidon::Http::ResponseHeaders responseHeaders,
		std::string transferEncoding, boost::uint64_t contentLength);
	void onSyncClientResponseEntity(boost::uint64_t entityOffset, bool isChunked, Poseidon::StreamBuffer entity);
	bool onSyncClientResponseEnd(boost::uint64_t contentLength, bool isChunked, Poseidon::OptionalMap headers);

protected:
	void onClose(int errCode) NOEXCEPT OVERRIDE;

	void onReadAvail(Poseidon::StreamBuffer data) OVERRIDE;

	bool send(Poseidon::StreamBuffer data) OVERRIDE;

public:
	const Poseidon::Uuid &getFetchUuid() const {
		return m_fetchUuid;
	}

	void onFetchConnected(bool keepAlive);
	void onFetchReceived(Poseidon::StreamBuffer data);
	void onFetchEnded();
	void onFetchClosed(int cbppErrCode, int sysErrCode, std::string errMsg);
};

}

#endif
