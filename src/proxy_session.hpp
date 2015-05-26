#ifndef MEDUSA_PROXY_SESSION_HPP_
#define MEDUSA_PROXY_SESSION_HPP_

#include <boost/scoped_ptr.hpp>
#include <poseidon/tcp_session_base.hpp>
#include <poseidon/http/server_reader.hpp>
#include <poseidon/http/server_writer.hpp>
#include <poseidon/uuid.hpp>

namespace Medusa {

class FetchClient;

class ProxySession : public Poseidon::TcpSessionBase, private Poseidon::Http::ServerReader, private Poseidon::Http::ServerWriter {
private:
	class CloseJob;
	class ReadAvailJob;

	class ClientAdaptor;

private:
	enum State {
		S_HTTP_HEADERS			= 0,
		S_HTTP_IDENTITY			= 1,
		S_HTTP_CHUNKED			= 2,
		S_TUNNEL_CONNECTING		= 3,
		S_TUNNEL_ESTABLISHED	= 4,
	};

private:
	const Poseidon::Uuid m_fetchUuid;
	const boost::weak_ptr<FetchClient> m_fetchClient;
	const boost::scoped_ptr<ClientAdaptor> m_client;

	State m_state;
	boost::uint64_t m_headerSize;

	bool m_keepAlive;

public:
	explicit ProxySession(Poseidon::UniqueFile socket);
	~ProxySession();

private:
	void onSyncReadAvail(Poseidon::StreamBuffer data);
	void shutdown(Poseidon::Http::StatusCode statusCode, Poseidon::OptionalMap headers, const char *what) NOEXCEPT;

protected:
	// TcpSessionBase
	void onClose(int errCode) NOEXCEPT OVERRIDE;

	void onReadAvail(Poseidon::StreamBuffer data) OVERRIDE;

	bool send(Poseidon::StreamBuffer data) OVERRIDE;

	// ServerReader
	void onRequestHeaders(Poseidon::Http::RequestHeaders requestHeaders, std::string transferEncoding, boost::uint64_t contentLength) OVERRIDE;
	void onRequestEntity(boost::uint64_t entityOffset, bool isChunked, Poseidon::StreamBuffer entity) OVERRIDE;
	bool onRequestEnd(boost::uint64_t contentLength, bool isChunked, Poseidon::OptionalMap headers) OVERRIDE;

	// ServerWriter
	long onEncodedDataAvail(Poseidon::StreamBuffer encoded) OVERRIDE;

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
