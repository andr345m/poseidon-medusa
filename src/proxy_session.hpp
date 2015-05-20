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
	enum State {
		S_HTTP,
		S_TUNNEL_CONNECTING,
		S_TUNNEL_ESTABLISTED,
	};

private:
	class HttpClient;

private:
	const Poseidon::Uuid m_fetchUuid;
	const boost::weak_ptr<FetchClient> m_fetchClient;
	const boost::scoped_ptr<HttpClient> m_httpClient;

	State m_state;
	boost::uint64_t m_headerSize;

public:
	explicit ProxySession(Poseidon::UniqueFile socket);
	~ProxySession();

private:
	void checkedForward(Poseidon::StreamBuffer data);

	template<typename MsgT>
	void checkedForward(const MsgT &msg){
		checkedForward(MsgT::ID, Poseidon::StreamBuffer(msg));
	}

protected:
	// TcpSessionBase
	void onClose(int errCode) NOEXCEPT OVERRIDE;

	void onReadAvail(const void *data, std::size_t size) OVERRIDE;

	// ServerReader
	void onRequestHeaders(Poseidon::Http::RequestHeaders requestHeaders, std::string transferEncoding, boost::uint64_t contentLength) OVERRIDE;
	void onRequestEntity(boost::uint64_t entityOffset, Poseidon::StreamBuffer entity) OVERRIDE;
	bool onRequestEnd(boost::uint64_t contentLength, bool isChunked, Poseidon::OptionalMap headers) OVERRIDE;

	// ServerWriter
	long onEncodedDataAvail(Poseidon::StreamBuffer encoded) OVERRIDE;

public:
	const Poseidon::Uuid &getUuid() const {
		return m_fetchUuid;
	}

	void onFetchConnect();
	void onFetchReceive(Poseidon::StreamBuffer data);
	void onFetchEnd(int errCode);
	void onFetchClose(int cbppErrCode, int sysErrCode, std::string errMsg) NOEXCEPT;
};

}

#endif
