#include "precompiled.hpp"
#include "fetch_session.hpp"
#include <poseidon/singletons/timer_daemon.hpp>
#include <poseidon/tcp_client_base.hpp>
#include <poseidon/atomic.hpp>
#include <poseidon/hash.hpp>
#include <poseidon/string.hpp>
#include <poseidon/async_job.hpp>
#include "encryption.hpp"
#include "singletons/dns_daemon.hpp"
#include "msg/cs_fetch.hpp"
#include "msg/sc_fetch.hpp"
#include "msg/error_codes.hpp"

namespace Medusa {
/*
class FetchSession::Client : public Poseidon::TcpClientBase {
private:
	const boost::weak_ptr<ClientControl> m_control;

public:
	TunnelClient(const Poseidon::SockAddr &sockAddr, bool useSsl, boost::weak_ptr<ClientControl> control)
		: Poseidon::TcpClientBase(sockAddr, useSsl)
		, m_control(STD_MOVE(control))
	{
	}

protected:
	void onClose(int errCode) NOEXCEPT OVERRIDE {
		PROFILE_ME;

		const AUTO(control, m_control.lock());
		if(control){
			try {
				if(errCode != 0){
					control->forwardData(Msg::SC_FetchError(Msg::ST_INTERNAL_ERROR, errCode, VAL_INIT));
				} else {
					control->forwardData(Msg::SC_FetchError(Msg::ST_OK, 0, VAL_INIT));
					control->notifyFetchComplete();
				}
			} catch(std::exception &e){
				LOG_MEDUSA_ERROR("std::exception thrown: what = ", e.what());
				control->close(Msg::ST_INTERNAL_ERROR, ECONNRESET, e.what());
			}
		}

		Poseidon::TcpClientBase::onClose(errCode);
	}

	void onReadAvail(const void *data, std::size_t size) OVERRIDE {
		PROFILE_ME;

		const AUTO(control, m_control.lock());
		if(!control){
			LOG_MEDUSA_DEBUG("Lost connection to fetch client");
			forceShutdown();
			return;
		}

		control->forwardData(Msg::SC_FetchTunnelReceive::ID, Poseidon::StreamBuffer(data, size));
	}
};

class FetchSession::ClientControl : public boost::enable_shared_from_this<ClientControl> {
private:
	struct RequestElement {
		std::string host;
		unsigned port;
		bool useSsl;

		Poseidon::Http::RequestHeaders reqh;
		Poseidon::StreamBuffer pending;

		bool keepAlive;
	};

private:
	static boost::shared_ptr<Poseidon::TcpClientBase> unlockedCreateClient(
		const Poseidon::SockAddr &addr, RequestElement &elem, const boost::shared_ptr<ClientControl> &control);

	static void dnsCallback(const boost::weak_ptr<ClientControl> &weakControl,
		const std::string &host, unsigned port,
		int gaiCode, const Poseidon::SockAddr &addr, int errCode, const char *errMsg)
	{
		PROFILE_ME;

		const AUTO(control, weakControl.lock());
		if(!control){
			return;
		}

		if(gaiCode != 0){
			control->close(Msg::ERR_FETCH_DNS_FAILURE, errCode, errMsg);
			return;
		}

		try {
			const Poseidon::Mutex::UniqueLock lock(control->m_mutex);

			if(control->m_queue.empty()){
				LOG_MEDUSA_WARNING("Wild DNS callback?");
				DEBUG_THROW(Exception, SSLIT("Wild DNS callback"));
			}
			AUTO_REF(elem, control->m_queue.front());
			if((host != elem.host) || (port != elem.port)){
				LOG_MEDUSA_WARNING("Unexpected DNS result: expecting ", elem.host, ':', elem.port, ", got ", host, ':', port);
				DEBUG_THROW(Exception, SSLIT("Unexpected DNS result"));
			}
			control->m_client = unlockedCreateClient(addr, elem, control);
		} catch(std::exception &e){
			LOG_MEDUSA_ERROR("std::exception thrown: what = ", e.what());
			control->close(Msg::ERR_FETCH_DNS_FAILURE, ECONNRESET, e.what());
		}
	}
	static void exceptionCallback(const boost::weak_ptr<ClientControl> &weakControl){
		PROFILE_ME;

		const AUTO(control, weakControl.lock());
		if(!control){
			return;
		}

		control->close(Msg::ERR_FETCH_DNS_FAILURE, ECONNRESET, VAL_INIT);
	}

private:
	const boost::weak_ptr<FetchSession> m_session;
	const Poseidon::Uuid m_fetchUuid;

	volatile boost::uint64_t m_updatedTime;

	mutable Poseidon::Mutex m_mutex;
	std::deque<RequestElement> m_queue;
	boost::weak_ptr<Poseidon::TcpClientBase> m_client;

public:
	ClientControl(boost::weak_ptr<FetchSession> session, const Poseidon::Uuid &fetchUuid)
		: m_session(STD_MOVE(session)), m_fetchUuid(fetchUuid)
		, m_updatedTime(0)
	{
		LOG_MEDUSA_DEBUG("Constructing client control: fetchUuid = ", m_fetchUuid);
	}
	~ClientControl(){
		LOG_MEDUSA_DEBUG("Destructing client control: fetchUuid = ", m_fetchUuid);

		close(Msg::ERR_FETCH_CONNECTION_LOST, ECONNRESET, VAL_INIT);
	}

private:
	void asyncConnect(const RequestElement &elem){
		PROFILE_ME;

		DnsDaemon::asyncLookup(elem.host, elem.port,
			boost::bind(&dnsCallback, boost::weak_ptr<ClientControl>(shared_from_this()), _1, _2, _3, _4, _5, _6),
			true, boost::bind(&exceptionCallback, boost::weak_ptr<ClientControl>(shared_from_this())));
	}

public:
	boost::shared_ptr<FetchSession> getSession() const {
		return m_session.lock();
	}
	const Poseidon::Uuid &getFetchUuid() const {
		return m_fetchUuid;
	}

	boost::uint64_t getUpdatedTime() const {
		return Poseidon::atomicLoad(m_updatedTime, Poseidon::ATOMIC_RELAXED);
	}

	void forwardData(boost::uint16_t messageId, Poseidon::StreamBuffer payload){
		const AUTO(session, m_session.lock());
		if(!session){
			return;
		}
		session->send(m_fetchUuid, messageId, STD_MOVE(payload));
		Poseidon::atomicStore(m_updatedTime, Poseidon::getFastMonoClock(), Poseidon::ATOMIC_RELAXED);
	}
	template<typename MsgT>
	void forwardData(const MsgT &msg){
		forwardData(MsgT::ID, Poseidon::StreamBuffer(msg));
	}

	void push(std::string host, unsigned port, bool useSsl, Poseidon::Http::RequestHeaders reqh,
		std::vector<std::string> transferEncoding, std::string xff)
	{
		PROFILE_ME;
		LOG_POSEIDON_DEBUG("Fetch connect: fetchUuid = ", m_fetchUuid,
			", host = ", host, ", port = ", port, ", useSsl = ", useSsl, ", URI = ", reqh.uri, ", XFF = ", xff);

		const AUTO(session, m_session.lock());
		if(!session){
			LOG_POSEIDON_DEBUG("Lost connection to fetch client");
			DEBUG_THROW(Poseidon::Cbpp::Exception, Msg::ERR_FETCH_CONNECTION_LOST);
		}

		reqh.headers.erase("Transfer-Encoding");
		reqh.headers.erase("Content-Length");
		reqh.headers.erase("Prxoy-Authenticate");
		reqh.headers.erase("Upgrade");

		std::vector<std::string> connectionVec;
		{
			const AUTO(it, reqh.headers.find("Proxy-Connection"));
			if(it != reqh.headers.end()){
				connectionVec = Poseidon::explode<std::string>(',', it->second);
				reqh.headers.erase(it);
			}
		}
		reqh.headers.set("Connection", "Close");

		bool keepAlive;
		if(reqh.version < 10001){
			keepAlive = false;
			for(AUTO(it, connectionVec.begin()); it != connectionVec.end(); ++it){
				*it = Poseidon::trim(STD_MOVE(*it));
				if(::strcasecmp(it->c_str(), "Keep-Alive") == 0){
					keepAlive = true;
				}
			}
		} else {
			keepAlive = true;
			for(AUTO(it, connectionVec.begin()); it != connectionVec.end(); ++it){
				*it = Poseidon::trim(STD_MOVE(*it));
				if(::strcasecmp(it->c_str(), "Close") == 0){
					keepAlive = false;
				}
			}
		}

		std::string transferEncodingStr;
		if(transferEncoding.empty()){
			transferEncodingStr = "chunked";
		} else {
			for(AUTO(it, transferEncoding.begin()); it != transferEncoding.end(); ++it){
				transferEncodingStr += *it;
				transferEncodingStr += ',';
			}
			transferEncodingStr.erase(transferEncodingStr.end() - 1);
		}
		reqh.headers.set("Transfer-Encoding", STD_MOVE(transferEncodingStr));
		reqh.headers.set("X-Forwarded-For", STD_MOVE(xff));

		RequestElement elem;
		elem.host = STD_MOVE(host);
		elem.port = port;
		elem.useSsl = useSsl;
		elem.reqh = STD_MOVE(reqh);
		elem.keepAlive = keepAlive;

		{
			const Poseidon::Mutex::UniqueLock lock(m_mutex);

			const AUTO(maxPipeliningSize, getConfig()->get<std::size_t>("fetch_max_pipelining_size", 16));
			if(m_queue.size() >= maxPipeliningSize){
				LOG_MEDUSA_WARNING("Max pipelining size exceeded: fetchUuid = ", m_fetchUuid);
				DEBUG_THROW(Poseidon::Cbpp::Exception, Msg::ERR_FETCH_MAX_PIPELINING_SIZE);
			}

			m_queue.push_back(STD_MOVE(elem));

			if(m_client.expired()){
				try {
					asyncConnect(m_queue.front());
				} catch(std::exception &e){
					LOG_MEDUSA_ERROR("std::exception thrown: what = ", e.what());
					session->forceShutdown();
					throw;
				}
			}
		}
		Poseidon::atomicStore(m_updatedTime, Poseidon::getFastMonoClock(), Poseidon::ATOMIC_RELAXED);
	}
	bool send(Poseidon::StreamBuffer data){
		PROFILE_ME;
		LOG_POSEIDON_DEBUG("Fetch send: fetchUuid = ", m_fetchUuid,
			", size = ", data.size());

		bool ret;
		{
			const Poseidon::Mutex::UniqueLock lock(m_mutex);

			if(m_queue.empty()){
				LOG_MEDUSA_WARNING("Queue is empty. Who shall I send data to? fetchUuid = ", m_fetchUuid);
				DEBUG_THROW(Poseidon::Cbpp::Exception, Msg::ERR_FETCH_NOT_CONNECTED);
			}

			if(m_queue.size() == 1){
				const AUTO(client, m_client.lock());
				if(client){
					ret = client->send(STD_MOVE(data));
					goto _done;
				}
			}

			boost::uint64_t pendingSize = 0;
			for(AUTO(it, m_queue.begin()); it != m_queue.end(); ++it){
				pendingSize += it->pending.size();
			}
			const AUTO(maxPendingSize, getConfig()->get<std::size_t>("fetch_max_pending_size", 65536));
			if(pendingSize + data.size() > maxPendingSize){
				LOG_MEDUSA_WARNING("Max pending size exceeded: fetchUuid = ", m_fetchUuid);
				DEBUG_THROW(Poseidon::Cbpp::Exception, Msg::ERR_FETCH_MAX_PENDING_SIZE);
			}
			m_queue.back().pending.splice(data);
			ret = true;
		}
	_done:
		Poseidon::atomicStore(m_updatedTime, Poseidon::getFastMonoClock(), Poseidon::ATOMIC_RELAXED);
		return ret;
	}
	void close(Poseidon::Cbpp::StatusCode cbppErrCode, int errCode, std::string description) NOEXCEPT {
		PROFILE_ME;
		LOG_POSEIDON_DEBUG("Fetch close: fetchUuid = ", m_fetchUuid,
			", cbppErrCode = ", cbppErrCode, ", errCode = ", errCode, ", description = ", description);

		{
			const Poseidon::Mutex::UniqueLock lock(m_mutex);

			const AUTO(client, m_client.lock());
			if(client){
				if(cbppErrCode == Msg::ST_OK){
					client->shutdownRead();
					client->shutdownWrite();
				} else {
					client->forceShutdown();
				}
			}

			if(m_queue.empty()){
				return;
			}

			m_queue.pop_front();
			m_client.reset();
		}
		Poseidon::atomicStore(m_updatedTime, Poseidon::getFastMonoClock(), Poseidon::ATOMIC_RELAXED);
	}

	void notifyFetchComplete(){
		PROFILE_ME;
		LOG_POSEIDON_DEBUG("Fetch complete: fetchUuid = ", m_fetchUuid);

		const AUTO(session, m_session.lock());
		if(!session){
			return;
		}

		close(Msg::ST_OK, 0, VAL_INIT);

		{
			const Poseidon::Mutex::UniqueLock lock(m_mutex);

			if(!m_queue.empty()){
				try {
					asyncConnect(m_queue.front());
				} catch(std::exception &e){
					LOG_MEDUSA_ERROR("std::exception thrown: what = ", e.what());
					session->forceShutdown();
					throw;
				}
			}
		}
		Poseidon::atomicStore(m_updatedTime, Poseidon::getFastMonoClock(), Poseidon::ATOMIC_RELAXED);
	}
};

class FetchSession::HttpClient : public Poseidon::Http::LowLevelClient {
private:
	const boost::weak_ptr<ClientControl> m_control;
	const bool m_keepAlive;

	bool m_fullyReceived;

public:
	HttpClient(const Poseidon::SockAddr &sockAddr, bool useSsl, boost::weak_ptr<ClientControl> control, bool keepAlive)
		: Poseidon::Http::LowLevelClient(sockAddr, useSsl)
		, m_control(STD_MOVE(control)), m_keepAlive(keepAlive)
		, m_fullyReceived(false)
	{
	}

protected:
	void onClose(int errCode) NOEXCEPT OVERRIDE {
		PROFILE_ME;

		const AUTO(control, m_control.lock());
		if(control){
			try {
				if(errCode != 0){
					control->forwardData(Msg::SC_FetchError(Msg::ST_INTERNAL_ERROR, errCode, VAL_INIT));
				} else if(!m_fullyReceived){
					control->forwardData(Msg::SC_FetchError(Msg::ERR_FETCH_TRUNCATED_RESPONSE, ECONNRESET, VAL_INIT));
				} else {
					control->forwardData(Msg::SC_FetchError(Msg::ST_OK, 0, VAL_INIT));
					control->notifyFetchComplete();
				}
			} catch(std::exception &e){
				LOG_MEDUSA_ERROR("std::exception thrown: what = ", e.what());
				control->close(Msg::ST_INTERNAL_ERROR, ECONNRESET, e.what());
			}
		}

		Poseidon::Http::LowLevelClient::onClose(errCode);
	}

	void onLowLevelResponseHeaders(Poseidon::Http::ResponseHeaders resh,
		std::vector<std::string> transferEncoding, boost::uint64_t contentLength) OVERRIDE
	{
		PROFILE_ME;

		const AUTO(control, m_control.lock());
		if(!control){
			LOG_MEDUSA_DEBUG("Lost connection to fetch client");
			forceShutdown();
			return;
		}

		resh.headers.erase("Transfer-Encoding");
		resh.headers.erase("Content-Length");
		resh.headers.erase("Prxoy-Authenticate");
		resh.headers.erase("Upgrade");

		if(m_keepAlive){
			resh.headers.set("Proxy-Connection", "Keep-Alive");
		} else {
			resh.headers.set("Proxy-Connection", "Close");
		}
		resh.headers.erase("Connection");

		const bool eof = (contentLength == 0);

		Msg::SC_FetchResponseHeaders msg;
		msg.statusCode = resh.statusCode;
		msg.reason = STD_MOVE(resh.reason);
		for(AUTO(it, resh.headers.begin()); it != resh.headers.end(); ++it){
			msg.headers.push_back(VAL_INIT);
			msg.headers.back().name = it->first.get();
			msg.headers.back().value = STD_MOVE(it->second);
		}
		for(AUTO(it, transferEncoding.begin()); it != transferEncoding.end(); ++it){
			msg.transferEncoding.push_back(VAL_INIT);
			msg.transferEncoding.back().value = STD_MOVE(*it);
		}
		msg.eof = eof;
		control->forwardData(msg);

		m_fullyReceived = eof;
	}
	void onLowLevelEntity(boost::uint64_t  contentOffset , Poseidon::StreamBuffer entity) OVERRIDE {
		PROFILE_ME;

		const AUTO(control, m_control.lock());
		if(!control){
			LOG_MEDUSA_DEBUG("Lost connection to fetch client");
			forceShutdown();
			return;
		}

		control->forwardData(Msg::SC_FetchHttpReceive::ID, STD_MOVE(entity));
	}
	void onLowLevelResponseEof(boost::uint64_t  realContentLength , Poseidon::OptionalMap headers) OVERRIDE {
		PROFILE_ME;

		const AUTO(control, m_control.lock());
		if(!control){
			LOG_MEDUSA_DEBUG("Lost connection to fetch client");
			forceShutdown();
			return;
		}

		m_fullyReceived = true;

		Msg::SC_FetchHttpReceiveEof msg;

		for(AUTO(it, headers.begin()); it != headers.end(); ++it){
			msg.headers.push_back(VAL_INIT);
			msg.headers.back().name = it->first.get();
			msg.headers.back().value = STD_MOVE(it->second);
		}

		control->forwardData(msg);
	}

public:
	bool sendRaw(Poseidon::StreamBuffer data){
		return Poseidon::TcpClientBase::send(STD_MOVE(data));
	}
};

boost::shared_ptr<Poseidon::TcpClientBase> FetchSession::ClientControl::unlockedCreateClient(
	const Poseidon::SockAddr &addr, FetchSession::ClientControl::RequestElement &elem,
	const boost::shared_ptr<FetchSession::ClientControl> &control)
{
	PROFILE_ME;
	LOG_MEDUSA_DEBUG("Creating new client connection to ", elem.host, ':', elem.port);

	if(elem.reqh.verb != Poseidon::Http::V_CONNECT){
		AUTO(client, boost::make_shared<HttpClient>(addr, elem.useSsl, control, elem.keepAlive));
		if(!client->send(STD_MOVE(elem.reqh))){
			LOG_MEDUSA_DEBUG("Error sending HTTP header to another");
			control->close(Msg::ERR_FETCH_CONNECTION_LOST, EPIPE, std::string());
			DEBUG_THROW(Exception, SSLIT("Error sending HTTP header to another"));
		}
		if(!client->sendRaw(STD_MOVE(elem.pending))){
			LOG_MEDUSA_DEBUG("Error sending pending HTTP contents to another server");
			control->close(Msg::ERR_FETCH_CONNECTION_LOST, EPIPE, std::string());
			DEBUG_THROW(Exception, SSLIT("Error sending pending HTTP contents to another server"));
		}
		client->goResident();
		return client;
	} else {
		AUTO(client, boost::make_shared<TunnelClient>(addr, elem.useSsl, control));
		if(!client->send(STD_MOVE(elem.pending))){
			LOG_MEDUSA_DEBUG("Error sending pending contents to another server");
			control->close(Msg::ERR_FETCH_CONNECTION_LOST, EPIPE, std::string());
			DEBUG_THROW(Exception, SSLIT("Error sending pending contents to another server"));
		}
		client->goResident();
		return client;
	}
}

void FetchSession::gcTimerProc(const boost::weak_ptr<FetchSession> &weakSession, boost::uint64_t now, boost::uint64_t period){
	PROFILE_ME;

	const AUTO(session, weakSession.lock());
	if(!session){
		return;
	}

	session->onGcTimer(now, period);
}

FetchSession::FetchSession(Poseidon::UniqueFile socket, std::string password)
	: Poseidon::Cbpp::Session(STD_MOVE(socket))
	, m_password(STD_MOVE(password))
{
}
FetchSession::~FetchSession(){
	for(AUTO(it, m_clients.begin()); it != m_clients.end(); ++it){
		it->second->close(Msg::ERR_FETCH_CONNECTION_LOST, ECONNRESET, VAL_INIT);
	}
}

void FetchSession::onGcTimer(boost::uint64_t now, boost::uint64_t period){
	PROFILE_ME;
	LOG_MEDUSA_TRACE("Fetch client GC timer: now = ", now, ", period = ", period);

	for(AUTO(next, m_clients.begin()), it = next; (next != m_clients.end()) && (++next, true); it = next){
		if(now < it->second->getUpdatedTime() + period){
			continue;
		}

		LOG_MEDUSA_DEBUG("Reclaiming timed out client: fetchUuid = ", it->first);
		it->second->close(Msg::ST_OK, 0, VAL_INIT);
		m_clients.erase(it);
	}
}

void FetchSession::onPlainMessage(const Poseidon::Uuid &fetchUuid, boost::uint16_t messageId, Poseidon::StreamBuffer plain){
	PROFILE_ME;
	LOG_MEDUSA_DEBUG("Fetch request: fetchUuid = ", fetchUuid, ", messageId = ", messageId);

	if(!m_gcTimer){
		const AUTO(clientGcInterval, getConfig()->get<boost::uint64_t>("fetch_client_gc_interval", 30000));
		m_gcTimer = Poseidon::TimerDaemon::registerTimer(clientGcInterval, clientGcInterval,
			boost::bind(&gcTimerProc, virtualWeakFromThis<FetchSession>(), _1, _2));
	}

	switch(messageId){
		{{
#define ON_MESSAGE(Msg_, req_)	\
		}}	\
		break;	\
	case Msg_::ID: {	\
		Msg_ req_(plain);	\
		{ //
#define ON_RAW_MESSAGE(Msg_)	\
		}}	\
		break;	\
	case Msg_::ID: {	\
		{ //
//=============================================================================
		ON_MESSAGE(Msg::CS_FetchRequestHeaders, req){
			AUTO(it, m_clients.find(fetchUuid));
			if(it == m_clients.end()){
				it = m_clients.insert(it, std::make_pair(fetchUuid,
					boost::make_shared<ClientControl>(virtualSharedFromThis<FetchSession>(), fetchUuid)));
			}

			Poseidon::Http::RequestHeaders reqh;
			reqh.verb = req.verb;
			reqh.uri = STD_MOVE(req.uri);
			reqh.version = 10001;
			for(AUTO(it, req.getParams.begin()); it != req.getParams.end(); ++it){
				reqh.getParams.set(SharedNts(it->name), STD_MOVE(it->value));
			}
			for(AUTO(it, req.headers.begin()); it != req.headers.end(); ++it){
				reqh.headers.set(SharedNts(it->name), STD_MOVE(it->value));
			}

			std::vector<std::string> transferEncoding;
			transferEncoding.reserve(req.transferEncoding.size());
			for(AUTO(it, req.transferEncoding.begin()); it != req.transferEncoding.end(); ++it){
				transferEncoding.push_back(STD_MOVE(it->value));
			}

			it->second->push(STD_MOVE(req.host), req.port, req.useSsl, STD_MOVE(reqh),
				STD_MOVE(transferEncoding), STD_MOVE(req.xff));
		}
		ON_RAW_MESSAGE(Msg::CS_FetchHttpSend){
			const AUTO(it, m_clients.find(fetchUuid));
			if(it == m_clients.end()){
				LOG_MEDUSA_DEBUG("Client not found: fetchUuid = ", fetchUuid);
				send(fetchUuid, Msg::SC_FetchError(Msg::ERR_FETCH_NOT_CONNECTED, ENOTCONN, VAL_INIT));
				break;
			}

			Poseidon::StreamBuffer chunk;
			char temp[64];
			unsigned len = (unsigned)std::sprintf(temp, "%llx\r\n", (unsigned long long)plain.size());
			chunk.put(temp, len);
			chunk.splice(plain);
			chunk.put("\r\n");
			if(!it->second->send(STD_MOVE(chunk))){
				LOG_MEDUSA_DEBUG("Failed to send data to client: fetchUuid = ", fetchUuid);
				send(fetchUuid, Msg::SC_FetchError(Msg::ERR_FETCH_CONNECTION_LOST, EPIPE, VAL_INIT));
				break;
			}
		}
		ON_MESSAGE(Msg::CS_FetchHttpSendEof, req){
			const AUTO(it, m_clients.find(fetchUuid));
			if(it == m_clients.end()){
				LOG_MEDUSA_DEBUG("Client not found: fetchUuid = ", fetchUuid);
				send(fetchUuid, Msg::SC_FetchError(Msg::ERR_FETCH_NOT_CONNECTED, ENOTCONN, VAL_INIT));
				break;
			}

			Poseidon::StreamBuffer data;
			data.put("0\r\n");
			for(AUTO(it, req.headers.begin()); it != req.headers.end(); ++it){
				data.put(it->name);
				data.put(": ");
				data.put(it->value);
				data.put("\r\n");
			}
			data.put("\r\n");
			if(!it->second->send(STD_MOVE(data))){
				LOG_MEDUSA_DEBUG("Failed to send data to client: fetchUuid = ", fetchUuid);
				send(fetchUuid, Msg::SC_FetchError(Msg::ERR_FETCH_CONNECTION_LOST, EPIPE, VAL_INIT));
				break;
			}
		}
		ON_RAW_MESSAGE(Msg::CS_FetchTunnelSend){
			const AUTO(it, m_clients.find(fetchUuid));
			if(it == m_clients.end()){
				LOG_MEDUSA_DEBUG("Client not found: fetchUuid = ", fetchUuid);
				send(fetchUuid, Msg::SC_FetchError(Msg::ERR_FETCH_NOT_CONNECTED, ENOTCONN, VAL_INIT));
				break;
			}

			if(!it->second->send(STD_MOVE(plain))){
				LOG_MEDUSA_DEBUG("Failed to send data to client: fetchUuid = ", fetchUuid);
				send(fetchUuid, Msg::SC_FetchError(Msg::ERR_FETCH_CONNECTION_LOST, EPIPE, VAL_INIT));
				break;
			}
		}
		ON_MESSAGE(Msg::CS_FetchClose, req){
			const AUTO(it, m_clients.find(fetchUuid));
			if(it == m_clients.end()){
				LOG_MEDUSA_DEBUG("Client not found: fetchUuid = ", fetchUuid);
				break;
			}

			if(req.errCode == 0){
				it->second->close(Msg::ST_OK, 0, VAL_INIT);
			} else {
				it->second->close(Msg::ERR_FETCH_CLIENT_REQUESTED, req.errCode, VAL_INIT);
			}
			m_clients.erase(it);
		}
//=============================================================================
		}}
		break;
	default:
		LOG_MEDUSA_ERROR("Unknown fetch message from client: messageId = ", messageId, ", size = ", plain.size());
		DEBUG_THROW(Poseidon::Cbpp::Exception, Msg::ST_NOT_FOUND);
	}
}

void FetchSession::onRequest(boost::uint16_t messageId, const Poseidon::StreamBuffer &payload){
	PROFILE_ME;

	try {
		const AUTO(headerSize, getEncryptedHeaderSize());
		if(payload.size() < headerSize){
			LOG_MEDUSA_ERROR("Frame from fetch client is too small, expecting ", headerSize);
			DEBUG_THROW(Poseidon::Cbpp::Exception, Msg::ST_END_OF_STREAM);
		}
		EncryptionContextPtr decContext;
		if(!tryDecryptHeader(decContext, m_password, payload)){
			LOG_MEDUSA_ERROR("Checksums mismatch. Maybe you provided a wrong password?");
			DEBUG_THROW(Poseidon::Cbpp::Exception, Msg::ERR_INVALID_AUTH);
		}
		Poseidon::StreamBuffer temp(payload);
		temp.discard(getEncryptedHeaderSize());
		AUTO(plain, decryptPayload(decContext, STD_MOVE(temp)));
		onPlainMessage(decContext->uuid, messageId, STD_MOVE(plain));
	} catch(Poseidon::Cbpp::Exception &e){
		LOG_MEDUSA_INFO("Cbpp::Exception: messageId = ", messageId, ", statusCode = ", e.statusCode(), ", what = ", e.what());
		sendError(messageId, e.statusCode(), e.what());
	}
}

bool FetchSession::send(const Poseidon::Uuid &fetchUuid, boost::uint16_t messageId, Poseidon::StreamBuffer plain){
	PROFILE_ME;

	EncryptionContextPtr encContext;
	AUTO(data, encryptHeader(encContext, fetchUuid, m_password));
	AUTO(payload, encryptPayload(encContext, STD_MOVE(plain)));
	data.splice(payload);
	return Poseidon::Cbpp::Session::send(messageId, STD_MOVE(data));
}

bool FetchSession::sendError(boost::uint16_t messageId, Poseidon::Cbpp::StatusCode statusCode, std::string reason){
	PROFILE_ME;

	const bool ret = Poseidon::Cbpp::Session::sendError(messageId, statusCode, STD_MOVE(reason));
	shutdownRead();
	shutdownWrite();
	return ret;
}
*/
}
