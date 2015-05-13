#include "precompiled.hpp"
#include "fetch_session.hpp"
#include <poseidon/singletons/timer_daemon.hpp>
#include <poseidon/http/low_level_client.hpp>
#include <poseidon/tcp_client_base.hpp>
#include <poseidon/atomic.hpp>
#include <poseidon/hash.hpp>
#include <poseidon/async_job.hpp>
#include "encryption.hpp"
#include "singletons/dns_daemon.hpp"
#include "msg/fetch.hpp"
#include "msg/error_codes.hpp"

namespace Medusa {

class FetchSession::ClientControl : public boost::enable_shared_from_this<ClientControl> {
private:
	struct RequestElement {
		std::string host;
		unsigned port;
		bool useSsl;

		bool keepAlive;

		Poseidon::Http::RequestHeaders req;
		Poseidon::StreamBuffer pending;
	};

	class HttpClient : public Poseidon::Http::LowLevelClient {
	private:
		const boost::weak_ptr<FetchSession> m_session;
		const Poseidon::Uuid m_fetchUuid;

		const bool m_keepAlive;

		bool m_fullyReceived;

	public:
		HttpClient(const Poseidon::SockAddr &sockAddr, bool useSsl,
			boost::weak_ptr<FetchSession> session, const Poseidon::Uuid &fetchUuid, bool keepAlive)
			: Poseidon::Http::LowLevelClient(sockAddr, useSsl)
			, m_session(STD_MOVE(session)), m_fetchUuid(fetchUuid), m_keepAlive(keepAlive)
			, m_fullyReceived(false)
		{
		}

	protected:
		void onClose(int errCode) NOEXCEPT OVERRIDE {
			PROFILE_ME;

			const AUTO(session, m_session.lock());
			if(session){
				if((errCode == 0) && !m_fullyReceived){
					LOG_MEDUSA_DEBUG("Partial response from another server?");
					errCode = ECONNRESET;
				}
				try {
					session->send(m_fetchUuid, Msg::SC_FetchError(
						((errCode == 0) ? Msg::ST_OK : Msg::ST_INTERNAL_ERROR), errCode, VAL_INIT));
				} catch(std::exception &e){
					LOG_MEDUSA_ERROR("std::exception thrown: what = ", e.what());
					session->forceShutdown();
				}
			}

			Poseidon::Http::LowLevelClient::onClose(errCode);
		}

		void onLowLevelResponseHeaders(Poseidon::Http::ResponseHeaders resh,
			std::vector<std::string> transferEncoding, boost::uint64_t /* contentLength */) OVERRIDE
		{
			PROFILE_ME;

			const AUTO(session, m_session.lock());
			if(!session){
				LOG_MEDUSA_DEBUG("Lost connection to fetch client");
				forceShutdown();
				return;
			}

			Msg::SC_FetchResponseHeaders msg;
			msg.statusCode = resh.statusCode;
			msg.reason = STD_MOVE(resh.reason);

			resh.headers.erase("Content-Length");
			resh.headers.erase("Prxoy-Authenticate");
			resh.headers.erase("Proxy-Connection");
			resh.headers.erase("Upgrade");
			resh.headers.erase("Transfer-Encoding");
			if(m_keepAlive){
				resh.headers.set("Connection", "Keep-Alive");
			} else {
				resh.headers.set("Connection", "Close");
			}
			for(AUTO(it, resh.headers.begin()); it != resh.headers.end(); ++it){
				msg.headers.push_back(VAL_INIT);
				msg.headers.back().name = it->first.get();
				msg.headers.back().value = STD_MOVE(it->second);
			}

			for(AUTO(it, transferEncoding.begin()); it != transferEncoding.end(); ++it){
				msg.transferEncoding.push_back(VAL_INIT);
				msg.transferEncoding.back().value = STD_MOVE(*it);
			}

			if(!session->send(m_fetchUuid, msg)){
				LOG_MEDUSA_DEBUG("Lost connection to fetch client");
				forceShutdown();
				return;
			}

			m_fullyReceived = false;
		}
		void onLowLevelEntity(boost::uint64_t /* contentOffset */, Poseidon::StreamBuffer entity) OVERRIDE {
			PROFILE_ME;

			const AUTO(session, m_session.lock());
			if(!session){
				LOG_MEDUSA_DEBUG("Lost connection to fetch client");
				forceShutdown();
				return;
			}

			if(!session->send(m_fetchUuid, Msg::SC_FetchHttpReceive::ID, STD_MOVE(entity))){
				LOG_MEDUSA_DEBUG("Lost connection to fetch client");
				forceShutdown();
				return;
			}
		}
		void onLowLevelResponseEof(boost::uint64_t /* realContentLength */, Poseidon::OptionalMap headers) OVERRIDE {
			PROFILE_ME;

			const AUTO(session, m_session.lock());
			if(!session){
				LOG_MEDUSA_DEBUG("Lost connection to fetch client");
				forceShutdown();
				return;
			}

			Msg::SC_FetchHttpReceiveEof msg;

			for(AUTO(it, headers.begin()); it != headers.end(); ++it){
				msg.headers.push_back(VAL_INIT);
				msg.headers.back().name = it->first.get();
				msg.headers.back().value = STD_MOVE(it->second);
			}

			if(!session->send(m_fetchUuid, msg)){
				LOG_MEDUSA_DEBUG("Lost connection to fetch client");
				forceShutdown();
				return;
			}

			m_fullyReceived = true;
		}
	};

	class TunnelClient : public Poseidon::TcpClientBase {
	private:
		const boost::weak_ptr<FetchSession> m_session;
		const Poseidon::Uuid m_fetchUuid;

	public:
		TunnelClient(const Poseidon::SockAddr &sockAddr, bool useSsl,
			boost::weak_ptr<FetchSession> session, const Poseidon::Uuid &fetchUuid)
			: Poseidon::TcpClientBase(sockAddr, useSsl)
			, m_session(STD_MOVE(session)), m_fetchUuid(fetchUuid)
		{
		}

	protected:
		void onClose(int errCode) NOEXCEPT OVERRIDE {
			PROFILE_ME;

			const AUTO(session, m_session.lock());
			if(session){
				try {
					session->send(m_fetchUuid, Msg::SC_FetchError(
						((errCode == 0) ? Msg::ST_OK : Msg::ST_INTERNAL_ERROR), errCode, VAL_INIT));
				} catch(std::exception &e){
					LOG_MEDUSA_ERROR("std::exception thrown: what = ", e.what());
					session->forceShutdown();
				}
			}

			Poseidon::TcpClientBase::onClose(errCode);
		}

		void onReadAvail(const void *data, std::size_t size) OVERRIDE {
			PROFILE_ME;

			const AUTO(session, m_session.lock());
			if(!session){
				LOG_MEDUSA_DEBUG("Lost connection to fetch client");
				forceShutdown();
				return;
			}

			if(!session->send(m_fetchUuid, Msg::SC_FetchTunnelReceive::ID, Poseidon::StreamBuffer(data, size))){
				LOG_MEDUSA_DEBUG("Lost connection to fetch client");
				forceShutdown();
				return;
			}
		}
	};

private:
/*

	void FetchSession::onFetchClose(const Poseidon::Uuid &fetchUuid, int errCode) NOEXCEPT {
		PROFILE_ME;
		LOG_MEDUSA_DEBUG("Fetch client closed: errCode = ", errCode);
	
		const AUTO(it, m_clients.find(fetchUuid));
		if(it == m_clients.end()){
			LOG_MEDUSA_DEBUG("Client not found: fetchUuid = ", fetchUuid);
			return;
		}
	
		try {
			if(errCode == 0){
				//it->pump
			} else {
				
	
				send(fetchUuid, Msg::SC_FetchError(Msg::ST_INTERNAL_ERROR, errCode, VAL_INIT));
			}
		} catch(std::exception &e){
			LOG_MEDUSA_ERROR("std::exception thrown: what = ", e.what());
			forceShutdown();
		}
	}
	
	

	static void timerProc(const boost::weak_ptr<ClientControl> &weakControl, boost::uint64_t now){
		PROFILE_ME;

		const AUTO(control, weakControl.lock());
		if(!control){
			return;
		}

		try {
			control->pumpStatus(now);
		} catch(std::exception &e){
			LOG_MEDUSA_WARNING("std::exception thrown: what = ", e.what());
			control->close(Msg::ST_INTERNAL_ERROR, ECONNRESET, e.what());
		}
	}

	static void dnsCallback(const boost::weak_ptr<ClientControl> &weakControl, const std::string &host, unsigned port,
		int gaiCode, const Poseidon::SockAddr &addr, const char *errMsg)
	{
		PROFILE_ME;

		const AUTO(control, weakControl.lock());
		if(!control){
			return;
		}

		if(control->m_state != S_DNS_LOOKING_UP){
			LOG_MEDUSA_WARNING("Unexpected state: fetchUuid = ", control->m_fetchUuid, ", state = ", control->m_state);
			return;
		}
		if(control->m_queue.empty()){
			LOG_MEDUSA_WARNING("No pending DNS request? fetchUuid = ", control->m_fetchUuid);
			return;
		}
		const AUTO_REF(elem, control->m_queue.front());
		if((elem.host != host) || (elem.port != port)){
			LOG_MEDUSA_WARNING("Unexpected address: expecting ", elem.host, ':', elem.port, ", got ", host, ':', port);
			return;
		}
		if(gaiCode == 0){
			try {
				control->createFetchClient(addr);
			} catch(std::exception &e){
				LOG_MEDUSA_WARNING("std::exception thrown: what = ", e.what());
				control->close(Msg::ST_INTERNAL_ERROR, ECONNRESET, e.what());
			}
		} else {
			control->close(Msg::ERR_FETCH_DNS_FAILURE, gaiCode, errMsg);
		}
	}
	static void exceptionCallback(const boost::weak_ptr<ClientControl> &weakControl) NOEXCEPT {
		PROFILE_ME;

		const AUTO(control, weakControl.lock());
		if(!control){
			return;
		}

		control->close(Msg::ST_INTERNAL_ERROR, ECONNRESET, VAL_INIT);
	}
*/
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
/*	void createFetchClient(const Poseidon::SockAddr &addr){
		PROFILE_ME;
		LOG_MEDUSA_DEBUG("Spawning fetch client to ", Poseidon::getIpPortFromSockAddr(addr))"

		const AUTO(client, m_client.lock());
		if(client){
			LOG_MEDUSA_DEBUG("Shutting down old client...");
			client->forceShutdown();
		}

		
	}

	void pumpStatus(boost::uint64_t now){
		PROFILE_ME;

		switch(m_state){
		case S_IDLE:
			if(!m_queue.empty()){
				LOG_MEDUSA_DEBUG("DNS looking up: host:port = ", elem.host, ':', elem.port);

				const AUTO_REF(elem, m_queue.front());
				const boost::weak_ptr<ClientControl> weakControl(shared_from_this());
				DnsDaemon::asyncLookup(elem.host, elem.port,
					boost::bind(&dnsCallback, weakControl, _1, _2, _3, _4, _6),
					false, boost::bind(&exceptionCallback, weakControl));

				m_state = S_DNS_LOOKING_UP;
				m_updatedTime = now;
			}
			break;

		case S_DNS_LOOKING_UP:
			{
				const AUTO(dnsTimeout, getConfig()->get<boost::uint64_t>("fetch_dns_timeout", 10000));
				if(m_updatedTime + dnsTimeout < now){
					LOG_MEDUSA_DEBUG("DNS timed out");
					close(Msg::ERR_FETCH_DNS_TIMEDOUT, ETIMEDOUT, VAL_INIT);
					break;
				}
			}
			break;

		case S_ASYNC_CONNECTED:
			if(m_client.expired()){
				m_state = S_IDLE;
			}
			break;

		default:
			LOG_MEDUSA_FATAL("Unknown state: ", m_state);
			std::abort();
		}
	}

	void sendFetchedData(Poseidon::StreamBuffer data){
		const AUTO(session, m_session.lock());
		if(!session){
			LOG_MEDUSA_DEBUG("Lost connection to fetch client: fetchUuid = ", m_fetchUuid);
			DEBUG_THROW(Exception, SSLIT("Lost connection to fetch client"));
		}
		if(!session->send(m_fetchUuid, Msg::SC_FetchReceive::ID, STD_MOVE(data))){
			LOG_MEDUSA_DEBUG("Error sending data to fetch client: fetchUuid = ", m_fetchUuid);
			DEBUG_THROW(Exception, SSLIT("Error sending data to fetch client"));
		}
		m_updatedTime = 
	}
*/
public:
	boost::uint64_t getUpdatedTime() const {
		return Poseidon::atomicLoad(m_updatedTime, Poseidon::ATOMIC_RELAXED);
	}

	void push(std::string host, unsigned port, bool useSsl, Poseidon::Http::RequestHeaders reqh, std::string xff){
		PROFILE_ME;
		LOG_POSEIDON_DEBUG("Fetch connect: fetchUuid = ", m_fetchUuid,
			", host = ", host, ", port = ", port, ", useSsl = ", useSsl, ", URI = ", reqh.uri, ", XFF = ", xff);
/*
		const AUTO(maxPipeliningSize, getConfig()->get<std::size_t>("fetch_max_pipelining_size", 16));

		RequestElement elem;
		elem.host = STD_MOVE(host);
		elem.port = port;
		elem.useSsl = useSsl;
		elem.reqh = STD_MOVE(reqh);
		elem.xff = STD_MOVE(xff);

		const Poseidon::Mutex::UniqueLock lock(m_mutex);
		if(m_queue.size() >= maxPipeliningSize){
			LOG_MEDUSA_WARNING("Max pipelining size exceeded: fetchUuid = ", m_fetchUuid, ", maxPipeliningSize = ", maxPipeliningSize);
			DEBUG_THROW(Poseidon::Cbpp::Exception, Msg::ERR_FETCH_MAX_PIPELINING_SIZE);
		}
		Poseidon::atomicStore(m_updatedTime, Poseidon::getFastMonoClock(), Poseidon::ATOMIC_RELAXED);
*/
	}
	bool send(Poseidon::StreamBuffer data){
		PROFILE_ME;
		LOG_POSEIDON_DEBUG("Fetch send: fetchUuid = ", m_fetchUuid,
			", size = ", data.size());
/*
		const AUTO(maxPendingSize, getConfig()->get<std::size_t>("fetch_max_pending_size", 65536));

		const Poseidon::Mutex::UniqueLock lock(m_mutex);

		if(m_queue.empty()){
			LOG_MEDUSA_WARNING("Queue is empty. Who shall I send data to? fetchUuid = ", m_fetchUuid);
			DEBUG_THROW(Poseidon::Cbpp::Exception, Msg::ERR_FETCH_NOT_CONNECTED);
		}

		if(m_queue.size() == 1){
			const AUTO(client, m_client.lock());
			if(client){
				return client->send(STD_MOVE(data));
			}
		}

		boost::uint64_t pendingSize = 0;
		for(AUTO(it, m_queue.begin()); it != m_queue.end(); ++it){
			pendingSize += it->pending.size();
		}
		if(pendingSize + data.size() > maxPendingSize){
			LOG_MEDUSA_WARNING("Max pending size exceeded: fetchUuid = ", m_fetchUuid, ", maxPendingSize = ", maxPendingSize);
			DEBUG_THROW(Poseidon::Cbpp::Exception, Msg::ERR_FETCH_MAX_PENDING_SIZE);
		}
		pending.splice(data);
*/
		return true;
	}
	void close(Poseidon::Cbpp::StatusCode cbppErrCode, int errCode, std::string description) NOEXCEPT {
		PROFILE_ME;
		LOG_POSEIDON_DEBUG("Fetch close: fetchUuid = ", m_fetchUuid,
			", cbppErrCode = ", cbppErrCode, ", errCode = ", errCode, ", description = ", description);
/*
		const Poseidon::Mutex::UniqueLock lock(m_mutex);

		const AUTO(session, m_session.lock());
		if(session){
			try {
				session->send(m_fetchUuid, Msg::SC_FetchError(cbppErrCode, errCode, STD_MOVE(description)));
			} catch(std::exception &e){
				LOG_MEDUSA_ERROR("std::exception thrown: what = ", e.what());
				session->forceShutdown();
			}
		}

		const AUTO(client, m_client.lock());
		if(client){
			if(errCode != 0){
				client->forceShutdown();
			} else {
				client->shutdownRead();
				client->shutdownWrite();
			}
		}

		m_state = S_IDLE;
		m_queue.clear();
		m_updatedTime = 0;
		m_client.reset();

		Poseidon::atomicStore(m_updatedTime, Poseidon::getFastMonoClock(), Poseidon::ATOMIC_RELAXED);
*/
	}
};

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
}

void FetchSession::onGcTimer(boost::uint64_t now, boost::uint64_t period){
	PROFILE_ME;
	LOG_MEDUSA_DEBUG("Fetch client GC timer: now = ", now, ", period = ", period);

	AUTO(it, m_clients.begin());
	while(it != m_clients.end()){
		if(it->second->getUpdatedTime() + period < now){
			LOG_MEDUSA_DEBUG("> Reclaiming client: fetchUuid = ", it->first);
			it->second->close(Msg::ERR_FETCH_CONNECTION_TIMED_OUT, ETIMEDOUT, VAL_INIT);
			m_clients.erase(it++);
		} else {
			++it;
		}
	}
}

void FetchSession::onPlainMessage(const Poseidon::Uuid &fetchUuid, boost::uint16_t messageId, Poseidon::StreamBuffer plain){
	PROFILE_ME;
	LOG_MEDUSA_DEBUG("Fetch request: fetchUuid = ", fetchUuid, ", messageId = ", messageId);

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
			std::string transferEncoding;
			if(req.transferEncoding.empty()){
				transferEncoding = "chunked";
			} else {
				for(AUTO(it, req.transferEncoding.begin()); it != req.transferEncoding.end(); ++it){
					transferEncoding += it->value;
					transferEncoding += ',';
				}
				transferEncoding.erase(transferEncoding.end() - 1);
			}
			reqh.headers.set("Transfer-Encoding", transferEncoding);

			it->second->push(STD_MOVE(req.host), req.port, req.useSsl, reqh, STD_MOVE(req.xff));
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
				it->second->close(Msg::ST_OK, req.errCode, VAL_INIT);
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

}
