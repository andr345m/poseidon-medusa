#include "precompiled.hpp"
#include "fetch_session.hpp"
#include <poseidon/singletons/timer_daemon.hpp>
#include <poseidon/job_base.hpp>
#include <poseidon/tcp_client_base.hpp>
#include "encryption.hpp"
#include "msg/cs_fetch.hpp"
#include "msg/sc_fetch.hpp"
#include "singletons/dns_daemon.hpp"
#include "msg/error_codes.hpp"

namespace Medusa {

namespace {
	const std::string STR_PRIVATE_ADDR_REQUESTED		("Connection to private address requested");
	const std::string STR_CONNECTION_IS_NOT_PERSISTENT	("Connection is not persistent");
	const std::string STR_NO_CONNECTION_ESTABLISHED		("No connection established");
	const std::string STR_COULD_NOT_SEND_TO_REMOTE		("Could not send data to remote server");
}

class FetchSession::Channel {
private:
	class Client;

	struct ConnectElement {
		std::string host;
		unsigned port;
		bool useSsl;
		bool keepAlive;

		bool connected;
		Poseidon::StreamBuffer pending;

		ConnectElement(std::string host_, unsigned port_, bool useSsl_, bool keepAlive_)
			: host(STD_MOVE(host_)), port(port_), useSsl(useSsl_), keepAlive(keepAlive_)
			, connected(false)
		{
		}
	};

	class ClientSyncJobBase : public Poseidon::JobBase {
	private:
		const boost::weak_ptr<FetchSession> m_session;
		const Poseidon::Uuid m_fetchUuid;

	public:
		ClientSyncJobBase(const boost::shared_ptr<FetchSession> &session, const Poseidon::Uuid &fetchUuid)
			: m_session(session), m_fetchUuid(fetchUuid)
		{
		}

	private:
		boost::weak_ptr<const void> getCategory() const FINAL {
			return m_session;
		}
		void perform() const FINAL {
			PROFILE_ME;

			const AUTO(session, m_session.lock());
			if(!session){
				return;
			}
			const AUTO(it, session->m_channels.find(m_fetchUuid));
			if(it == session->m_channels.end()){
				return;
			}

			try {
				perform(session, it);
			} catch(std::exception &e){
				LOG_MEDUSA_ERROR("std::exception thrown: what = ", e.what());
				try {
					session->sendError(0, Msg::ST_INTERNAL_ERROR, e.what());
					session->shutdownRead();
					session->shutdownWrite();
				} catch(...){
					session->forceShutdown();
				}
			}
		}

	protected:
		virtual void perform(const boost::shared_ptr<FetchSession> &session, std::map<Poseidon::Uuid, Channel>::iterator it) const = 0;
	};

	class ClientConnectJob : public ClientSyncJobBase {
	public:
		ClientConnectJob(const boost::shared_ptr<FetchSession> &session, const Poseidon::Uuid &fetchUuid)
			: ClientSyncJobBase(session, fetchUuid)
		{
		}

	protected:
		void perform(const boost::shared_ptr<FetchSession> &session, std::map<Poseidon::Uuid, Channel>::iterator it) const OVERRIDE {
			PROFILE_ME;
			LOG_MEDUSA_DEBUG("Remote client connect: fetchUuid = ", it->first);

			assert(!it->second.m_connectQueue.empty());
			AUTO_REF(elem, it->second.m_connectQueue.front());

			elem.connected = true;
			if(!elem.pending.empty()){
				const AUTO(client, it->second.m_client.lock());
				if(client){
					client->send(STD_MOVE(elem.pending));
				}
				elem.pending.clear();
			}

			session->send(it->first, Msg::SC_FetchConnected(elem.keepAlive));
		}
	};

	class ClientCloseJob : public ClientSyncJobBase {
	private:
		const int m_errCode;

	public:
		ClientCloseJob(const boost::shared_ptr<FetchSession> &session, const Poseidon::Uuid &fetchUuid, int errCode)
			: ClientSyncJobBase(session, fetchUuid)
			, m_errCode(errCode)
		{
		}

	protected:
		void perform(const boost::shared_ptr<FetchSession> &session, std::map<Poseidon::Uuid, Channel>::iterator it) const OVERRIDE {
			PROFILE_ME;
			LOG_MEDUSA_DEBUG("Remote client close: fetchUuid = ", it->first, ", errCode = ", m_errCode);

			assert(!it->second.m_connectQueue.empty());
			AUTO_REF(elem, it->second.m_connectQueue.front());

			if(m_errCode != 0){
				try {
					std::string errMsg;
					errMsg.resize(255);
					unsigned len;
					if(elem.connected){
						len = (unsigned)std::sprintf(&errMsg[0], "Lost connection to remote server: errno was %d: ", m_errCode);
					} else {
						len = (unsigned)std::sprintf(&errMsg[0], "Could not connect to remote server: errno was %d: ", m_errCode);
					}
					errMsg.resize(len);
					errMsg += Poseidon::getErrorDesc(m_errCode).get();
					session->send(it->first, Msg::SC_FetchClosed(Msg::ERR_CONNECTION_LOST, m_errCode, STD_MOVE(errMsg)));
				} catch(std::exception &e){
					LOG_MEDUSA_ERROR("std::exception thrown: what = ", e.what());
				}
				session->m_channels.erase(it);
				return;
			}

			session->send(it->first, Msg::SC_FetchEnded());

			if(elem.keepAlive){
				it->second.m_connectQueue.pop_front();
				if(!it->second.m_connectQueue.empty()){
					it->second.createClient();
				}
			} else {
				session->send(it->first, Msg::SC_FetchClosed(Msg::ST_OK, 0, STR_CONNECTION_IS_NOT_PERSISTENT));
				session->m_channels.erase(it);
			}
		}
	};

	class ClientReadAvailJob : public ClientSyncJobBase {
	private:
		mutable Poseidon::StreamBuffer m_data;

	public:
		ClientReadAvailJob(const boost::shared_ptr<FetchSession> &session, const Poseidon::Uuid &fetchUuid, Poseidon::StreamBuffer data)
			: ClientSyncJobBase(session, fetchUuid)
			, m_data(STD_MOVE(data))
		{
		}

	protected:
		void perform(const boost::shared_ptr<FetchSession> &session, std::map<Poseidon::Uuid, Channel>::iterator it) const OVERRIDE {
			PROFILE_ME;
			LOG_MEDUSA_DEBUG("Remote client read avail: fetchUuid = ", it->first, ", size = ", m_data.size());

			session->send(it->first, Msg::SC_FetchReceived::ID, STD_MOVE(m_data));
			it->second.m_updatedTime = Poseidon::getFastMonoClock();
		}
	};

	class Client : public Poseidon::TcpClientBase {
	private:
		const boost::weak_ptr<FetchSession> m_session;
		const Poseidon::Uuid m_fetchUuid;

	public:
		Client(const Poseidon::SockAddr &addr, bool useSsl,
			const boost::shared_ptr<FetchSession> &session, const Poseidon::Uuid &fetchUuid)
			: Poseidon::TcpClientBase(addr, useSsl)
			, m_session(session), m_fetchUuid(fetchUuid)
		{
			LOG_MEDUSA_DEBUG("Constructor of remote client: remote = ", Poseidon::getIpPortFromSockAddr(addr));
		}
		~Client(){
			try {
				LOG_MEDUSA_DEBUG("Destructor of remote client: remote = ", getRemoteInfo());
			} catch(...){
				LOG_MEDUSA_DEBUG("Destructor of remote client: remote is not connected");
			}
		}

	protected:
		void onConnect() OVERRIDE {
			PROFILE_ME;

			const AUTO(session, m_session.lock());
			if(session){
				Poseidon::enqueueJob(boost::make_shared<ClientConnectJob>(
					session, m_fetchUuid));
			}

			Poseidon::TcpClientBase::onConnect();
		}
		void onClose(int errCode) NOEXCEPT OVERRIDE {
			PROFILE_ME;

			const AUTO(session, m_session.lock());
			if(session){
				try {
					Poseidon::enqueueJob(boost::make_shared<ClientCloseJob>(
						session, m_fetchUuid, errCode));
				} catch(std::exception &e){
					LOG_MEDUSA_ERROR("std::exception thrown: what = ", e.what());
					session->forceShutdown();
				}
			}

			Poseidon::TcpClientBase::onClose(errCode);
		}

		void onReadAvail(Poseidon::StreamBuffer data) OVERRIDE {
			PROFILE_ME;

			const AUTO(session, m_session.lock());
			if(!session){
				LOG_MEDUSA_DEBUG("Lost connection to remote client: fetchUuid = ", m_fetchUuid);
				forceShutdown();
				return;
			}

			try {
				Poseidon::enqueueJob(boost::make_shared<ClientReadAvailJob>(
					session, m_fetchUuid, STD_MOVE(data)));
				setTimeout(0);
			} catch(std::exception &e){
				LOG_MEDUSA_ERROR("std::exception thrown: what = ", e.what());
				forceShutdown();
				session->forceShutdown();
			}
		}

	public:
		void goResident(){
			PROFILE_ME;

			const AUTO(connectTimeout, getConfig<boost::uint64_t>("remote_client_connect_timeout", 10000));
			Poseidon::TcpClientBase::setTimeout(connectTimeout);

			Poseidon::TcpClientBase::goResident();
		}
	};

private:
	static void dnsCallback(const boost::weak_ptr<FetchSession> &weakSession, const Poseidon::Uuid &fetchUuid,
		const std::string &host, unsigned port, int gaiCode, const Poseidon::SockAddr &addr, const char *errMsg)
	{
		PROFILE_ME;
		LOG_MEDUSA_DEBUG("DNS result: fetchUuid = ", fetchUuid,
			", host:port = ", host, ':', port, ", gaiCode = ", gaiCode, ", errMsg = ", errMsg);

		const AUTO(session, weakSession.lock());
		if(!session){
			return;
		}
		const AUTO(it, session->m_channels.find(fetchUuid));
		if(it == session->m_channels.end()){
			return;
		}

		try {
			if(it->second.m_connectQueue.empty()){
				LOG_MEDUSA_ERROR("No pending connect request?");
				DEBUG_THROW(Exception, sslit("No pending connect request?"));
			}
			AUTO_REF(elem, it->second.m_connectQueue.front());
			if((elem.host != host) || (elem.port != port)){
				LOG_MEDUSA_ERROR("Unexpected DNS callback: expecting ", elem.host, ':', elem.port, ", got ", host, ':', port);
				DEBUG_THROW(Exception, sslit("Unexpected DNS callback"));
			}

			int cbppErrCode = 0;
			int sysErrCode = 0;
			std::string errMsgStr;

			if(gaiCode != 0){
				LOG_MEDUSA_DEBUG("DNS failure...");
				cbppErrCode = Msg::ERR_DNS_FAILURE;
				sysErrCode = gaiCode;
				errMsgStr = errMsg;
			} else if(addr.isPrivate()){
				LOG_MEDUSA_DEBUG("Connection to private address requested. Abort.");
				cbppErrCode = Msg::ERR_ACCESS_DENIED;
				sysErrCode = ECONNREFUSED;
				errMsgStr = STR_PRIVATE_ADDR_REQUESTED;
			}

			if(cbppErrCode == 0){
				LOG_MEDUSA_DEBUG("Creating remote client...");
				const AUTO(client, boost::make_shared<Client>(addr, elem.useSsl, session, fetchUuid));
				client->goResident();
				it->second.m_client = client;
				it->second.m_updatedTime = Poseidon::getFastMonoClock();
			} else {
				session->send(fetchUuid, Msg::SC_FetchClosed(cbppErrCode, sysErrCode, STD_MOVE(errMsgStr)));
				session->m_channels.erase(it);
			}
		} catch(std::exception &e){
			LOG_MEDUSA_ERROR("std::exception thrown: what = ", e.what());
			session->forceShutdown();
		}
	}
	static void dnsException(const boost::weak_ptr<FetchSession> &weakSession) NOEXCEPT {
		PROFILE_ME;
		LOG_MEDUSA_ERROR("Handling DNS exception...");

		const AUTO(session, weakSession.lock());
		if(session){
			session->forceShutdown();
		}
	}

private:
	const boost::weak_ptr<FetchSession> m_session;
	const Poseidon::Uuid m_fetchUuid;

	std::deque<ConnectElement> m_connectQueue;
	boost::weak_ptr<Client> m_client;
	boost::uint64_t m_updatedTime;

public:
	Channel(const boost::shared_ptr<FetchSession> &session, const Poseidon::Uuid &fetchUuid)
		: m_session(session), m_fetchUuid(fetchUuid)
		, m_updatedTime(0)
	{
	}
	~Channel(){
		killClient(true);
	}

private:
	void createClient(){
		PROFILE_ME;

		assert(!m_connectQueue.empty());

		const AUTO_REF(elem, m_connectQueue.front());
		LOG_MEDUSA_DEBUG("Next fetch request: host:port = ", elem.host, ':', elem.port,
			", useSsl = ", elem.useSsl, ", keepAlive = ", elem.keepAlive);
		DnsDaemon::asyncLookup(elem.host, elem.port,
			boost::bind(&dnsCallback, m_session, m_fetchUuid,  _1, _2, _3, _4, _5),
			boost::bind(&dnsException, m_session), false);
	}
	void killClient(bool force){
		PROFILE_ME;

		const AUTO(client, m_client.lock());
		if(client){
			if(force){
				client->forceShutdown();
			} else {
				client->shutdownRead();
				client->shutdownWrite();
			}
		}

		m_connectQueue.clear();
		m_client.reset();
	}

public:
	const Poseidon::Uuid &getFetchUuid() const {
		return m_fetchUuid;
	}

	boost::uint64_t getUpdatedTime() const {
		return m_updatedTime;
	}

	void connect(std::string host, unsigned port, bool useSsl, bool keepAlive){
		PROFILE_ME;
		LOG_MEDUSA_INFO("Fetch connect: fetchUuid = ", m_fetchUuid,
			", host:port = ", host, ':', port, ", useSsl = ", useSsl, ", keepAlive = ", keepAlive);

		const AUTO(maxPipeliningSize, getConfig<std::size_t>("fetch_max_pipelining_size", 16));
		if(m_connectQueue.size() + 1 > maxPipeliningSize){
			LOG_MEDUSA_WARNING("Max pipelining size exceeded: maxPipeliningSize = ", maxPipeliningSize);
			DEBUG_THROW(Poseidon::Cbpp::Exception, Msg::ERR_MAX_PIPELINING_SIZE);
		}

		m_connectQueue.push_back(ConnectElement(STD_MOVE(host), port, useSsl, keepAlive));

		if(m_connectQueue.size() == 1){
			createClient();
		}

		m_updatedTime = Poseidon::getFastMonoClock();
	}
	bool send(Poseidon::StreamBuffer data){
		PROFILE_ME;

		if(m_connectQueue.empty()){
			LOG_MEDUSA_DEBUG("No connection in progress or connection lost: fetchUuid = ", m_fetchUuid);
			return false;
		}

		if((m_connectQueue.size() == 1) && m_connectQueue.front().connected){
			const AUTO(client, m_client.lock());
			if(!client){
				return false;
			}
			if(!client->send(STD_MOVE(data))){
				return false;
			}
		} else {
			const AUTO(maxPendingBufferSize, getConfig<std::size_t>("fetch_max_pending_buffer_size", 65536));
			std::size_t pendingSize = 0;
			for(AUTO(it, m_connectQueue.begin()); it != m_connectQueue.end(); ++it){
				pendingSize += it->pending.size();
			}
			if(pendingSize + data.size() > maxPendingBufferSize){
				LOG_MEDUSA_WARNING("Max pending buffer size exceeded: maxPendingBufferSize = ", maxPendingBufferSize);
				DEBUG_THROW(Poseidon::Cbpp::Exception, Msg::ERR_MAX_PENDING_BUFFER_SIZE);
			}
			m_connectQueue.back().pending.splice(data);
		}

		m_updatedTime = Poseidon::getFastMonoClock();
		return true;
	}
	void close(int errCode) NOEXCEPT {
		PROFILE_ME;
		LOG_MEDUSA_INFO("Fetch close: fetchUuid = ", m_fetchUuid, ", errCode = ", errCode);

		killClient(errCode != 0);

		m_updatedTime = Poseidon::getFastMonoClock();
	}
};

void FetchSession::syncGcTimerProc(const boost::weak_ptr<FetchSession> &weak, boost::uint64_t now) NOEXCEPT {
	PROFILE_ME;

	const AUTO(session, weak.lock());
	if(!session){
		return;
	}

	try {
		session->onSyncGcTimer(now);
	} catch(std::exception &e){
		LOG_MEDUSA_ERROR("std::exception thrown: what = ", e.what());
		try {
			session->sendError(0, Msg::ST_INTERNAL_ERROR, e.what());
			session->shutdownRead();
			session->shutdownWrite();
		} catch(...){
			session->forceShutdown();
		}
	}
}

FetchSession::FetchSession(Poseidon::UniqueFile socket, std::string password)
	: Poseidon::Cbpp::Session(STD_MOVE(socket))
	, m_password(STD_MOVE(password))
{
	LOG_MEDUSA_DEBUG("Fetch session constructor: remote = ", getRemoteInfo());
}
FetchSession::~FetchSession(){
	try {
		LOG_MEDUSA_DEBUG("Fetch session destructor: remote = ", getRemoteInfo());
	} catch(...){
		LOG_MEDUSA_DEBUG("Fetch session destructor: remote is not connected");
	}
}

void FetchSession::onSyncGcTimer(boost::uint64_t now){
	PROFILE_ME;

	const AUTO(gcTimeout, getConfig<boost::uint64_t>("fetch_channel_gc_timeout", 30000));

	for(AUTO(next, m_channels.begin()), it = next; (next != m_channels.end()) && (++next, true); it = next){
		if(now < it->second.getUpdatedTime() + gcTimeout){
			continue;
		}
		LOG_MEDUSA_DEBUG("Remote client shutdown due to inactivity: fetchUuid = ", it->first);
		m_channels.erase(it);
	}
}

void FetchSession::onSyncDataMessage(boost::uint16_t messageId, const Poseidon::StreamBuffer &payload){
	PROFILE_ME;

	if(!m_gcTimer){
		m_gcTimer = Poseidon::TimerDaemon::registerTimer(5000, 5000,
			boost::bind(&syncGcTimerProc, virtualWeakFromThis<FetchSession>(), _1));
	}

	const AUTO(headerSize, getEncryptedHeaderSize());
	if(payload.size() < headerSize){
		LOG_MEDUSA_WARNING("Frame from remote client is too small, expecting ", headerSize);
		DEBUG_THROW(Poseidon::Cbpp::Exception, Msg::ST_END_OF_STREAM);
	}
	const AUTO(context, tryDecryptHeader(payload, m_password));
	if(!context){
		LOG_MEDUSA_WARNING("Unexpected checksum. Maybe you provided a wrong password?");
		DEBUG_THROW(Poseidon::Cbpp::Exception, Msg::ST_FORBIDDEN);
	}
	Poseidon::StreamBuffer temp(payload);
	temp.discard(headerSize);
	AUTO(plain, decryptPayload(context, STD_MOVE(temp)));

	const AUTO_REF(fetchUuid, context->uuid);
	LOG_MEDUSA_DEBUG("Fetch request: fetchUuid = ", fetchUuid, ", messageId = ", messageId);
	switch(messageId){
		{{
#define ON_MESSAGE(Msg_, req_)	\
		}}	\
		break;	\
	case Msg_::ID: {	\
		Msg_ (req_)(plain);	\
		{ //
#define ON_RAW_MESSAGE(Msg_, req_)	\
		}}	\
		break;	\
	case Msg_::ID: {	\
		::Poseidon::StreamBuffer & (req_) = plain;	\
		{ //
//=============================================================================
	ON_MESSAGE(Msg::CS_FetchConnect, req){
		AUTO(it, m_channels.find(fetchUuid));
		if(it == m_channels.end()){
			it = m_channels.insert(std::make_pair(fetchUuid, Channel(virtualSharedFromThis<FetchSession>(), fetchUuid))).first;
		}
		it->second.connect(STD_MOVE(req.host), req.port, req.useSsl, req.keepAlive);
	}
	ON_RAW_MESSAGE(Msg::CS_FetchSend, req){
		const AUTO(it, m_channels.find(fetchUuid));
		if(it == m_channels.end()){
			send(fetchUuid, Msg::SC_FetchClosed(Msg::ERR_NOT_CONNECTED, ENOTCONN, STR_NO_CONNECTION_ESTABLISHED));
			break;
		}
		if(!it->second.send(STD_MOVE(req))){
			send(fetchUuid, Msg::SC_FetchClosed(Msg::ERR_CONNECTION_LOST, EPIPE, STR_COULD_NOT_SEND_TO_REMOTE));
			m_channels.erase(it);
			break;
		}
	}
	ON_MESSAGE(Msg::CS_FetchClose, req){
		const AUTO(it, m_channels.find(fetchUuid));
		if(it == m_channels.end()){
			send(fetchUuid, Msg::SC_FetchClosed(Msg::ERR_NOT_CONNECTED, ENOTCONN, STR_NO_CONNECTION_ESTABLISHED));
			break;
		}
		it->second.close(req.errCode);
		m_channels.erase(it);
	}
//=============================================================================
		}}
		break;
	default:
		LOG_MEDUSA_ERROR("Unknown fetch message from client: messageId = ", messageId, ", size = ", plain.size());
		DEBUG_THROW(Poseidon::Cbpp::Exception, Msg::ST_NOT_FOUND);
	}
}

bool FetchSession::send(const Poseidon::Uuid &fetchUuid, boost::uint16_t messageId, Poseidon::StreamBuffer plain){
	PROFILE_ME;

	AUTO(pair, encryptHeader(fetchUuid, m_password));
	AUTO(payload, encryptPayload(pair.first, STD_MOVE(plain)));
	pair.second.splice(payload);
	return Poseidon::Cbpp::Session::send(messageId, STD_MOVE(pair.second));
}

}
