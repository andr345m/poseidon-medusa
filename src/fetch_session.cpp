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

class FetchSession::Channel {
private:
	struct ConnectElement {
		std::string host;
		unsigned port;
		bool useSsl;

		Poseidon::StreamBuffer pending;
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
			const AUTO(it, session->m_channels.find(Channel(m_fetchUuid)));
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
		virtual void perform(const boost::shared_ptr<FetchSession> &session, std::set<Channel>::const_iterator it) const = 0;
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
		void perform(const boost::shared_ptr<FetchSession> &session, std::set<Channel>::const_iterator it) const OVERRIDE {
			PROFILE_ME;

			if(m_errCode != 0){
				session->send(it->getFetchUuid(), Msg::SC_FetchClose(Msg::ST_INTERNAL_ERROR, m_errCode, VAL_INIT));
				session->m_channels.erase(it);
				return;
			}
			session->send(it->getFetchUuid(), Msg::SC_FetchEnd(0));

			it->m_connectQueue.pop_front();
			if(!it->m_connectQueue.empty()){
				it->nextRequest();
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
		void perform(const boost::shared_ptr<FetchSession> &session, std::set<Channel>::const_iterator it) const OVERRIDE {
			PROFILE_ME;

			session->send(it->getFetchUuid(), Msg::SC_FetchReceive::ID, STD_MOVE(m_data));
			it->m_updatedTime = Poseidon::getFastMonoClock();
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
		}

	protected:
		void onClose(int errCode) NOEXCEPT OVERRIDE {
			PROFILE_ME;

			do {
				const AUTO(session, m_session.lock());
				if(!session){
					break;
				}
				const AUTO(it, session->m_channels.find(Channel(m_fetchUuid)));
				if(it == session->m_channels.end()){
					break;
				}
				const AUTO(test, it->m_client.lock());
				if(test.get() != this){
					break;
				}

				try {
					Poseidon::enqueueJob(boost::make_shared<ClientCloseJob>(
						session, m_fetchUuid, errCode));
				} catch(std::exception &e){
					LOG_MEDUSA_ERROR("std::exception thrown: what = ", e.what());
					session->forceShutdown();
				}
			} while(false);

			Poseidon::TcpClientBase::onClose(errCode);
		}

		void onReadAvail(const void *data, std::size_t size) OVERRIDE {
			PROFILE_ME;

			const AUTO(session, m_session.lock());
			if(!session){
				LOG_MEDUSA_DEBUG("Lost connection to fetch client: fetchUuid = ", m_fetchUuid);
				forceShutdown();
				return;
			}

			try {
				Poseidon::enqueueJob(boost::make_shared<ClientReadAvailJob>(
					session, m_fetchUuid, Poseidon::StreamBuffer(data, size)));
			} catch(std::exception &e){
				LOG_MEDUSA_ERROR("std::exception thrown: what = ", e.what());
				forceShutdown();
				session->forceShutdown();
			}
		}
	};

private:
	static void dnsCallback(const boost::weak_ptr<FetchSession> &weakSession, const Poseidon::Uuid &fetchUuid,
		const std::string &host, unsigned port, int gaiCode, const Poseidon::SockAddr &addr, int errCode, const char *errMsg)
	{
		PROFILE_ME;
		LOG_MEDUSA_DEBUG("DNS result: fetchUuid = ", fetchUuid,
			", host:port = ", host, ':', port, ", gaiCode = ", gaiCode, ", errCode = ", errCode, ", errMsg = ", errMsg);

		const AUTO(session, weakSession.lock());
		if(!session){
			return;
		}
		const AUTO(it, session->m_channels.find(Channel(fetchUuid)));
		if(it == session->m_channels.end()){
			return;
		}

		try {
			if(it->m_connectQueue.empty()){
				LOG_MEDUSA_ERROR("No pending connect request?");
				DEBUG_THROW(Exception, sslit("No pending connect request?"));
			}

			AUTO_REF(elem, it->m_connectQueue.front());
			if((elem.host != host) || (elem.port != port)){
				LOG_MEDUSA_ERROR("Unexpected DNS callback: expecting ", elem.host, ':', elem.port, ", got ", host, ':', port);
				DEBUG_THROW(Exception, sslit("Unexpected DNS callback"));
			}

			if(gaiCode == 0){
				LOG_MEDUSA_DEBUG("Creating fetch client...");
				const AUTO(client, boost::make_shared<Client>(addr, elem.useSsl, session, fetchUuid));
				client->goResident();
				if(!elem.pending.empty()){
					client->send(STD_MOVE(elem.pending));
					elem.pending.clear();
				}
				it->m_client = client;
			} else {
				LOG_MEDUSA_DEBUG("DNS failure...");
				session->send(fetchUuid, Msg::SC_FetchClose(Msg::ERR_FETCH_DNS_FAILURE, gaiCode, errMsg));
				session->m_channels.erase(it);
			}
			it->m_updatedTime = Poseidon::getFastMonoClock();
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

	mutable std::deque<ConnectElement> m_connectQueue;
	mutable boost::weak_ptr<Client> m_client;
	mutable boost::uint64_t m_updatedTime;

public:
	explicit Channel(const Poseidon::Uuid &fetchUuid)
		: m_fetchUuid(fetchUuid)
		, m_updatedTime(0)
	{
	}
	~Channel(){
		close(ECONNRESET);
	}

private:
	void nextRequest() const {
		PROFILE_ME;

		assert(!m_connectQueue.empty());

		const AUTO_REF(elem, m_connectQueue.front());
		LOG_MEDUSA_DEBUG("Next fetch request: host:port = ", elem.host, ':', elem.port, ", useSsl = ", elem.useSsl);
		DnsDaemon::asyncLookup(elem.host, elem.port,
			boost::bind(&dnsCallback, m_session, m_fetchUuid,  _1, _2, _3, _4, _5, _6),
			boost::bind(&dnsException, m_session), false);
	}

public:
	const Poseidon::Uuid &getFetchUuid() const {
		return m_fetchUuid;
	}

	boost::uint64_t getUpdatedTime() const {
		return m_updatedTime;
	}

	void connect(std::string host, unsigned port, bool useSsl) const {
		PROFILE_ME;

		ConnectElement elem;
		elem.host = STD_MOVE(host);
		elem.port = port;
		elem.useSsl = useSsl;
		m_connectQueue.push_back(STD_MOVE(elem));

		if(m_connectQueue.size() == 1){
			nextRequest();
		}
		m_updatedTime = Poseidon::getFastMonoClock();
	}
	bool send(Poseidon::StreamBuffer data) const {
		PROFILE_ME;

		bool ret;
		if(m_connectQueue.empty()){
			LOG_MEDUSA_ERROR("No connection in progress?");
			ret = false;
		} else if(m_connectQueue.size() == 1){
			const AUTO(client, m_client.lock());
			if(client){
				ret = client->send(STD_MOVE(data));
			} else {
				LOG_MEDUSA_DEBUG("Lost connection to remote host");
				ret = false;
			}
		} else {
			m_connectQueue.back().pending.splice(data);
			ret = true;
		}
		m_updatedTime = Poseidon::getFastMonoClock();
		return ret;
	}
	void close(int errCode) const NOEXCEPT {
		PROFILE_ME;

		const AUTO(client, m_client.lock());
		if(client){
			if(errCode == 0){
				client->shutdownRead();
				client->shutdownWrite();
			} else {
				client->forceShutdown();
			}
		}

		m_connectQueue.clear();
		m_client.reset();
		m_updatedTime = Poseidon::getFastMonoClock();
	}

public:
	bool operator<(const Channel &rhs) const {
		return m_fetchUuid < rhs.m_fetchUuid;
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
}
FetchSession::~FetchSession(){
}

void FetchSession::onSyncGcTimer(boost::uint64_t now){
	PROFILE_ME;

	const AUTO(gcTimeout, getConfig<boost::uint64_t>("fetch_channel_gc_timeout", 30000));

	for(AUTO(next, m_channels.begin()), it = next; (next != m_channels.end()) && (++next, true); it = next){
		if(now < it->getUpdatedTime() + gcTimeout){
			continue;
		}
		LOG_MEDUSA_DEBUG("Fetch client shutdown due to inactivity: fetchUuid = ", it->getFetchUuid());
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
		LOG_MEDUSA_WARNING("Frame from fetch client is too small, expecting ", headerSize);
		DEBUG_THROW(Poseidon::Cbpp::Exception, Msg::ST_END_OF_STREAM);
	}
	const AUTO(context, tryDecryptHeader(payload, m_password));
	if(!context){
		LOG_MEDUSA_WARNING("Unexpected checksum. Maybe you provided a wrong password?");
		DEBUG_THROW(Poseidon::Cbpp::Exception, Msg::ERR_INVALID_AUTH);
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
		const AUTO(it, m_channels.insert(Channel(fetchUuid)).first);
		it->connect(STD_MOVE(req.host), req.port, req.useSsl);
	}
	ON_RAW_MESSAGE(Msg::CS_FetchSend, req){
		const AUTO(it, m_channels.find(Channel(fetchUuid)));
		if(it == m_channels.end()){
			send(fetchUuid, Msg::SC_FetchClose(Msg::ERR_FETCH_NOT_CONNECTED, ENOTCONN, VAL_INIT));
			break;
		}
		if(!it->send(STD_MOVE(req))){
			send(fetchUuid, Msg::SC_FetchClose(Msg::ERR_FETCH_CONNECTION_LOST, EPIPE, VAL_INIT));
			it->close(EPIPE);
			break;
		}
	}
	ON_MESSAGE(Msg::CS_FetchClose, req){
		const AUTO(it, m_channels.find(Channel(fetchUuid)));
		if(it == m_channels.end()){
			break;
		}
		it->close(req.errCode);
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
