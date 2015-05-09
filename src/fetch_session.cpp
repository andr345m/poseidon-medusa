#include "precompiled.hpp"
#include "fetch_session.hpp"
#include <poseidon/singletons/timer_daemon.hpp>
#include <poseidon/tcp_client_base.hpp>
#include <poseidon/hash.hpp>
#include <poseidon/async_job.hpp>
#include <poseidon/job_base.hpp>
#include "encryption.hpp"
#include "singletons/dns_daemon.hpp"
#include "msg/fetch.hpp"
#include "msg/error_codes.hpp"

namespace Medusa {

class FetchSession::Client : public Poseidon::TcpClientBase {
private:
	const boost::weak_ptr<FetchSession> m_parent;
	const Poseidon::Uuid m_fetchUuid;

public:
	Client(const Poseidon::SockAddr &addr, bool useSsl,
		const boost::shared_ptr<FetchSession> &parent, const Poseidon::Uuid &fetchUuid)
		: Poseidon::TcpClientBase(addr, useSsl)
		, m_parent(parent), m_fetchUuid(fetchUuid)
	{
	}

protected:
	void onReadAvail(const void *data, std::size_t size) OVERRIDE {
		PROFILE_ME;
		LOG_MEDUSA_DEBUG("Fetch client has received some data: size = ", size);

		const AUTO(parent, m_parent.lock());
		if(!parent){
			LOG_MEDUSA_DEBUG("Lost connection to fetch client");
			forceShutdown();
			return;
		}

		parent->send(m_fetchUuid, Msg::SC_FetchContents::ID, Poseidon::StreamBuffer(data, size));
	}

	void onClose(int errCode) NOEXCEPT {
		PROFILE_ME;
		LOG_MEDUSA_DEBUG("Fetch client is shutting down...");

		const AUTO(parent, m_parent.lock());
		if(!parent){
			LOG_MEDUSA_DEBUG("Lost connection to fetch client");
			return;
		}

		try {
			if(errCode == 0){
				parent->send(m_fetchUuid, Msg::SC_FetchError(Msg::ST_OK, 0, VAL_INIT));
			} else {
				parent->send(m_fetchUuid, Msg::SC_FetchError(Msg::ST_INTERNAL_ERROR, errCode, VAL_INIT));
			}
		} catch(std::exception &e){
			LOG_MEDUSA_ERROR("std::exception thrown: what = ", e.what());
			parent->forceShutdown();
		}
	}
};

class FetchSession::ClientControl {
private:
	static void realConnect(const boost::weak_ptr<FetchSession> &weakSession, const Poseidon::Uuid &fetchUuid,
		const Poseidon::SockAddr &addr)
	{
		PROFILE_ME;
		LOG_MEDUSA_DEBUG("Establishing connection to ", Poseidon::getIpPortFromSockAddr(addr));

		const AUTO(session, weakSession.lock());
		if(!session){
			return;
		}
		const AUTO(it, session->m_clients.find(fetchUuid));
		if(it == session->m_clients.end()){
			LOG_MEDUSA_DEBUG("Lost connection to client?");
			return;
		}

		AUTO(client, boost::make_shared<Client>(addr, it->second.m_useSsl, session, fetchUuid));
		client->goResident();

		it->second.m_client = client; // noexcept
		it->second.m_connected = true; // noexcept

		LOG_MEDUSA_DEBUG("Done asynchronous connecting.");

		try {
			session->send(fetchUuid, Msg::SC_FetchConnected());

			if(!it->second.m_pending.empty()){
				client->send(STD_MOVE(it->second.m_pending));
				it->second.m_pending.clear();
			}
		} catch(std::exception &e){
			LOG_MEDUSA_ERROR("std::exception thrown: what = ", e.what());

			client->forceShutdown();
			session->forceShutdown();
		}
	}

	static void dnsSuccessCallback(const boost::weak_ptr<FetchSession> &weakSession, const Poseidon::Uuid &fetchUuid,
		const std::string &host, unsigned port, const Poseidon::SockAddr &addr)
	{
		PROFILE_ME;
		LOG_MEDUSA_DEBUG("DNS success callback: host:port = ", host, ':', port);

		const AUTO(session, weakSession.lock());
		if(!session){
			return;
		}

		try {
			Poseidon::enqueueAsyncJob(weakSession, boost::bind(&realConnect, weakSession, fetchUuid, addr));
		} catch(std::exception &e){
			LOG_MEDUSA_ERROR("std::exception thrown: what = ", e.what());
			session->forceShutdown();
		}
	}
	static void dnsFailureCallback(const boost::weak_ptr<FetchSession> &weakSession, const Poseidon::Uuid &fetchUuid,
		const std::string &host, unsigned port, int gaiCode, int /* errCode */, const char *errMsg)
	{
		PROFILE_ME;
		LOG_MEDUSA_DEBUG("DNS failure callback: host:port = ", host, ':', port, ", errMsg = ", errMsg);

		const AUTO(session, weakSession.lock());
		if(!session){
			return;
		}

		try {
			session->send(fetchUuid, Msg::SC_FetchError(Msg::ERR_FETCH_DNS_FAILURE, gaiCode, errMsg));
		} catch(std::exception &e){
			LOG_MEDUSA_ERROR("std::exception thrown: what = ", e.what());
			session->forceShutdown();
		}
	}

private:
	const boost::weak_ptr<FetchSession> m_session;
	const Poseidon::Uuid m_fetchUuid;

	boost::shared_ptr<Poseidon::TimerDaemon> m_dnsTimer;

	std::string m_host;
	unsigned m_port;
	bool m_useSsl;

	bool m_connected;
	boost::weak_ptr<Client> m_client;
	boost::uint64_t m_createdTime;

	Poseidon::StreamBuffer m_pending;

public:
	ClientControl(boost::weak_ptr<FetchSession> session, const Poseidon::Uuid &fetchUuid)
		: m_session(STD_MOVE(session)), m_fetchUuid(fetchUuid)
		, m_port(0), m_useSsl(false)
		, m_connected(false), m_createdTime(Poseidon::getFastMonoClock())
	{
	}
	~ClientControl(){
		const AUTO(client, m_client.lock());
		if(client){
			client->forceShutdown();
		}
	}

public:
	boost::shared_ptr<Client> getClient() const {
		return m_client.lock();
	}
	boost::uint64_t getCreatedTime() const {
		return m_createdTime;
	}

	void prepare(const std::string &host, unsigned port, bool useSsl){
		PROFILE_ME;

		if(m_connected && (m_host == host) && (m_port == port) && (m_useSsl == useSsl)){
			return;
		}

		const AUTO(client, m_client.lock());
		if(client){
			client->forceShutdown();
		}

		m_connected = false;
		m_client.reset();
		m_createdTime = Poseidon::getFastMonoClock();

		DnsDaemon::asyncLookup(host, port,
			boost::bind(&dnsSuccessCallback, m_session, m_fetchUuid, _1, _2, _3),
			boost::bind(&dnsFailureCallback, m_session, m_fetchUuid, _1, _2, _3, _4, _5));

		m_host = host;
		m_port = port;
		m_useSsl = useSsl;
	}
	bool send(Poseidon::StreamBuffer data){
		PROFILE_ME;

		if(m_connected){
			const AUTO(client, m_client.lock());
			if(!client){
				return false;
			}
			return client->send(STD_MOVE(data));
		}

		m_pending.splice(data);
		const AUTO(maxBufferSize, getConfig()->get<boost::uint64_t>("fetch_max_buffer_size", 65536));
		if(m_pending.size() > maxBufferSize){
			LOG_MEDUSA_WARNING("Max buffer size exceeded");
			DEBUG_THROW(Exception, SSLIT("Max buffer size exceeded"));
		}
		return true;
	}
};

void FetchSession::clientGcProc(const boost::weak_ptr<FetchSession> &weakSession, boost::uint64_t now, boost::uint64_t period){
	PROFILE_ME;
	LOG_MEDUSA_DEBUG("Reaping inactive clients...");

	const AUTO(session, weakSession.lock());
	if(!session){
		return;
	}

	AUTO(it, session->m_clients.begin());
	while(it != session->m_clients.end()){
		if(it->second.getClient() || (now < it->second.getCreatedTime() + period * 2)){
			++it;
		} else {
			session->m_clients.erase(it++);
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

void FetchSession::onPlainMessage(const Poseidon::Uuid &fetchUuid, boost::uint16_t messageId, Poseidon::StreamBuffer plain){
	PROFILE_ME;
	LOG_MEDUSA_DEBUG("Fetch request: fetchUuid = ", fetchUuid, ", messageId = ", messageId);

	switch(messageId){
		{{
#define ON_MESSAGE(Msg_, req_)	\
		}}	\
		break;	\
	case Msg_::ID:	{	\
		Msg_ req_(plain);	\
		{
//=============================================================================
	ON_MESSAGE(Msg::CS_FetchConnect, req){
		if(!m_clientGcTimer){
			const AUTO(clientGcInterval, getConfig()->get<boost::uint64_t>("fetch_client_gc_interval", 15000));
			m_clientGcTimer = Poseidon::TimerDaemon::registerTimer(clientGcInterval, clientGcInterval,
				boost::bind(&clientGcProc, virtualWeakFromThis<FetchSession>(), _1, _2));
		}

		AUTO(it, m_clients.find(fetchUuid));
		if(it == m_clients.end()){
			it = m_clients.insert(it,
				std::make_pair(fetchUuid, ClientControl(virtualWeakFromThis<FetchSession>(), fetchUuid)));
		}
		LOG_MEDUSA_DEBUG("Connect request: host:port = ", req.host, ':', req.port, ", useSsl = ", req.useSsl);
		it->second.prepare(req.host, req.port, req.useSsl);
	}
	ON_MESSAGE(Msg::CS_FetchSend, req){
		const AUTO(it, m_clients.find(fetchUuid));
		if(it == m_clients.end()){
			LOG_MEDUSA_DEBUG("Client not found: fetchUuid = ", fetchUuid);
			send(fetchUuid, Msg::SC_FetchError(Msg::ERR_FETCH_CONNECTION_LOST, -1, std::string()));
			break;
		}
		if(!it->second.send(Poseidon::StreamBuffer(req.payload))){
			LOG_MEDUSA_DEBUG("Lost connection to client: fetchUuid = ", fetchUuid);
			send(fetchUuid, Msg::SC_FetchError(Msg::ERR_FETCH_CONNECTION_LOST, -1, std::string()));
			break;
		}
	}
	ON_MESSAGE(Msg::CS_FetchClose, req){
		const AUTO(it, m_clients.find(fetchUuid));
		if(it == m_clients.end()){
			LOG_MEDUSA_DEBUG("Client not found: fetchUuid = ", fetchUuid);
			break;
		}

		const AUTO(client, it->second.getClient());
		if(client){
			client->shutdownRead();
			client->shutdownWrite();
		}
		m_clients.erase(it);
	}
//=============================================================================
		}}
		break;
	default:
		LOG_MEDUSA_ERROR("Unknown fetch message from client: messageId = ", messageId, ", size = ", plain.size());
		DEBUG_THROW(Poseidon::Cbpp::Exception, Poseidon::Cbpp::ST_NOT_FOUND);
	}
}

void FetchSession::onRequest(boost::uint16_t messageId, const Poseidon::StreamBuffer &payload){
	PROFILE_ME;

	const AUTO(headerSize, getEncryptedHeaderSize());

	if(payload.size() < headerSize){
		LOG_MEDUSA_ERROR("Frame from fetch client is too small, expecting ", headerSize);
		sendError(messageId, Msg::ST_END_OF_STREAM, "Frame from fetch client is too small");
		return;
	}

	EncryptionContextPtr decContext;
	if(!tryDecryptHeader(decContext, m_password, payload)){
		LOG_MEDUSA_ERROR("Checksums mismatch. Maybe you provided a wrong password?");
		sendError(messageId, Msg::ERR_INVALID_AUTH, "Checksums mismatch");
		return;
	}

	Poseidon::StreamBuffer temp(payload);
	temp.discard(getEncryptedHeaderSize());
	AUTO(plain, decryptPayload(decContext, STD_MOVE(temp)));
	onPlainMessage(decContext->uuid, messageId, STD_MOVE(plain));
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
