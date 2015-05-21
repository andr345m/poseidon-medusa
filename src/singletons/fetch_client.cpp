#include "../precompiled.hpp"
#include "fetch_client.hpp"
#include <poseidon/singletons/timer_daemon.hpp>
#include <poseidon/cbpp/control_codes.hpp>
#include "../proxy_session.hpp"
#include "../encryption.hpp"
#include "../msg/cs_fetch.hpp"
#include "../msg/sc_fetch.hpp"
#include "../msg/error_codes.hpp"

namespace Medusa {

namespace {
	Poseidon::Mutex g_clientMutex;
	boost::weak_ptr<FetchClient> g_client;
}

struct FetchClient::Impl : public FetchClient {
	static void keepAliveTimerProc(const boost::weak_ptr<FetchClient> &weakClient){
		PROFILE_ME;

		const AUTO(client, weakClient.lock());
		if(!client){
			return;
		}
		client->sendControl(Poseidon::Cbpp::CTL_HEARTBEAT, 0, VAL_INIT);
	}

	Impl(const Poseidon::IpPort &addr, bool useSsl, boost::uint64_t keepAliveInterval, std::string password)
		: FetchClient(addr, useSsl, keepAliveInterval, STD_MOVE(password))
	{
	}
};

boost::shared_ptr<FetchClient> FetchClient::get(){
	const Poseidon::Mutex::UniqueLock lock(g_clientMutex);
	return g_client.lock();
}
boost::shared_ptr<FetchClient> FetchClient::require(){
	const Poseidon::Mutex::UniqueLock lock(g_clientMutex);
	AUTO(client, g_client.lock());
	if(!client){
		AUTO(addr, getConfig<std::string>("fetch_client_addr", "0.0.0.0"));
		AUTO(port, getConfig<unsigned>("fetch_client_port", 5326));
		AUTO(hbtm, getConfig<boost::uint64_t>("fetch_client_heartbeat_interval", 15000));
		AUTO(ssl,  getConfig<bool>("fetch_client_uses_ssl", false));
		AUTO(pass, getConfig<std::string>("fetch_client_password", ""));

		const Poseidon::IpPort addrPort(SharedNts(addr), port);
		LOG_MEDUSA_INFO("Creating fetch client to ", addrPort, (ssl ? " using SSL" : ""));
		client = boost::make_shared<Impl>(addrPort, ssl, hbtm, STD_MOVE(pass));
		client->goResident();
		g_client = client;
	}
	return client;
}

FetchClient::FetchClient(const Poseidon::IpPort &addr, bool useSsl, boost::uint64_t keepAliveInterval, std::string password)
	: Poseidon::TcpClientBase(addr, useSsl)
	, m_keepAliveInterval(keepAliveInterval), m_password(STD_MOVE(password))
{
}
FetchClient::~FetchClient(){
	for(AUTO(it, m_sessions.begin()); it != m_sessions.end(); ++it){
		const AUTO(session, it->second.lock());
		if(!session){
			continue;
		}
		session->forceShutdown();
	}
}

bool FetchClient::send(const Poseidon::Uuid &fetchUuid, boost::uint16_t messageId, Poseidon::StreamBuffer plain){
	PROFILE_ME;

	AUTO(pair, encryptHeader(fetchUuid, m_password));
	AUTO(payload, encryptPayload(pair.first, STD_MOVE(plain)));
	pair.second.splice(payload);

	const Poseidon::Mutex::UniqueLock lock(m_mutex);
	if(!m_keepAliveTimer){
		m_keepAliveTimer = Poseidon::TimerDaemon::registerTimer(m_keepAliveInterval, m_keepAliveInterval,
			boost::bind(&Impl::keepAliveTimerProc, virtualWeakFromThis<FetchClient>()));
	}
	return Poseidon::Cbpp::Writer::putDataMessage(messageId, STD_MOVE(pair.second));
}
bool FetchClient::sendControl(Poseidon::Cbpp::ControlCode controlCode, boost::int64_t vintParam, std::string stringParam){
	PROFILE_ME;

	return Poseidon::Cbpp::Writer::putControlMessage(controlCode, vintParam, STD_MOVE(stringParam));
}

void FetchClient::onReadAvail(const void *data, std::size_t size){
	PROFILE_ME;

	Poseidon::Cbpp::Reader::putEncodedData(Poseidon::StreamBuffer(data, size));
}

void FetchClient::onDataMessageHeader(boost::uint16_t messageId, boost::uint64_t payloadSize){
	PROFILE_ME;
	LOG_MEDUSA_DEBUG("Fetch data message header: messageId = ", messageId, ", payloadSize = ", payloadSize);

	const AUTO(headerSize, getEncryptedHeaderSize());
	if(payloadSize < headerSize){
		LOG_MEDUSA_ERROR("Frame from fetch server is too small, expecting ", headerSize);
		forceShutdown();
		return;
	}

	m_messageId = messageId;
	m_payload.clear();
}
void FetchClient::onDataMessagePayload(boost::uint64_t payloadOffset, Poseidon::StreamBuffer payload){
	PROFILE_ME;
	LOG_MEDUSA_DEBUG("Fetch data message fragment: payloadOffset = ", payloadOffset, ", fragmentSize = ", payload.size());

	m_payload.splice(payload);
}
bool FetchClient::onDataMessageEnd(boost::uint64_t payloadSize){
	PROFILE_ME;
	LOG_MEDUSA_DEBUG("Fetch data message end: payloadSize = ", payloadSize);

	const AUTO(headerSize, getEncryptedHeaderSize());
	if(m_payload.size() < headerSize){
		LOG_MEDUSA_ERROR("Frame from fetch server is too small, expecting ", headerSize);
		forceShutdown();
		return false;
	}

	const AUTO(context, tryDecryptHeader(m_payload, m_password));
	if(!context){
		LOG_MEDUSA_ERROR("Checksums mismatch. Maybe you provided a wrong password?");
		forceShutdown();
		return false;
	}
	m_payload.discard(headerSize);
	AUTO(plain, decryptPayload(context, STD_MOVE(m_payload)));

	const AUTO_REF(fetchUuid, context->uuid);
	LOG_MEDUSA_DEBUG("Fetch response: fetchUuid = ", fetchUuid, ", messageId = ", m_messageId);
	boost::shared_ptr<ProxySession> session;
	{
		const Poseidon::Mutex::UniqueLock lock(m_mutex);
		const AUTO(it, m_sessions.find(fetchUuid));
		if(it != m_sessions.end()){
			session = it->second.lock();
		}
	}
	if(!session){
		LOG_MEDUSA_DEBUG("Proxy session has gone away: fetchUuid = ", fetchUuid);
		return true;
	}
	switch(m_messageId){
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
	ON_RAW_MESSAGE(Msg::SC_FetchConnect, req){
		LOG_MEDUSA_DEBUG("Fetch connect: fetchUuid = ", fetchUuid);
		session->onFetchConnect();
	}
	ON_RAW_MESSAGE(Msg::SC_FetchReceive, req){
		LOG_MEDUSA_DEBUG("Fetch receive: fetchUuid = ", fetchUuid, ", size = ", req.size());
		session->onFetchReceive(STD_MOVE(req));
	}
	ON_MESSAGE(Msg::SC_FetchEnd, req){
		LOG_MEDUSA_DEBUG("Fetch end: fetchUuid = ", fetchUuid, ", errCode = ", req.errCode);
		session->onFetchEnd(req.errCode);
	}
	ON_MESSAGE(Msg::SC_FetchClose, req){
		LOG_MEDUSA_DEBUG("Fetch close: fetchUuid = ", fetchUuid,
			", cbppErrCode = ", req.cbppErrCode, ", sysErrCode = ", req.sysErrCode, ", errMsg = ", req.errMsg);
		session->onFetchClose(req.cbppErrCode, req.sysErrCode, STD_MOVE(req.errMsg));
	}
//=============================================================================
		}}
		break;
	default:
		LOG_MEDUSA_ERROR("Unknown fetch response from server: messageId = ", m_messageId, ", size = ", plain.size());
		forceShutdown();
		return false;
	}
	return true;
}

bool FetchClient::onControlMessage(Poseidon::Cbpp::ControlCode controlCode, boost::int64_t vintParam, std::string stringParam){
	PROFILE_ME;

	const unsigned messageId = static_cast<boost::uint16_t>(controlCode);
	const AUTO(statusCode, static_cast<Poseidon::Cbpp::StatusCode>(vintParam));
	const AUTO_REF(reason, stringParam);

	if(statusCode == Msg::ST_OK){
		return true;
	}

	LOG_MEDUSA_ERROR("Fetch error: messageId = ", messageId, ", statusCode = ", statusCode, ", reason = ", reason);
	forceShutdown();
	return false;
}

long FetchClient::onEncodedDataAvail(Poseidon::StreamBuffer encoded){
	PROFILE_ME;

	return Poseidon::TcpSessionBase::send(STD_MOVE(encoded));
}

bool FetchClient::connect(const boost::shared_ptr<ProxySession> &session, std::string host, unsigned port, bool useSsl){
	PROFILE_ME;

	const AUTO(fetchUuid, session->getFetchUuid());
	boost::shared_ptr<ProxySession> oldSession;
	{
		const Poseidon::Mutex::UniqueLock lock(m_mutex);
		AUTO_REF(oldWeakSession, m_sessions[fetchUuid]);
		oldSession = oldWeakSession.lock();
		oldWeakSession = session;
	}
	if(oldSession && (oldSession != session)){
		LOG_MEDUSA_WARNING("Conflict UUID? fetchUuid = ", fetchUuid);
		oldSession->forceShutdown();
	}
	return send(fetchUuid, Msg::CS_FetchConnect(STD_MOVE(host), port, useSsl));
}
bool FetchClient::send(const boost::shared_ptr<ProxySession> &session, Poseidon::StreamBuffer data){
	PROFILE_ME;

	const AUTO(fetchUuid, session->getFetchUuid());
	boost::shared_ptr<ProxySession> oldSession;
	{
		const Poseidon::Mutex::UniqueLock lock(m_mutex);
		AUTO_REF(oldWeakSession, m_sessions[fetchUuid]);
		oldSession = oldWeakSession.lock();
		oldWeakSession = session;
	}
	if(oldSession && (oldSession != session)){
		return false;
	}
	return send(fetchUuid, Msg::CS_FetchSend::ID, STD_MOVE(data));
}
void FetchClient::close(const Poseidon::Uuid &fetchUuid, int errCode) NOEXCEPT {
	PROFILE_ME;

	bool erased = false;
	{
		const Poseidon::Mutex::UniqueLock lock(m_mutex);
		const AUTO(it, m_sessions.find(fetchUuid));
		if(it != m_sessions.end()){
			erased = true;
			m_sessions.erase(it);
		}
	}
	if(!erased){
		return;
	}
	try {
		send(fetchUuid, Msg::CS_FetchClose(errCode));
	} catch(std::exception &e){
		LOG_MEDUSA_ERROR("std::exception thrown: what = ", e.what());
		forceShutdown();
	}
}

}
