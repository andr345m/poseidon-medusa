#include "../precompiled.hpp"
#include "fetch_client.hpp"
#include "../proxy_session.hpp"
#include "../encryption.hpp"
#include "../msg/fetch.hpp"
#include "../msg/error_codes.hpp"

namespace Medusa {

namespace {
	Poseidon::Mutex g_clientMutex;
	boost::weak_ptr<FetchClient> g_client;
}

boost::shared_ptr<FetchClient> FetchClient::get(){
	const Poseidon::Mutex::UniqueLock lock(g_clientMutex);
	return g_client.lock();
}
boost::shared_ptr<FetchClient> FetchClient::require(){
	const Poseidon::Mutex::UniqueLock lock(g_clientMutex);
	AUTO(ret, g_client.lock());
	if(!ret){
		AUTO(addr, getConfig()->get<std::string>("fetch_client_addr", "0.0.0.0"));
		AUTO(port, getConfig()->get<unsigned>("fetch_client_port", 5326));
		AUTO(hbtm, getConfig()->get<boost::uint64_t>("fetch_client_heartbeat_interval", 15000));
		AUTO(ssl,  getConfig()->get<bool>("fetch_client_uses_ssl", false));
		AUTO(pass, getConfig()->get<std::string>("fetch_client_password", ""));

		const Poseidon::IpPort connAddr(SharedNts(addr), port);
		LOG_MEDUSA_INFO("Creating fetch client to ", connAddr, (ssl ? " using SSL" : ""));
		ret.reset(new FetchClient(connAddr, ssl, hbtm, STD_MOVE(pass)));
		ret->goResident();
		g_client = ret;
	}
	return ret;
}

FetchClient::FetchClient(const Poseidon::IpPort &addr, bool useSsl, boost::uint64_t keepAliveTimeout, std::string password)
	: Poseidon::Cbpp::LowLevelClient(addr, useSsl, keepAliveTimeout)
	, m_password(STD_MOVE(password))
{
}
FetchClient::~FetchClient(){
	for(AUTO(it, m_sessions.begin()); it != m_sessions.end(); ++it){
		const AUTO(client, it->second.lock());
		if(!client){
			continue;
		}
		client->forceShutdown();
	}
}

void FetchClient::onLowLevelPlainMessage(const Poseidon::Uuid &fetchUuid, boost::uint16_t messageId, Poseidon::StreamBuffer plain){
	PROFILE_ME;

	const AUTO(session, getSession(fetchUuid));
	if(!session){
		LOG_MEDUSA_DEBUG("Session has gone away: fetchUuid = ", fetchUuid);
		return;
	}

	switch(messageId){
		{{
#define ON_MESSAGE(Msg_, msg_)	\
		}}	\
		break;	\
	case Msg_::ID: {	\
		Msg_ msg(plain);	\
		{ //
#define ON_RAW_MESSAGE(Msg_)	\
		}}	\
		break;	\
	case Msg_::ID: {	\
		{ //
//=============================================================================
		ON_MESSAGE(Msg::SC_FetchResponseHeaders, msg){
			Poseidon::Http::ResponseHeaders responseHeaders;
			session->send(STD_MOVE(responseHeaders));
		}
		ON_RAW_MESSAGE(Msg::SC_FetchReceive){
			session->sendRaw(STD_MOVE(plain));
		}
		ON_MESSAGE(Msg::SC_FetchError, msg){
			LOG_MEDUSA_DEBUG("Fetch error: fetchUuid = ", fetchUuid,
				", cbppErrCode = ", msg.cbppErrCode, ", sysErrCode = ", msg.sysErrCode, ", description = ", msg.description);
			if(msg.cbppErrCode == Msg::ST_OK){
				session->shutdownRead();
				session->shutdownWrite();
			} else {
				session->forceShutdown();
			}
		}
//=============================================================================
		}}
		break;
	default:
		LOG_MEDUSA_WARNING("Unknown message from fetch server: messageId = ", messageId, ", size = ", plain.size());
		break;
	}
}

void FetchClient::onLowLevelResponse(boost::uint16_t messageId, boost::uint64_t payloadLen){
	PROFILE_ME;

	const AUTO(headerSize, getEncryptedHeaderSize());
	if(payloadLen < headerSize){
		LOG_MEDUSA_ERROR("Frame from fetch server is too small, expecting ", headerSize);
		forceShutdown();
		return;
	}
	m_messageId = messageId;
	m_payloadLen = payloadLen;
	m_payload.clear();
	m_decContext.reset();
}
void FetchClient::onLowLevelPayload(boost::uint64_t payloadOffset, Poseidon::StreamBuffer payload){
	PROFILE_ME;
	LOG_MEDUSA_DEBUG("Received payload from fetch server: offset = ", payloadOffset, ", size = ", payload.size());

	m_payload.splice(payload);

	const AUTO(headerSize, getEncryptedHeaderSize());
	if(!m_decContext){
		assert(m_payloadLen >= headerSize);
		if(m_payload.size() < headerSize){
			return;
		}
		if(!tryDecryptHeader(m_decContext, m_password, m_payload)){
			LOG_MEDUSA_ERROR("Checksums mismatch. Maybe you provided a wrong password?");
			DEBUG_THROW(Exception, SSLIT("Checksums mismatch"));
		}
	}
	if(m_payload.size() < m_payloadLen){
		return;
	}
	m_payload.discard(headerSize);
	AUTO(plain, decryptPayload(m_decContext, STD_MOVE(m_payload)));
	onLowLevelPlainMessage(m_decContext->uuid, m_messageId, STD_MOVE(plain));
}

void FetchClient::onLowLevelError(boost::uint16_t messageId, Poseidon::Cbpp::StatusCode statusCode, std::string reason){
	PROFILE_ME;

	LOG_MEDUSA_ERROR("Fetch error: messageId = ", messageId, ", statusCode = ", statusCode, ", reason = ", reason);
	forceShutdown();
}

boost::shared_ptr<ProxySession> FetchClient::getSession(const Poseidon::Uuid &fetchUuid){
	PROFILE_ME;

	const Poseidon::Mutex::UniqueLock lock(m_sessionMutex);
	const AUTO(it, m_sessions.find(fetchUuid));
	if(it == m_sessions.end()){
		return VAL_INIT;
	}
	AUTO(session, it->second.lock());
	if(!session){
		m_sessions.erase(it);
		return VAL_INIT;
	}
	return STD_MOVE(session);
}
void FetchClient::link(const boost::shared_ptr<ProxySession> &session){
	PROFILE_ME;

	const Poseidon::Mutex::UniqueLock lock(m_sessionMutex);
	m_sessions[session->getUuid()] = session;
}
void FetchClient::unlink(const Poseidon::Uuid &fetchUuid) NOEXCEPT {
	PROFILE_ME;

	const Poseidon::Mutex::UniqueLock lock(m_sessionMutex);
	m_sessions.erase(fetchUuid);
}

bool FetchClient::send(const Poseidon::Uuid &fetchUuid, boost::uint16_t messageId, Poseidon::StreamBuffer plain){
	PROFILE_ME;

	EncryptionContextPtr encContext;
	AUTO(data, encryptHeader(encContext, fetchUuid, m_password));
	AUTO(payload, encryptPayload(encContext, STD_MOVE(plain)));
	data.splice(payload);
	return Poseidon::Cbpp::LowLevelClient::send(messageId, STD_MOVE(data));
}

}
