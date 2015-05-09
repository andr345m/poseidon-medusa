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
		ret.reset(new FetchClient(connAddr, hbtm, ssl, STD_MOVE(pass)));
		ret->goResident();
		g_client = ret;
	}
	return ret;
}

FetchClient::FetchClient(const Poseidon::IpPort &addr, boost::uint64_t keepAliveTimeout, bool useSsl, std::string password)
	: Poseidon::Cbpp::LowLevelClient(addr, keepAliveTimeout, useSsl)
	, m_password(STD_MOVE(password))
{
}
FetchClient::~FetchClient(){
	ProxySession::shutdownAll(true);
}

void FetchClient::onLowLevelPlainMessage(const Poseidon::Uuid &sessionUuid, boost::uint16_t messageId, Poseidon::StreamBuffer plain){
	PROFILE_ME;

	const AUTO(session, ProxySession::findByUuid(sessionUuid));
	if(!session){
		LOG_MEDUSA_DEBUG("Session has gone away: sessionUuid = ", sessionUuid);
		return;
	}

	if(messageId == Msg::SC_FetchContents::ID){
		session->sendRaw(STD_MOVE(plain));
	} else if(messageId == Msg::SC_FetchConnected::ID){
		session->notifyFetchConnected();
	} else if(messageId == Msg::SC_FetchError::ID){
		Msg::SC_FetchError msg(plain);
		LOG_MEDUSA_INFO("Fetch error: cbppErrCode = ", msg.cbppErrCode, ", sysErrCode = ", msg.sysErrCode, ", description = ", msg.description);
		session->forceShutdown();
	} else {
		LOG_MEDUSA_WARNING("Unknown message from fetch server: messageId = ", messageId, ", size = ", plain.size());
	}
}

void FetchClient::onLowLevelResponse(boost::uint16_t messageId, boost::uint64_t payloadLen){
	PROFILE_ME;

	const AUTO(headerSize, getEncryptedHeaderSize());

	if(payloadLen < headerSize){
		LOG_MEDUSA_ERROR("Frame from fetch server is too small, expecting ", headerSize);
		DEBUG_THROW(Exception, SSLIT("Frame from fetch server is too small"));
	}

	m_messageId = messageId;
	m_payloadLen = payloadLen;
	m_payload.clear();
	m_decContext.reset();
}
void FetchClient::onLowLevelPayload(boost::uint64_t payloadOffset, Poseidon::StreamBuffer payload){
	PROFILE_ME;
	LOG_MEDUSA_DEBUG("Received payload from fetch server: offset = ", payloadOffset, ", size = ", payload.size());

	const AUTO(headerSize, getEncryptedHeaderSize());

	m_payload.splice(payload);

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

	if(statusCode != Msg::ST_OK){
		return;
	}

	LOG_MEDUSA_ERROR("Fetch error: messageId = ", messageId, ", statusCode = ", statusCode, ", reason = ", reason);
	forceShutdown();
}

bool FetchClient::send(const Poseidon::Uuid &sessionUuid, boost::uint16_t messageId, Poseidon::StreamBuffer plain){
	PROFILE_ME;

	EncryptionContextPtr encContext;
	AUTO(data, encryptHeader(encContext, sessionUuid, m_password));
	AUTO(payload, encryptPayload(encContext, STD_MOVE(plain)));
	data.splice(payload);
	return Poseidon::Cbpp::LowLevelClient::send(messageId, STD_MOVE(data));
}

}
