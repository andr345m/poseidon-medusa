#include "../precompiled.hpp"
#include "fetch_client.hpp"
#include <poseidon/job_base.hpp>
#include <poseidon/singletons/timer_daemon.hpp>
#include <poseidon/cbpp/control_codes.hpp>
#include "../proxy_session.hpp"
#include "../encryption.hpp"
#include "../msg/cs_fetch.hpp"
#include "../msg/sc_fetch.hpp"
#include "../msg/error_codes.hpp"

namespace Medusa {

namespace {
	std::vector<boost::weak_ptr<FetchClient> > g_clients;
	std::size_t g_currentIndex = 0;

	boost::weak_ptr<FetchClient> &getNextClientRef(){
		PROFILE_ME;

		if(g_clients.empty()){
			AUTO(count, getConfig<std::size_t>("fetch_client_count", 5));
			if(count == 0){
				LOG_MEDUSA_WARNING("Fetch client count was set to zero? Corrected as one.");
				count = 1;
			}
			g_clients.resize(count);
		}

		if(++g_currentIndex >= g_clients.size()){
			g_currentIndex = 0;
		}
		return g_clients.at(g_currentIndex);
	}
}

class FetchClient::CloseJob : public Poseidon::JobBase {
private:
	const boost::shared_ptr<FetchClient> m_client;
	const int m_errCode;

public:
	CloseJob(const boost::shared_ptr<FetchClient> &client, int errCode)
		: m_client(client), m_errCode(errCode)
	{
	}

protected:
	boost::weak_ptr<const void> getCategory() const FINAL {
		return m_client;
	}
	void perform() const FINAL {
		PROFILE_ME;

		if(m_errCode == 0){
			m_client->clear(Msg::ST_OK, 0, "Connection to fetch server closed gracefully");
		} else {
			m_client->clear(Msg::ERR_CONNECTION_LOST, m_errCode, "Lost connection to fetch server");
		}
	}
};

boost::shared_ptr<FetchClient> FetchClient::get(){
	PROFILE_ME;

	const AUTO_REF(weakClient, getNextClientRef());
	AUTO(client, weakClient.lock());
	return client;
}
boost::shared_ptr<FetchClient> FetchClient::require(){
	PROFILE_ME;

	AUTO_REF(weakClient, getNextClientRef());
	AUTO(client, weakClient.lock());
	if(!client){
		AUTO(addr, getConfig<std::string>("fetch_client_addr", "0.0.0.0"));
		AUTO(port, getConfig<unsigned>("fetch_client_port", 5326));
		AUTO(hbtm, getConfig<boost::uint64_t>("fetch_client_heartbeat_interval", 15000));
		AUTO(ssl,  getConfig<bool>("fetch_client_uses_ssl", false));
		AUTO(pass, getConfig<std::string>("fetch_client_password", ""));

		const Poseidon::IpPort addrPort(SharedNts(addr), port);
		LOG_MEDUSA_INFO("Creating fetch client to ", addrPort, (ssl ? " using SSL" : ""));
		client.reset(new FetchClient(addrPort, ssl, hbtm, STD_MOVE(pass)));
		client->goResident();
		weakClient = client;
	}
	return client;
}

FetchClient::FetchClient(const Poseidon::IpPort &addr, bool useSsl, boost::uint64_t keepAliveInterval, std::string password)
	: Poseidon::Cbpp::Client(addr, useSsl, keepAliveInterval)
	, m_password(STD_MOVE(password))
{
}
FetchClient::~FetchClient(){
	clear(Msg::ERR_CONNECTION_LOST, ECONNRESET, "Lost connection to fetch server");
}

void FetchClient::onClose(int errCode) NOEXCEPT {
	PROFILE_ME;

	try {
		Poseidon::enqueueJob(boost::make_shared<CloseJob>(virtualSharedFromThis<FetchClient>(), errCode));
	} catch(std::exception &e){
		LOG_MEDUSA_ERROR("std::exception thrown: what = ", e.what());
	}

	Poseidon::Cbpp::Client::onClose(errCode);
}

bool FetchClient::sendData(const Poseidon::Uuid &fetchUuid, boost::uint16_t messageId, Poseidon::StreamBuffer plain){
	PROFILE_ME;

	AUTO(pair, encryptHeader(fetchUuid, m_password));
	AUTO(payload, encryptPayload(pair.first, STD_MOVE(plain)));
	pair.second.splice(payload);
	return Poseidon::Cbpp::Client::send(messageId, STD_MOVE(pair.second));
}
bool FetchClient::sendControl(Poseidon::Cbpp::ControlCode controlCode, boost::int64_t vintParam, std::string stringParam){
	PROFILE_ME;

	return Poseidon::Cbpp::Client::sendControl(controlCode, vintParam, STD_MOVE(stringParam));
}

void FetchClient::onSyncDataMessageHeader(boost::uint16_t messageId, boost::uint64_t payloadSize){
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
void FetchClient::onSyncDataMessagePayload(boost::uint64_t payloadOffset, const Poseidon::StreamBuffer &payload){
	PROFILE_ME;
	LOG_MEDUSA_DEBUG("Fetch data message fragment: payloadOffset = ", payloadOffset, ", fragmentSize = ", payload.size());

	AUTO(temp, payload);
	m_payload.splice(temp);
}
void FetchClient::onSyncDataMessageEnd(boost::uint64_t payloadSize){
	PROFILE_ME;
	LOG_MEDUSA_DEBUG("Fetch data message end: payloadSize = ", payloadSize);

	const AUTO(headerSize, getEncryptedHeaderSize());
	if(m_payload.size() < headerSize){
		LOG_MEDUSA_ERROR("Frame from fetch server is too small, expecting ", headerSize);
		forceShutdown();
		return;
	}

	const AUTO(context, tryDecryptHeader(m_payload, m_password));
	if(!context){
		LOG_MEDUSA_ERROR("Checksums mismatch. Maybe you provided a wrong password?");
		forceShutdown();
		return;
	}
	m_payload.discard(headerSize);
	AUTO(plain, decryptPayload(context, STD_MOVE(m_payload)));

	const AUTO_REF(fetchUuid, context->uuid);
	LOG_MEDUSA_DEBUG("Fetch response: fetchUuid = ", fetchUuid, ", messageId = ", m_messageId);
	const AUTO(it, m_sessions.find(fetchUuid));
	if(it == m_sessions.end()){
		LOG_MEDUSA_DEBUG("Proxy session has gone away: fetchUuid = ", fetchUuid);
		return;
	}
	const AUTO(session, it->second.lock());
	if(!session){
		LOG_MEDUSA_DEBUG("Shutting down expired proxy session: fetchUuid = ", fetchUuid);
		m_sessions.erase(it);
		sendData(fetchUuid, Msg::CS_FetchClose(EPIPE));
		return;
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
	ON_MESSAGE(Msg::SC_FetchConnected, req){
		LOG_MEDUSA_DEBUG("Fetch connected: fetchUuid = ", fetchUuid, ", keepAlive = ", req.keepAlive);
		session->onFetchConnected(req.keepAlive);
	}
	ON_RAW_MESSAGE(Msg::SC_FetchReceived, req){
		LOG_MEDUSA_DEBUG("Fetch received: fetchUuid = ", fetchUuid, ", size = ", req.size());
		session->onFetchReceived(STD_MOVE(req));
	}
	ON_MESSAGE(Msg::SC_FetchEnded, req){
		LOG_MEDUSA_DEBUG("Fetch ended: fetchUuid = ", fetchUuid);
		session->onFetchEnded();
	}
	ON_MESSAGE(Msg::SC_FetchClosed, req){
		LOG_MEDUSA_DEBUG("Fetch closed: fetchUuid = ", fetchUuid,
			", cbppErrCode = ", req.cbppErrCode, ", sysErrCode = ", req.sysErrCode, ", errMsg = ", req.errMsg);
		try {
			session->onFetchClosed(req.cbppErrCode, req.sysErrCode, STD_MOVE(req.errMsg));
			session->shutdownRead();
			session->shutdownWrite();
		} catch(std::exception &e){
			LOG_MEDUSA_ERROR("std::exception thrown: what = ", e.what());
			session->forceShutdown();
		}
		m_sessions.erase(it);
	}
//=============================================================================
		}}
		break;
	default:
		LOG_MEDUSA_ERROR("Unknown fetch response from server: messageId = ", m_messageId, ", size = ", plain.size());
		return;
	}
}

void FetchClient::onSyncErrorMessage(boost::uint16_t messageId, Poseidon::Cbpp::StatusCode statusCode, const std::string &reason){
	PROFILE_ME;

	if(statusCode != Msg::ST_OK){
		LOG_MEDUSA_ERROR("Fetch error: messageId = ", messageId, ", statusCode = ", statusCode, ", reason = ", reason);
		forceShutdown();
		return;
	}

	Poseidon::Cbpp::Client::onSyncErrorMessage(messageId, statusCode, reason);
}

bool FetchClient::connect(const boost::shared_ptr<ProxySession> &session, std::string host, unsigned port, bool useSsl, bool keepAlive){
	PROFILE_ME;

	const AUTO(fetchUuid, session->getFetchUuid());
	m_sessions[fetchUuid] = session;
	return sendData(fetchUuid, Msg::CS_FetchConnect(STD_MOVE(host), port, useSsl, keepAlive));
}
bool FetchClient::send(const Poseidon::Uuid &fetchUuid, Poseidon::StreamBuffer data){
	PROFILE_ME;

	if(m_sessions.find(fetchUuid) == m_sessions.end()){
		LOG_MEDUSA_WARNING("Fetch client not connected? fetchUuid = ", fetchUuid);
		return false;
	}
	return sendData(fetchUuid, Msg::CS_FetchSend::ID, STD_MOVE(data));
}
void FetchClient::close(const Poseidon::Uuid &fetchUuid, int cbppErrCode, int sysErrCode, const char *errMsg) NOEXCEPT {
	PROFILE_ME;

	const AUTO(it, m_sessions.find(fetchUuid));
	if(it == m_sessions.end()){
		return;
	}

	const AUTO(session, it->second.lock());
	if(session){
		try {
			session->onFetchClosed(cbppErrCode, sysErrCode, errMsg);
			session->shutdownRead();
			session->shutdownWrite();
		} catch(std::exception &e){
			LOG_MEDUSA_ERROR("std::exception thrown: what = ", e.what());
			session->forceShutdown();
		}
	}
	try {
		sendData(fetchUuid, Msg::CS_FetchClose(sysErrCode));
	} catch(std::exception &e){
		LOG_MEDUSA_ERROR("std::exception thrown: what = ", e.what());
		forceShutdown();
	}
	m_sessions.erase(it);
}
void FetchClient::clear(int cbppErrCode, int sysErrCode, const char *errMsg) NOEXCEPT {
	PROFILE_ME;

	for(AUTO(it, m_sessions.begin()); it != m_sessions.end(); ++it){
		const AUTO(session, it->second.lock());
		if(session){
			try {
				session->onFetchClosed(cbppErrCode, sysErrCode, errMsg);
				session->shutdownRead();
				session->shutdownWrite();
			} catch(std::exception &e){
				LOG_MEDUSA_ERROR("std::exception thrown: what = ", e.what());
				session->forceShutdown();
			}
		}

		try {
			sendData(it->first, Msg::CS_FetchClose(sysErrCode));
		} catch(std::exception &e){
			LOG_MEDUSA_ERROR("std::exception thrown: what = ", e.what());
			forceShutdown();
		}
	}
	m_sessions.clear();
}

}
