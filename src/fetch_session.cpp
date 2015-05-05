#include "precompiled.hpp"
#include "fetch_session.hpp"
#include <poseidon/hash.hpp>
#include <poseidon/job_base.hpp>
#include <poseidon/tcp_client_base.hpp>
#include "singletons/dns_cache.hpp"
#include "msg/fetch_protocol.hpp"
#include "msg/error_codes.hpp"
#include "encryption.hpp"

namespace Medusa {

class FetchSession::FetchClient : public Poseidon::TcpClientBase {
public:
	static boost::shared_ptr<FetchClient> create(boost::weak_ptr<FetchSession> parent, boost::uint64_t context,
		const Poseidon::IpPort &addr, bool useSsl)
	{
		boost::shared_ptr<FetchClient> ret(new FetchClient(STD_MOVE(parent), context, addr, useSsl));
		ret->goResident();
		return ret;
	}

private:
	const boost::weak_ptr<FetchSession> m_parent;
	const boost::uint64_t m_context;

private:
	FetchClient(boost::weak_ptr<FetchSession> parent, boost::uint64_t context,
		const Poseidon::IpPort &addr, bool useSsl)
		: Poseidon::TcpClientBase(addr, useSsl)
		, m_parent(STD_MOVE(parent)), m_context(context)
	{
	}

protected:
	void onClose(int errCode) NOEXCEPT OVERRIDE {
		PROFILE_ME;

		const AUTO(parent, m_parent.lock());
		if(!parent){
			return;
		}

		try {
			bool erased;
			{
				const Poseidon::Mutex::UniqueLock lock(parent->m_clientMutex);
				erased = parent->m_clients.erase(m_context) > 0;
			}
			if(erased){
				parent->send(m_context, Msg::SC_FetchFailure(Msg::ERR_FETCH_CONNECTION_CLOSED, errCode, VAL_INIT));
			}
		} catch(std::exception &e){
			LOG_MEDUSA_DEBUG("std::exception thrown: what = ", e.what());
			parent->forceShutdown();
		}
	}

	void onReadAvail(const void *data, std::size_t size) OVERRIDE {
		PROFILE_ME;

		const AUTO(parent, m_parent.lock());
		if(!parent){
			LOG_MEDUSA_DEBUG("Parent session has expired");
			forceShutdown();
			return;
		}

		try {
			bool found;
			{
				const Poseidon::Mutex::UniqueLock lock(parent->m_clientMutex);
				found = parent->m_clients.find(m_context) != parent->m_clients.end();
			}
			if(found){
				parent->send(m_context, Msg::SC_FetchSuccess(std::string(static_cast<const char *>(data), size)));
			} else {
				LOG_MEDUSA_DEBUG("Context not found. Assuming the remote host has closed the connection.");
				forceShutdown();
			}
		} catch(std::exception &e){
			LOG_MEDUSA_DEBUG("std::exception thrown: what = ", e.what());
			parent->forceShutdown();
			forceShutdown();
		}
	}
};
/*
class FetchSession::FetchJob : public Poseidon::JobBase {
private:
	const boost::weak_ptr<FetchSession> m_session;
	const Msg::FetchRequest m_request;

public:
	FetchJob(boost::weak_ptr<FetchSession> session, Msg::FetchRequest request)
		: m_session(STD_MOVE(session)), m_request(STD_MOVE(request))
	{
	}

protected:
	boost::weak_ptr<const void> getCategory() const OVERRIDE {
		return m_session;
	}
	void perform() const OVERRIDE {
		PROFILE_ME;

		const AUTO(session, m_session.lock());
		if(!session){
			return;
		}

		try {
			const AUTO(serverIp, DnsCache::lookUp(m_request.host));

			AUTO(client, session->m_client.lock());
			if(!client){
				const boost::weak_ptr<void> NWPTR;
				if(m_request.isTunnel && ((NWPTR < session->m_client) || (session->m_client < NWPTR))){
					LOG_MEDUSA_INFO("Tunnel connection lost");
					DEBUG_THROW(Exception, SSLIT("Tunnel connection lost"));
				}
				client = FetchClient::create(session, Poseidon::IpPort(serverIp, m_request.port), m_request.useSsl);
			}
			client->send(Poseidon::StreamBuffer(m_request.body));
		} catch(Poseidon::JobBase::TryAgainLater &){
			throw Poseidon::JobBase::TryAgainLater(session);
		} catch(std::exception &e){
			LOG_MEDUSA_WARNING("std::exception thrown while dispatching fetch job: what = ", e.what());
			session->forceShutdown();
			throw;
		}
	}
};
*/
FetchSession::FetchSession(Poseidon::UniqueFile socket, std::string password)
	: Poseidon::Cbpp::Session(STD_MOVE(socket))
	, m_password(STD_MOVE(password))
{
}
FetchSession::~FetchSession(){
	unlockedShutdownAllClients(true);
}

void FetchSession::unlockedShutdownAllClients(bool force) NOEXCEPT {
	PROFILE_ME;

	for(AUTO(it, m_clients.begin()); it != m_clients.end(); ++it){
		const AUTO(client, it->second.lock());
		if(!client){
			continue;
		}
		if(force){
			client->forceShutdown();
		} else {
			client->shutdownRead();
			client->shutdownWrite();
		}
	}
	m_clients.clear();
}

void FetchSession::onClose(int errCode) NOEXCEPT {
	PROFILE_ME;

	{
		const Poseidon::Mutex::UniqueLock lock(m_clientMutex);
		unlockedShutdownAllClients(errCode != 0);
	}

	Poseidon::Cbpp::Session::onClose(errCode);
}

void FetchSession::onDecryptedRequest(boost::uint64_t context, boost::uint16_t messageId, std::string data){
	PROFILE_ME;

	switch(messageId){
		{{
#define ON_MESSAGE(MsgType_, msg_)	\
		}}	\
		break;	\
	case MsgType_::ID: {	\
		AUTO(msg_, MsgType_(::Poseidon::StreamBuffer(data)));	\
		{
//=============================================================================
	ON_MESSAGE(Msg::CS_FetchRequest, req){
		boost::shared_ptr<FetchClient> client;
		{
			const Poseidon::Mutex::UniqueLock lock(m_clientMutex);
			AUTO(result, m_clients.insert(std::make_pair(context, boost::weak_ptr<FetchClient>())));
			if(result.second){
				// 建立新连接。
				client = FetchClient::create(virtualWeakFromThis<FetchSession>(), context,
					Poseidon::IpPort(SharedNts(req.host), req.port), req.useSsl);
				result.first->second = client;
			} else {
				// 已经有连接了。
				client = result.first->second.lock();
			}
		}
		if(!client){
			LOG_MEDUSA_DEBUG("Connection lost: context = ", context);
			send(context, Msg::SC_FetchFailure(Msg::ERR_FETCH_CONNECTION_LOST, -1, VAL_INIT));
			break;
		}
		client->send(Poseidon::StreamBuffer(req.contents));
	}
//=============================================================================
		}}
		break;
	default:
		LOG_MEDUSA_DEBUG("Unknown message: messageId = ", messageId);
		DEBUG_THROW(Exception, SSLIT("Unknown message"));
	}
}

void FetchSession::onRequest(boost::uint16_t messageId, const Poseidon::StreamBuffer &payload){
	PROFILE_ME;

	Msg::GN_FetchEncryptedMessage encryptedReq(payload);
	AUTO(data, decrypt(STD_MOVE(encryptedReq.data), m_password, encryptedReq.nonce));
	if(Poseidon::crc32Sum(data.data(), data.size()) != encryptedReq.crc32){
		LOG_MEDUSA_DEBUG("CRC32 mismatch");
		DEBUG_THROW(Exception, SSLIT("CRC32 mismatch"));
	}
	onDecryptedRequest(encryptedReq.context, messageId, STD_MOVE(data));
}

bool FetchSession::send(boost::uint64_t context, boost::uint16_t messageId, std::string data){
	PROFILE_ME;

	Msg::GN_FetchEncryptedMessage encryptedMsg;
	encryptedMsg.context = context;
	encryptedMsg.nonce = generateNonce();
	encryptedMsg.crc32 = Poseidon::crc32Sum(data.data(), data.size());
	encryptedMsg.data = encrypt(STD_MOVE(data), m_password, encryptedMsg.nonce);
	return Poseidon::Cbpp::Session::send(messageId, Poseidon::StreamBuffer(encryptedMsg));
}

}
