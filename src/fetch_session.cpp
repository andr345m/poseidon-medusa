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
	static boost::shared_ptr<FetchClient> create(boost::weak_ptr<FetchSession> parent,
		const Poseidon::IpPort &addr, bool useSsl)
	{
		boost::shared_ptr<FetchClient> ret(new FetchClient(STD_MOVE(parent), addr, useSsl));
		ret->goResident();
		return ret;
	}

private:
	const boost::weak_ptr<FetchSession> m_parent;

private:
	FetchClient(boost::weak_ptr<FetchSession> parent, const Poseidon::IpPort &addr, bool useSsl)
		: Poseidon::TcpClientBase(addr, useSsl)
		, m_parent(STD_MOVE(parent))
	{
	}

protected:
	void onReadHup() NOEXCEPT OVERRIDE {
		const AUTO(parent, m_parent.lock());
		if(!parent){
			return;
		}
		parent->shutdownWrite();
	}
	void onWriteHup() NOEXCEPT OVERRIDE {
		const AUTO(parent, m_parent.lock());
		if(!parent){
			return;
		}
		parent->shutdownRead();
	}
	void onClose() NOEXCEPT OVERRIDE {
		const AUTO(parent, m_parent.lock());
		if(!parent){
			return;
		}
		parent->forceShutdown();
	}

	void onReadAvail(const void *data, std::size_t size) OVERRIDE {
		PROFILE_ME;

		const AUTO(parent, m_parent.lock());
		if(!parent){
			LOG_MEDUSA_DEBUG("Parent session has expired");
			forceShutdown();
			return;
		}

		parent->send(Poseidon::StreamBuffer(data, size));
	}
};

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

FetchSession::FetchSession(Poseidon::UniqueFile socket, std::string password)
	: Poseidon::Cbpp::Session(STD_MOVE(socket))
	, m_password(STD_MOVE(password))
{
}
FetchSession::~FetchSession(){
}

void FetchSession::onRequest(boost::uint16_t messageId, const Poseidon::StreamBuffer &payload){
	PROFILE_ME;

	try {
		if(messageId != Msg::FetchEncryptedMessage::ID){
			LOG_MEDUSA_DEBUG("Unexpected message: messageId = ", messageId);
			DEBUG_THROW(Poseidon::Cbpp::Exception, Msg::ST_NOT_FOUND);
		}

		Msg::FetchEncryptedMessage encrypted(payload);
		AUTO(decryptedData, decrypt(STD_MOVE(encrypted.data),  m_password, encrypted.nonce));
		const AUTO(crc32, Poseidon::crc32Sum(decryptedData.data(), decryptedData.size()));
		if(crc32 != encrypted.crc32){
			LOG_MEDUSA_DEBUG("CRC32 mismatch");
			DEBUG_THROW(Poseidon::Cbpp::Exception, Msg::ERR_FETCH_CRC_MISMATCH);
		}
		Poseidon::enqueueJob(boost::make_shared<FetchJob>(
			virtualSharedFromThis<FetchSession>(), Msg::FetchRequest(Poseidon::StreamBuffer(decryptedData))));
	} catch(Poseidon::Cbpp::Exception &e){
		LOG_MEDUSA_INFO("Cbpp::Exception thrown: statusCode = ", e.statusCode(), ", what = ", e.what());
		Poseidon::Cbpp::Session::sendControl(messageId, e.statusCode(), e.what());
		shutdownRead();
		shutdownWrite();
	}
}
bool FetchSession::send(Poseidon::StreamBuffer payload){
	PROFILE_ME;

	AUTO(decryptedData, payload.dump());

	Msg::FetchEncryptedMessage encrypted;
	encrypted.nonce = generateNonce();
	encrypted.crc32 = Poseidon::crc32Sum(decryptedData.data(), decryptedData.size());
	encrypted.data = encrypt(STD_MOVE(decryptedData), m_password, encrypted.nonce);
	return Poseidon::Cbpp::Session::send(encrypted);
}

}
