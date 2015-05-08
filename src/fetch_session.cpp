#include "precompiled.hpp"
#include "fetch_session.hpp"
#include <poseidon/hash.hpp>
#include <poseidon/job_base.hpp>
#include <poseidon/tcp_client_base.hpp>
#include "singletons/dns_daemon.hpp"
#include "msg/fetch.hpp"
#include "msg/error_codes.hpp"
#include "encryption.hpp"

namespace Medusa {
/*
struct FetchSession::ClientContext {
	std::string host;
	unsigned port;
	boost::uint64_t opaque;

	ClientContext(std::string host_, unsigned port_, boost::uint64_t opaque_)
		: host(STD_MOVE(host_)), port(port_), opaque(opaque_)
	{
	}

	bool operator<(const ClientContext &rhs) const {
		int cmp = host.compare(rhs.host);
		if(cmp != 0){
			return cmp < 0;
		}
		if(port != rhs.port){
			return port < rhs.port;
		}
		return opaque < rhs.opaque;
	}
};

struct FetchSession::ClientControl {
};


class FetchSession::FetchClient : public Poseidon::TcpClientBase {
public:
	static boost::shared_ptr<FetchClient> create(boost::weak_ptr<FetchSession> parent, ClientContext context, bool useSsl){
		boost::shared_ptr<FetchClient> ret(new FetchClient(STD_MOVE(parent), STD_MOVE(context), useSsl));
		ret->goResident();
		return ret;
	}

private:
	const boost::weak_ptr<FetchSession> m_parent;
	const ClientContext m_context;
	const bool m_useSsl;

private:
	FetchClient(boost::weak_ptr<FetchSession> parent, ClientContext context, bool useSsl);
		: Poseidon::TcpClientBase(Poseidon::IpPort(SharedNts(context.host), context.port)
		boost::weak_ptr<FetchSession> parent, ClientContext context, bool useSsl)
		: Poseidon::TcpClientBase(Poseidon::IpPort(SharedNts(context.host, useSsl)
	 boost::uint64_t context,
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
			} else {
				LOG_MEDUSA_DEBUG("Context not found. Assuming the remote host has closed the connection.");
			}
		} catch(std::exception &e){
			LOG_MEDUSA_ERROR("std::exception thrown: what = ", e.what());
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
			LOG_MEDUSA_ERROR("std::exception thrown: what = ", e.what());
			parent->forceShutdown();
			forceShutdown();
		}
	}
};

FetchSession::FetchSession(Poseidon::UniqueFile socket, std::string password)
	: Poseidon::Cbpp::Session(STD_MOVE(socket))
	, m_password(STD_MOVE(password))
{
}
FetchSession::~FetchSession(){
	shutdownAllClients(true);
}

void FetchSession::shutdownAllClients(bool force) NOEXCEPT {
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

	LOG_MEDUSA_INFO("Fetch session closed: errCode = ", errCode);
	shutdownAllClients(errCode != 0);

	Poseidon::Cbpp::Session::onClose(errCode);
}

void FetchSession::onLowLevelRequest(boost::uint16_t messageId, Poseidon::StreamBuffer payload){
	PROFILE_ME;

	Msg::GN_FetchEncryptedMessage req(payload);
	const AUTO(prefix, encrypt(req.challenge, m_password, req.nonce));
	if((req.data.size() < prefix.size()) || (prefix.compare(req.data, 0, prefix.size()) != 0)){
		LOG_MEDUSA_DEBUG("Encrypted challenge mismatch. Maybe your password is incorrect?");
		DEBUG_THROW(Poseidon::Cbpp::Exception, Poseidon::Cbpp::ST_FORBIDDEN));
	}
	const AUTO(decryptedSize, req.data.size() - prefix.size());
	LOG_MEDUSA_DEBUG("Decrypted data: decryptedSize = ", decryptedSize, ", remote = ", getRemoteInfo());
	AUTO(decryptedPayload, 

	Poseidon::Cbpp::Session::onLowLevelRequest(messageId, Poseidon::StreamBuffer(req.data

}
void FetchSession::onLowLevelControl(Poseidon::Cbpp::ControlCode controlCode, Poseidon::Cbpp::StatusCode statusCode, std::string reason){
	PROFILE_ME;

}

void FetchSession::onRequest(boost::uint16_t messageId, const Poseidon::StreamBuffer &payload){
	PROFILE_ME;

}
void FetchSession::onControl(Poseidon::Cbpp::ControlCode controlCode, Poseidon::Cbpp::StatusCode statusCode, const std::string &reason){
	PROFILE_ME;

}

bool FetchSession::send(boost::uint16_t messageId, Poseidon::StreamBuffer payload){
	PROFILE_ME;

}



std::string FetchSession::encryptClientContext(const FetchSession::ClientContext &context, const std::string &nonce) const {
	PROFILE_ME;

	boost::uint16_t temp16;
	boost::uint64_t temp64;

	std::string tempStr;
	tempStr.reserve(256);
	temp64 = Poseidon::rand64();
	tempStr.append(reinterpret_cast<const char *>(&temp64), 8);	//  0 8 随机
	Poseidon::storeBe(temp16, context.port);
	tempStr.append(reinterpret_cast<const char *>(&temp16), 2);	//  8 2 端口
	Poseidon::storeBe(temp64, context.opaque);
	tempStr.append(reinterpret_cast<const char *>(&temp64), 8);	// 10 8 客户端上下文
	tempStr.append(context.host);								// 18 - 主机名
	return encrypt(STD_MOVE(tempStr), m_password, nonce);
}
FetchSession::ClientContext FetchSession::decryptClientContext(std::string str, const std::string &nonce) const {
	PROFILE_ME;

	AUTO(tempStr, decrypt(STD_MOVE(str), m_password, nonce));
	if(tempStr.size() < 18){
		DEBUG_THROW(Exception, SSLIT("Client context too small"));
	}

	boost::uint16_t temp16;
	boost::uint64_t temp64;

	ClientContext ret;
	tempStr.copy(reinterpret_cast<char *>(&temp16), 2, 8);	//  8 2 端口
	ret.port = Poseidon::loadBe(temp16);
	tempStr.copy(reinterpret_cast<char *>(&temp64), 8, 10);	// 10 8 客户端上下文
	ret.opaque = Poseidon::loadBe(temp64);
	tempStr.erase(0, 18);
	ret.host = STD_MOVE(tempStr);							// 18 - 主机名
	return ret;
}

void FetchSession::onDecryptedRequest(const FetchSession::ClientContext &context, boost::uint16_t messageId, std::string data){
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
			const AUTO(it, m_clients.find(context));
			if(it == m_clients.end()){
				// 建立新连接。
				client = FetchClient::create(virtualWeakFromThis<FetchSession>(), context, req.useSsl);
				try {
					m_clients.insert(std::make_pair(context, client));
				} catch(...){
					client->forceShutdown();
					throw;
				}
			} else {
				// 已经有连接了。
				client = it->second.lock();
			}
		}
		if(!client){
			LOG_MEDUSA_DEBUG("Connection lost: host:port = ", context.host, ':', context.port);
			send(context, Msg::SC_FetchFailure(Msg::ERR_FETCH_CONNECTION_LOST, -1, VAL_INIT));
			break;
		}
		client->send(Poseidon::StreamBuffer(req.contents));
	}
//=============================================================================
		}}
		break;
	default:
		LOG_MEDUSA_INFO("Unknown message: messageId = ", messageId);
		DEBUG_THROW(Poseidon::Cbpp::Exception, Msg::ST_NOT_FOUND);
	}
}

void FetchSession::onClose(int errCode) NOEXCEPT {
	PROFILE_ME;
	LOG_MEDUSA_INFO("Fetch session closed: errCode = ", errCode);

	{
		const Poseidon::Mutex::UniqueLock lock(m_clientMutex);
		unlockedShutdownAllClients(errCode != 0);
	}

	Poseidon::Cbpp::Session::onClose(errCode);
}

void FetchSession::onLowLevelRequest(boost::uint16_t messageId, Poseidon::StreamBuffer payload){
	PROFILE_ME;

	Msg::GN_FetchEncryptedMessage req(payload);
	const AUTO(prefix, encrypt(req.challenge, m_password, req.nonce));
	if((req.data.size() < prefix.size()) || (prefix.compare(req.data, 0, prefix.size()) != 0)){
		LOG_MEDUSA_DEBUG("Encrypted challenge mismatch. Maybe your password is incorrect?");
		DEBUG_THROW(Poseidon::Cbpp::Exception, Poseidon::Cbpp::ST_FORBIDDEN));
	}
	const AUTO(decryptedSize, req.data.size() - prefix.size());
	LOG_MEDUSA_DEBUG("Decrypted data: decryptedSize = ", decryptedSize, ", remote = ", getRemoteInfo());
	AUTO(decryptedPayload, 

	Poseidon::Cbpp::Session::onLowLevelRequest(messageId, Poseidon::StreamBuffer(req.data
}
void FetchSession::onLowLevelControl(Poseidon::Cbpp::ControlCode controlCode, Poseidon::Cbpp::StatusCode statusCode, std::string reason){
}

void FetchSession::onRequest(boost::uint16_t messageId, const StreamBuffer &payload){
}
void FetchSession::onControl(Poseidon::Cbpp::ControlCode controlCode, Poseidon::Cbpp::StatusCode statusCode, const std::string &reason){
}

void FetchSession::onLowLevelRequest(boost::uint16_t messageId, Poseidon::StreamBuffer payload){
	PROFILE_ME;

}
void FetchSession::onLowLevelControl(Poseidon::Cbpp::ControlCode controlCode,
	Poseidon::Cbpp::StatusCode statusCode, std::string reason)
{
	PROFILE_ME;

}

void FetchSession::onLowLevelError(unsigned messageId, Poseidon::Cbpp::StatusCode statusCode, const char *reason){
	PROFILE_ME;
	LOG_MEDUSA_DEBUG("Fetch session error: messageId = ", messageId, ", statusCode = ", statusCode, ", reason = ", reason);

	Poseidon::Cbpp::LowLevelSession::sendControl(messageId, statusCode, std::string(reason));
	Poseidon::Cbpp::LowLevelSession::shutdownRead();
	Poseidon::Cbpp::LowLevelSession::shutdownWrite();
}

void FetchSession::onLowLevelRequest(boost::uint16_t messageId, const Poseidon::StreamBuffer &payload){
	PROFILE_ME;

	Msg::GN_FetchEncryptedMessage encryptedReq(payload);
	AUTO(data, decrypt(STD_MOVE(encryptedReq.data), m_password, encryptedReq.nonce));
	if(Poseidon::crc32Sum(data.data(), data.size()) != encryptedReq.dataCrc32){
		LOG_MEDUSA_DEBUG("Data CRC32 mismatch. Maybe your password is wrong?");
		DEBUG_THROW(Poseidon::Cbpp::Exception, Msg::ERR_CRC32_MISMATCH);
	}
	const AUTO(context, decryptClientContext(STD_MOVE(encryptedReq.context), encryptedReq.nonce));
	LOG_MEDUSA_DEBUG("Received fetch request: host:port = ", context.host, ':', context.port);
	onDecryptedRequest(context, messageId, STD_MOVE(data));
}

bool FetchSession::send(const ClientContext &context, boost::uint16_t messageId, std::string data){
	PROFILE_ME;

	Msg::GN_FetchEncryptedMessage encryptedMsg;
	encryptedMsg.nonce = generateNonce();
	encryptedMsg.context = encryptClientContext(context, encryptedMsg.nonce);
	encryptedMsg.dataCrc32 = Poseidon::crc32Sum(data.data(), data.size());
	encryptedMsg.data = encrypt(STD_MOVE(data), m_password, encryptedMsg.nonce);
	return Poseidon::Cbpp::LowLevelSession::send(messageId, Poseidon::StreamBuffer(encryptedMsg));
}


void FetchSession::shutdownAllClients(bool force) NOEXCEPT {
	PROFILE_ME;

	const Poseidon::Mutex::UniqueLock lock(m_clientMutex);
	while(!m_clients.empty()){
		const AUTO(client, m_clients.begin()->second.lock());
		if(client){
			if(force){
				client->forceShutdown();
			} else {
				client->shutdownRead();
				client->shutdownWrite();
			}
		}
		m_clients.erase(m_clients.begin());
	}
}

void FetchSession::onLowLevelPlainMessage(boost::uint16_t messageId, Poseidon::StreamBuffer plain){
	PROFILE_ME;

	{
		const Poseidon::Mutex::UniqueLock lock(m_clientMutex);
	}
	// TODO
}

void FetchSession::onClose(int errCode) NOEXCEPT {
	shutdownAllClients(errCode != 0);
}

void FetchSession::onLowLevelRequest(boost::uint16_t messageId, Poseidon::StreamBuffer payload){
	PROFILE_ME;

	Msg::G_FetchEncryptedHeader header;
	// TODO
}
void FetchSession::onLowLevelControl(Poseidon::Cbpp::ControlCode controlCode, boost::int64_t intParam, std::string strParam){
	PROFILE_ME;

	if(controlCode == Poseidon::Cbpp::CTL_HEARTBEAT){
		return;
	}

	sendError(controlCode, intParam, STD_MOVE(strParam));
}

void FetchSession::onLowLevelError(unsigned messageId, Poseidon::Cbpp::StatusCode statusCode, const char *reason){
	PROFILE_ME;

	sendError(messageId, statusCode, std::string(reason));
}

bool FetchSession::send(boost::uint16_t messageId, Poseidon::StreamBuffer plain){
	PROFILE_ME;

	Msg::G_FetchEncryptedMessage msg;
	msg.nonce = generateRandomBytes();
	msg.

	Poseidon::StreamBuffer payload;


	// TODO

	std::string nonce = generateRandomBytes();
	AUTO(noncedPassword, nonce + m_password);
	std::string hash(32);
	Poseidon::sha256Sum(reinterpret_cast<unsigned char (*)[32]>(hash.data())[0], noncedPassword.data(), noncedPassword.size());

	Msg::G_FetchEncryptedHeader header(STD;
	heaeder.nonce = STD_MOVE(nonce);
	header.noncedPasswordSha256.assign(reinterpret_cast<const char *>(sha256), sizeof(sha256));
	header >>payload;

	Poseidon::StreamBuffer plain;
	plain.put(header.challenge);
	plain.splice(payload);
	AUTO(encrypted, encrypt(STD_MOVE(plain), m_password, header.nonce));
	payload.splice(encrypted);

	return Poseidon::Cbpp::LowLevelSession::send(messageId, STD_MOVE(payload));
}

bool FetchSession::sendError(boost::uint16_t messageId, Poseidon::Cbpp::StatusCode statusCode, std::string reason){
	PROFILE_ME;

	const bool ret = Poseidon::Cbpp::LowLevelSession::sendError(messageId, statusCode, STD_MOVE(reason));
	Poseidon::Cbpp::LowLevelSession::shutdownRead();
	Poseidon::Cbpp::LowLevelSession::shutdownWrite();
	return ret;
}
*/

}
