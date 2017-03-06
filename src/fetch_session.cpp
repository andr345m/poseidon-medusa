#include "precompiled.hpp"
#include "fetch_session.hpp"
#include <poseidon/singletons/timer_daemon.hpp>
#include <poseidon/singletons/job_dispatcher.hpp>
#include <poseidon/singletons/dns_daemon.hpp>
#include <poseidon/job_base.hpp>
#include <poseidon/job_promise.hpp>
#include <poseidon/sock_addr.hpp>
#include <poseidon/tcp_client_base.hpp>
#include <poseidon/cbpp/message_base.hpp>
#include "encryption.hpp"
#include "msg/cs_fetch.hpp"
#include "msg/sc_fetch.hpp"
#include "msg/error_codes.hpp"

namespace Medusa {

class FetchSession::Channel {
private:
	struct ConnectElement {
		std::string host;
		unsigned port;
		bool use_ssl;
		boost::uint64_t flags;

		bool connected;
		Poseidon::StreamBuffer pending;

		ConnectElement(std::string host_, unsigned port_, bool use_ssl_, boost::uint64_t flags_)
			: host(STD_MOVE(host_)), port(port_), use_ssl(use_ssl_), flags(flags_)
			, connected(false)
		{
		}
	};

	typedef std::map<Poseidon::Uuid, boost::shared_ptr<Channel> >::iterator ChannelIterator;

	class ClientSyncJobBase : public Poseidon::JobBase {
	private:
		const boost::weak_ptr<Poseidon::TcpSessionBase> m_category;
		const boost::weak_ptr<FetchSession> m_session;
		const Poseidon::Uuid m_fetch_uuid;

	public:
		ClientSyncJobBase(const boost::shared_ptr<FetchSession> &session, const Poseidon::Uuid &fetch_uuid)
			: m_category(session), m_session(session), m_fetch_uuid(fetch_uuid)
		{
		}

	private:
		boost::weak_ptr<const void> get_category() const FINAL {
			return m_category;
		}
		void perform() FINAL {
			PROFILE_ME;

			const AUTO(session, m_session.lock());
			if(!session){
				return;
			}
			const AUTO(it, session->m_channels.find(m_fetch_uuid));
			if(it == session->m_channels.end()){
				return;
			}

			try {
				really_perform(session, it);
			} catch(std::exception &e){
				LOG_MEDUSA_ERROR("std::exception thrown: what = ", e.what());
				session->shutdown(Msg::ST_INTERNAL_ERROR, e.what());
			}
		}

	protected:
		virtual void really_perform(const boost::shared_ptr<FetchSession> &session, ChannelIterator it) = 0;
	};

	class ClientConnectJob : public ClientSyncJobBase {
	public:
		ClientConnectJob(const boost::shared_ptr<FetchSession> &session, const Poseidon::Uuid &fetch_uuid)
			: ClientSyncJobBase(session, fetch_uuid)
		{
		}

	protected:
		void really_perform(const boost::shared_ptr<FetchSession> &session, ChannelIterator it) OVERRIDE {
			PROFILE_ME;
			LOG_MEDUSA_DEBUG("Remote client connected: fetch_uuid = ", it->first);

			const AUTO(channel, it->second);
			assert(!channel->m_connect_queue.empty());
			AUTO_REF(elem, channel->m_connect_queue.front());

			elem.connected = true;
			if(!elem.pending.empty()){
				const AUTO(client, channel->m_client.lock());
				if(client){
					client->send(STD_MOVE(elem.pending));
				}
				elem.pending.clear();
			}

			session->send(it->first, Msg::SC_FetchConnected(elem.flags));
		}
	};

	class ClientCloseJob : public ClientSyncJobBase {
	private:
		int m_err_code;

	public:
		ClientCloseJob(const boost::shared_ptr<FetchSession> &session, const Poseidon::Uuid &fetch_uuid, int err_code)
			: ClientSyncJobBase(session, fetch_uuid)
			, m_err_code(err_code)
		{
		}

	protected:
		void really_perform(const boost::shared_ptr<FetchSession> &session, ChannelIterator it) OVERRIDE {
			PROFILE_ME;
			LOG_MEDUSA_DEBUG("Remote client closed: fetch_uuid = ", it->first, ", err_code = ", m_err_code);

			const AUTO(channel, it->second);
			assert(!channel->m_connect_queue.empty());
			AUTO_REF(elem, channel->m_connect_queue.front());

			if(m_err_code != 0){
				try {
					Poseidon::Buffer_ostream os;
					if(elem.connected){
						os <<"Lost connection to remote server";
					} else {
						os <<"Could not connect to remote server";
					}
					os <<": errno was " <<m_err_code <<": " <<Poseidon::get_error_desc(m_err_code);
					session->send(it->first, Msg::SC_FetchClosed(Msg::ERR_CONNECTION_LOST, m_err_code, os.get_buffer().dump_string()));
				} catch(std::exception &e){
					LOG_MEDUSA_ERROR("std::exception thrown: what = ", e.what());
				}
				session->m_channels.erase(it);
				return;
			}

			session->send(it->first, Msg::SC_FetchEnded());

			if(Poseidon::has_any_flags_of(elem.flags, FL_KEEP_ALIVE)){
				channel->m_connect_queue.pop_front();
				if(!channel->m_connect_queue.empty()){
					channel->create_client();
				}
			} else {
				session->send(it->first, Msg::SC_FetchClosed(Msg::ST_OK, 0, "Connection is not persistent"));
				session->m_channels.erase(it);
			}
		}
	};

	class ClientReadAvailJob : public ClientSyncJobBase {
	private:
		Poseidon::StreamBuffer m_data;

	public:
		ClientReadAvailJob(const boost::shared_ptr<FetchSession> &session, const Poseidon::Uuid &fetch_uuid, Poseidon::StreamBuffer data)
			: ClientSyncJobBase(session, fetch_uuid)
			, m_data(STD_MOVE(data))
		{
		}

	protected:
		void really_perform(const boost::shared_ptr<FetchSession> &session, ChannelIterator it) OVERRIDE {
			PROFILE_ME;

			const AUTO(size, m_data.size());
			LOG_MEDUSA_DEBUG("Remote client read avail: fetch_uuid = ", it->first, ", size = ", size);

			const AUTO(channel, it->second);

			session->send_explicit(it->first, Msg::SC_FetchReceived::ID, STD_MOVE(m_data));
			channel->m_updated_time = Poseidon::get_fast_mono_clock();

			channel->throttle_consume(size);
		}
	};

	class Client : public Poseidon::TcpClientBase {
		friend Channel;

	private:
		const boost::weak_ptr<FetchSession> m_session;
		const Poseidon::Uuid m_fetch_uuid;

	public:
		Client(const Poseidon::SockAddr &addr, bool use_ssl,
			const boost::shared_ptr<FetchSession> &session, const Poseidon::Uuid &fetch_uuid)
			: Poseidon::TcpClientBase(addr, use_ssl)
			, m_session(session), m_fetch_uuid(fetch_uuid)
		{
			LOG_MEDUSA_DEBUG("Constructor of remote client: remote = ", Poseidon::get_ip_port_from_sock_addr(addr));
		}
		~Client(){
			LOG_MEDUSA_DEBUG("Destructor of remote client: remote = ", get_remote_info_nothrow());
		}

	protected:
		void on_connect() OVERRIDE {
			PROFILE_ME;

			const AUTO(session, m_session.lock());
			if(session){
				Poseidon::JobDispatcher::enqueue(
					boost::make_shared<ClientConnectJob>(
						session, m_fetch_uuid),
					VAL_INIT);
			}

			Poseidon::TcpClientBase::on_connect();
		}
		void on_read_hup() NOEXCEPT OVERRIDE {
			PROFILE_ME;

			shutdown_write();

			Poseidon::TcpClientBase::on_read_hup();
		}
		void on_close(int err_code) NOEXCEPT OVERRIDE {
			PROFILE_ME;

			const AUTO(session, m_session.lock());
			if(session){
				try {
					Poseidon::JobDispatcher::enqueue(
						boost::make_shared<ClientCloseJob>(
							session, m_fetch_uuid, err_code),
						VAL_INIT);
				} catch(std::exception &e){
					LOG_MEDUSA_ERROR("std::exception thrown: what = ", e.what());
					session->force_shutdown();
				}
			}

			Poseidon::TcpClientBase::on_close(err_code);
		}

		void on_read_avail(Poseidon::StreamBuffer data) OVERRIDE {
			PROFILE_ME;

			const AUTO(session, m_session.lock());
			if(!session){
				LOG_MEDUSA_DEBUG("Lost connection to remote client: fetch_uuid = ", m_fetch_uuid);
				force_shutdown();
				return;
			}

			try {
				Poseidon::JobDispatcher::enqueue(
					boost::make_shared<ClientReadAvailJob>(
						session, m_fetch_uuid, STD_MOVE(data)),
					VAL_INIT);
				set_timeout(0);
			} catch(std::exception &e){
				LOG_MEDUSA_ERROR("std::exception thrown: what = ", e.what());
				force_shutdown();
				session->force_shutdown();
			}
		}

	public:
		void go_resident(){
			PROFILE_ME;

			const AUTO(connect_timeout, get_config<boost::uint64_t>("remote_client_connect_timeout", 10000));
			Poseidon::TcpClientBase::set_timeout(connect_timeout);

			Poseidon::TcpClientBase::go_resident();
		}
	};

private:
	const boost::weak_ptr<FetchSession> m_session;
	const Poseidon::Uuid m_fetch_uuid;

	std::deque<ConnectElement> m_connect_queue;
	boost::weak_ptr<Client> m_client;
	boost::uint64_t m_updated_time;
	boost::uint64_t m_throttle_threshold;

public:
	Channel(const boost::shared_ptr<FetchSession> &session, const Poseidon::Uuid &fetch_uuid)
		: m_session(session), m_fetch_uuid(fetch_uuid)
		, m_updated_time(Poseidon::get_fast_mono_clock())
		, m_throttle_threshold(get_config<boost::uint64_t>("fetch_max_single_pipeline_size", 65536))
	{
	}
	~Channel(){
		kill_client(true);
	}

private:
	void create_client(){
		PROFILE_ME;

		assert(!m_connect_queue.empty());

		const AUTO_REF(elem, m_connect_queue.front());
		LOG_MEDUSA_DEBUG("Next fetch request: host:port = ", elem.host, ':', elem.port,
			", use_ssl = ", elem.use_ssl, ", flags = ", elem.flags);
		try {
			const AUTO(promise, Poseidon::DnsDaemon::enqueue_for_looking_up(elem.host, elem.port));
			try {
				Poseidon::JobDispatcher::yield(promise, true);
			} catch(std::exception &e){
				LOG_MEDUSA_DEBUG("DNS failure...");
				const AUTO(session, m_session.lock());
				if(session){
					session->send(m_fetch_uuid, Msg::SC_FetchClosed(Msg::ERR_DNS_FAILURE, -1, e.what()));
					session->m_channels.erase(m_fetch_uuid);
				}
				return;
			}
			const AUTO_REF(addr, promise->get());
			LOG_MEDUSA_DEBUG("DNS lookup succeeded: fetch_uuid = ", m_fetch_uuid, ", host:port = ", elem.host, ':', elem.port);

			if(addr.is_private()){
				LOG_MEDUSA_DEBUG("Connection to private address requested. Abort.");
				const AUTO(session, m_session.lock());
				if(session){
					session->send(m_fetch_uuid, Msg::SC_FetchClosed(Msg::ERR_ACCESS_DENIED, ECONNREFUSED, "Connection to private address requested"));
					session->m_channels.erase(m_fetch_uuid);
				}
				return;
			}

			const AUTO(session, m_session.lock());
			if(!session){
				return;
			}
			LOG_MEDUSA_DEBUG("Creating remote client...");
			const AUTO(client, boost::make_shared<Client>(addr, elem.use_ssl, session, m_fetch_uuid));
			client->go_resident();
			m_client = client;
			m_updated_time = Poseidon::get_fast_mono_clock();
		} catch(std::exception &e){
			LOG_MEDUSA_ERROR("std::exception thrown: what = ", e.what());
			const AUTO(session, m_session.lock());
			if(session){
				session->force_shutdown();
			}
		}
	}
	void kill_client(bool force){
		PROFILE_ME;

		const AUTO(client, m_client.lock());
		if(client){
			if(force){
				client->force_shutdown();
			} else {
				client->shutdown_read();
				client->shutdown_write();
			}
		}

		m_connect_queue.clear();
		m_client.reset();
	}

public:
	const Poseidon::Uuid &get_fetch_uuid() const {
		return m_fetch_uuid;
	}

	boost::uint64_t get_updated_time() const {
		return m_updated_time;
	}

	void throttle_consume(boost::uint64_t size){
		m_throttle_threshold -= size;

		if(static_cast<boost::int64_t>(m_throttle_threshold) <= 0){
			LOG_MEDUSA_DEBUG("Throttle the client!");
			const AUTO(client, m_client.lock());
			if(client){
				client->set_throttled(true);
			}
		}
	}
	void throttle_produce(boost::uint64_t size){
		m_throttle_threshold += size;

		if(static_cast<boost::int64_t>(m_throttle_threshold) > 0){
			LOG_MEDUSA_DEBUG("Unthrottle the client!");
			const AUTO(client, m_client.lock());
			if(client){
				client->set_throttled(false);
			}
		}
	}

	void connect(std::string host, unsigned port, bool use_ssl, boost::uint64_t flags){
		PROFILE_ME;
		LOG_MEDUSA_INFO("Fetch connect: fetch_uuid = ", m_fetch_uuid,
			", host:port = ", host, ':', port, ", use_ssl = ", use_ssl, ", flags = ", flags);

		const AUTO(max_pipelining_size, get_config<std::size_t>("fetch_max_pipelining_size", 16));
		if(m_connect_queue.size() + 1 > max_pipelining_size){
			LOG_MEDUSA_WARNING("Max pipelining size exceeded: max_pipelining_size = ", max_pipelining_size);
			DEBUG_THROW(Poseidon::Cbpp::Exception, Msg::ERR_MAX_PIPELINING_SIZE);
		}

		m_connect_queue.push_back(ConnectElement(STD_MOVE(host), port, use_ssl, flags));

		if(m_connect_queue.size() == 1){
			create_client();
		}

		m_updated_time = Poseidon::get_fast_mono_clock();
	}
	bool send(Poseidon::StreamBuffer data){
		PROFILE_ME;

		if(m_connect_queue.empty()){
			LOG_MEDUSA_DEBUG("No connection in progress or connection lost: fetch_uuid = ", m_fetch_uuid);
			return false;
		}

		if((m_connect_queue.size() == 1) && m_connect_queue.front().connected){
			const AUTO(client, m_client.lock());
			if(!client){
				return false;
			}
			if(!client->send(STD_MOVE(data))){
				return false;
			}
		} else {
			const AUTO(max_pending_buffer_size, get_config<std::size_t>("fetch_max_pending_buffer_size", 65536));
			std::size_t pending_size = 0;
			for(AUTO(it, m_connect_queue.begin()); it != m_connect_queue.end(); ++it){
				pending_size += it->pending.size();
			}
			if(pending_size + data.size() > max_pending_buffer_size){
				LOG_MEDUSA_WARNING("Max pending buffer size exceeded: max_pending_buffer_size = ", max_pending_buffer_size);
				DEBUG_THROW(Poseidon::Cbpp::Exception, Msg::ERR_MAX_PENDING_BUFFER_SIZE);
			}
			m_connect_queue.back().pending.splice(data);
		}

		m_updated_time = Poseidon::get_fast_mono_clock();
		return true;
	}
	void close(int err_code) NOEXCEPT {
		PROFILE_ME;
		LOG_MEDUSA_INFO("Fetch close: fetch_uuid = ", m_fetch_uuid, ", err_code = ", err_code);

		kill_client(err_code != 0);

		m_updated_time = Poseidon::get_fast_mono_clock();
	}
};

void FetchSession::sync_gc_timer_proc(const boost::weak_ptr<FetchSession> &weak, boost::uint64_t now) NOEXCEPT {
	PROFILE_ME;

	const AUTO(session, weak.lock());
	if(!session){
		return;
	}

	try {
		session->on_sync_gc_timer(now);
	} catch(std::exception &e){
		LOG_MEDUSA_ERROR("std::exception thrown: what = ", e.what());
		session->shutdown(Msg::ST_INTERNAL_ERROR, e.what());
	}
}

FetchSession::FetchSession(Poseidon::UniqueFile socket, std::string password)
	: Poseidon::Cbpp::Session(STD_MOVE(socket))
	, m_password(STD_MOVE(password))
{
	LOG_MEDUSA_DEBUG("Fetch session constructor: remote = ", get_remote_info());
}
FetchSession::~FetchSession(){
	LOG_MEDUSA_DEBUG("Fetch session destructor: remote = ", get_remote_info_nothrow());
}

void FetchSession::on_sync_gc_timer(boost::uint64_t now){
	PROFILE_ME;

	const AUTO(gc_timeout, get_config<boost::uint64_t>("fetch_channel_gc_timeout", 30000));

	for(AUTO(next, m_channels.begin()), it = next; (next != m_channels.end()) && (++next, true); it = next){
		const AUTO(fetch_uuid, it->first);
		const AUTO_REF(channel, it->second);
		if(now < channel->get_updated_time() + gc_timeout){
			continue;
		}
		LOG_MEDUSA_DEBUG("Remote client shutdown due to inactivity: fetch_uuid = ", fetch_uuid);
		m_channels.erase(it);
	}
}

void FetchSession::on_sync_data_message(boost::uint16_t message_id, Poseidon::StreamBuffer payload){
	PROFILE_ME;

	if(!m_gc_timer){
		m_gc_timer = Poseidon::TimerDaemon::register_timer(5000, 5000,
			boost::bind(&sync_gc_timer_proc, virtual_weak_from_this<FetchSession>(), _2));
	}

	const AUTO(header_size, get_encrypted_header_size());
	if(payload.size() < header_size){
		LOG_MEDUSA_WARNING("Frame from remote client is too small, expecting ", header_size);
		DEBUG_THROW(Poseidon::Cbpp::Exception, Msg::ST_END_OF_STREAM);
	}
	const AUTO(context, try_decrypt_header(payload, m_password));
	if(!context){
		LOG_MEDUSA_WARNING("Unexpected checksum. Maybe you provided a wrong password?");
		DEBUG_THROW(Poseidon::Cbpp::Exception, Msg::ST_FORBIDDEN);
	}
	payload.discard(header_size);
	AUTO(plain, decrypt_payload(context, STD_MOVE(payload)));

	const AUTO_REF(fetch_uuid, context->uuid);
	LOG_MEDUSA_DEBUG("Fetch request: fetch_uuid = ", fetch_uuid, ", message_id = ", message_id);
	switch(message_id){
		{{
#define ON_MESSAGE(Msg_, req_)  \
		}}  \
		break;  \
	case Msg_::ID: {    \
		Msg_ (req_)(plain); \
		{ //
#define ON_RAW_MESSAGE(Msg_, req_)  \
		}}  \
		break;  \
	case Msg_::ID: {    \
		::Poseidon::StreamBuffer & (req_) = plain;  \
		{ //
//=============================================================================
	ON_MESSAGE(Msg::CS_FetchConnect, req){
		AUTO(it, m_channels.find(fetch_uuid));
		if(it == m_channels.end()){
			it = m_channels.insert(std::make_pair(fetch_uuid,
				boost::make_shared<Channel>(virtual_shared_from_this<FetchSession>(), fetch_uuid))).first;
		}
		const AUTO(channel, it->second);
		channel->connect(STD_MOVE(req.host), req.port, req.use_ssl, req.flags);
	}
	ON_RAW_MESSAGE(Msg::CS_FetchSend, req){
		const AUTO(it, m_channels.find(fetch_uuid));
		if(it == m_channels.end()){
			send(fetch_uuid, Msg::SC_FetchClosed(Msg::ERR_NOT_CONNECTED, ENOTCONN, "Lost connection to remote server"));
			break;
		}
		const AUTO(channel, it->second);
		if(!channel->send(STD_MOVE(req))){
			send(fetch_uuid, Msg::SC_FetchClosed(Msg::ERR_CONNECTION_LOST, EPIPE, "Could not send data to remote server"));
			m_channels.erase(it);
			break;
		}
	}
	ON_MESSAGE(Msg::CS_FetchClose, req){
		const AUTO(it, m_channels.find(fetch_uuid));
		if(it == m_channels.end()){
			send(fetch_uuid, Msg::SC_FetchClosed(Msg::ERR_NOT_CONNECTED, ENOTCONN, "Lost connection to remote server"));
			break;
		}
		const AUTO(channel, it->second);
		channel->close(req.err_code);
		m_channels.erase(it);
	}
	ON_MESSAGE(Msg::CS_FetchDataAcknowledgment, req){
		const AUTO(it, m_channels.find(fetch_uuid));
		if(it == m_channels.end()){
			send(fetch_uuid, Msg::SC_FetchClosed(Msg::ERR_NOT_CONNECTED, ENOTCONN, "Lost connection to remote server"));
			break;
		}
		const AUTO(channel, it->second);
		channel->throttle_produce(req.size);
	}
//=============================================================================
		}}
		break;
	default:
		LOG_MEDUSA_ERROR("Unknown fetch message from client: message_id = ", message_id, ", size = ", plain.size());
		DEBUG_THROW(Poseidon::Cbpp::Exception, Msg::ST_NOT_FOUND);
	}
}

bool FetchSession::send_explicit(const Poseidon::Uuid &fetch_uuid, boost::uint16_t message_id, Poseidon::StreamBuffer plain){
	PROFILE_ME;

	AUTO(pair, encrypt_header(fetch_uuid, m_password));
	AUTO(payload, encrypt_payload(pair.first, STD_MOVE(plain)));
	pair.second.splice(payload);
	return Poseidon::Cbpp::Session::send(message_id, STD_MOVE(pair.second));
}
bool FetchSession::send(const Poseidon::Uuid &fetch_uuid, const Poseidon::Cbpp::MessageBase &msg){
	return send_explicit(fetch_uuid, msg.get_message_id(), msg);
}

}
