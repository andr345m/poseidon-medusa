#include "precompiled.hpp"
#include "fetch_session.hpp"
#include <poseidon/singletons/timer_daemon.hpp>
#include <poseidon/job_base.hpp>
#include <poseidon/singletons/dns_daemon.hpp>
#include <poseidon/sock_addr.hpp>
#include <poseidon/tcp_client_base.hpp>
#include <poseidon/atomic.hpp>
#include <poseidon/mutex.hpp>
#include <poseidon/zlib.hpp>
#include "encryption.hpp"
#include "msg/cs_fetch.hpp"
#include "msg/sc_fetch.hpp"
#include "msg/error_codes.hpp"

namespace Medusa {

namespace {
	inline boost::uint64_t get_max_single_pipeline_size(){
		const AUTO(max_single_pipeline_size, get_config<boost::uint64_t>("fetch_max_single_pipeline_size", 1048576));
		return max_single_pipeline_size;
	}
}

class FetchSession::OriginClient : public Poseidon::TcpClientBase {
private:
	const boost::weak_ptr<Channel> m_weak_channel;

	volatile bool m_readable;
	volatile int m_err_code;

	mutable Poseidon::Mutex m_recv_queue_mutex;
	Poseidon::StreamBuffer m_recv_queue;

public:
	OriginClient(const Poseidon::SockAddr &sock_addr, bool use_ssl, const boost::shared_ptr<Channel> &channel)
		: Poseidon::TcpClientBase(sock_addr, use_ssl, true)
		, m_weak_channel(channel)
		, m_readable(false), m_err_code(0)
	{
	}
	~OriginClient();

protected:
	void on_connect() OVERRIDE {
		Poseidon::atomic_store(m_readable, true, Poseidon::ATOMIC_RELAXED);
	}
	void on_read_hup() NOEXCEPT OVERRIDE {
		shutdown_write();
	}
	void on_close(int err_code) OVERRIDE {
		Poseidon::atomic_store(m_readable, true, Poseidon::ATOMIC_RELAXED);
		Poseidon::atomic_store(m_err_code, err_code, Poseidon::ATOMIC_RELAXED);
	}
	void on_receive(Poseidon::StreamBuffer data) OVERRIDE;

public:
	bool is_readable() const NOEXCEPT {
		return Poseidon::atomic_load(m_readable, Poseidon::ATOMIC_RELAXED);
	}
	bool send(Poseidon::StreamBuffer data) OVERRIDE {
		return Poseidon::TcpClientBase::send(data);
	}
	Poseidon::StreamBuffer move_recv_queue(){
		Poseidon::StreamBuffer recv_queue;
		const Poseidon::Mutex::UniqueLock lock(m_recv_queue_mutex);
		recv_queue.swap(m_recv_queue);
		return recv_queue;
	}
	int peek_err_code() const NOEXCEPT {
		return Poseidon::atomic_load(m_err_code, Poseidon::ATOMIC_RELAXED);
	}
};

FetchSession::OriginClient::~OriginClient(){
}

class FetchSession::Channel : NONCOPYABLE, public virtual Poseidon::VirtualSharedFromThis {
private:
	struct Request {
		std::string host;
		unsigned port;
		bool use_ssl;
		boost::uint64_t flags;

		Poseidon::StreamBuffer send_queue;
		bool connected;

		boost::shared_ptr<const Poseidon::JobPromiseContainer<Poseidon::SockAddr> > promised_sock_addr;
		boost::shared_ptr<OriginClient> origin_client;
		boost::uint64_t creation_time;
	};
	boost::container::deque<Request> m_requests;

	volatile boost::uint64_t m_bytes_received;
	volatile boost::uint64_t m_bytes_acknowledged;

	boost::uint64_t m_last_activity_time;

public:
	Channel()
		: m_requests()
		, m_bytes_received(0), m_bytes_acknowledged(0)
		, m_last_activity_time(0)
	{
	}
	~Channel();

public:
	void fetch_some(const Poseidon::Uuid &fetch_uuid, FetchSession *session){
		PROFILE_ME;

		while(!m_requests.empty()){
			AUTO_REF(req, m_requests.front());
			const AUTO(now, Poseidon::get_fast_mono_clock());

			if(!req.promised_sock_addr){
				LOG_MEDUSA_INFO("Looking up origin server: host:port = ", req.host, ":", req.port);
				req.promised_sock_addr = Poseidon::DnsDaemon::enqueue_for_looking_up(req.host, req.port);
			}
			if(!req.promised_sock_addr->is_satisfied()){
				LOG_MEDUSA_DEBUG("Waiting for DNS resolve: host:port = ", req.host);
				break;
			}

			if(!req.origin_client){
				Poseidon::SockAddr sock_addr;
				try {
					sock_addr = req.promised_sock_addr->get();
				} catch(std::exception &e){
					LOG_MEDUSA_INFO("DNS failure: host:port = ", req.host, ":", req.port, ", what = ", e.what());
					DEBUG_THROW(Poseidon::Cbpp::Exception, Msg::ERR_DNS_FAILURE, Poseidon::SharedNts(e.what()));
				}
				if(sock_addr.is_private()){
					LOG_MEDUSA_INFO("Connection to private address requested: host:port = ", req.host, ":", req.port,
						", ip_port = ", Poseidon::IpPort(sock_addr));
					DEBUG_THROW(Poseidon::Cbpp::Exception, Msg::ERR_PRIVATE_ADDRESS, Poseidon::SharedNts("Connection to private address requested"));
				}
				LOG_MEDUSA_INFO("Connecting to origin server: host:port = ", req.host, ":", req.port, ", use_ssl = ", req.use_ssl);
				AUTO(origin_client, boost::make_shared<OriginClient>(sock_addr, req.use_ssl, virtual_shared_from_this<Channel>()));
				origin_client->go_resident();

				req.origin_client = origin_client;
				req.creation_time = now;
			}

			if(!req.origin_client->is_readable()){
				LOG_MEDUSA_DEBUG("Waiting for SYN ACK: host:port = ", req.host);
				const AUTO(time_elapsed, Poseidon::saturated_sub(now, req.creation_time));
				const AUTO(connect_timeout, get_config<boost::uint64_t>("remote_client_connect_timeout", 10000));
				if(time_elapsed > connect_timeout){
					LOG_MEDUSA_INFO("Connection to origin server timed out: host:port = ", req.host);
					DEBUG_THROW(Poseidon::Cbpp::Exception, Msg::ERR_CONNECTION_TIMED_OUT, Poseidon::sslit("Connection to origin server timed out"));
				}
				break;
			}
			if(!req.connected){
				session->send(fetch_uuid, Msg::SC_FetchConnected(req.flags));
				req.connected = true;
			}
			const bool client_closed = req.origin_client->has_been_shutdown_read();
			AUTO(recv_queue, req.origin_client->move_recv_queue());

			Poseidon::Deflator deflator;
			std::basic_string<unsigned char> temp;
			for(;;){
				temp.resize(8192);
				temp.resize(recv_queue.get(&*temp.begin(), temp.size()));
				if(temp.empty()){
					break;
				}
				deflator.put(&*temp.begin(), temp.size());
				AUTO(data, deflator.finalize());
				temp.resize(data.size());
				data.get(&*temp.begin(), temp.size());
				DEBUG_THROW_ASSERT(data.empty());
				session->send(fetch_uuid, Msg::SC_FetchReceived(STD_MOVE(temp)));
			}

			const AUTO(err_code, req.origin_client->peek_err_code());
			if(err_code != 0){
				LOG_MEDUSA_DEBUG("Fetch error: err_code = ", err_code);
				DEBUG_THROW(Poseidon::Cbpp::Exception, Msg::ERR_CONNECTION_LOST, Poseidon::get_error_desc(err_code));
			}
			if(!req.send_queue.empty() && !req.origin_client->send(STD_MOVE(req.send_queue))){
				LOG_MEDUSA_DEBUG("Error sending data to origin server: host:port = ", req.host, ":", req.port);
				DEBUG_THROW(Poseidon::Cbpp::Exception, Msg::ERR_CONNECTION_LOST, Poseidon::sslit("Error sending data to origin server"));
			}

			if(!client_closed){
				break;
			}
			LOG_MEDUSA_INFO("Closing connection to origin server: host:port = ", req.host, ":", req.port);
			session->send(fetch_uuid, Msg::SC_FetchEnded());
			m_requests.pop_front();
		}
	}

	void push_connect(std::string host, unsigned port, bool use_ssl, boost::uint64_t flags){
		PROFILE_ME;

		Request request = { STD_MOVE(host), port, use_ssl, flags };
		m_requests.push_back(STD_MOVE(request));

		const AUTO(max_size, get_config<std::size_t>("fetch_max_pipelining_size", 16));
		if(m_requests.size() >= max_size){
			LOG_MEDUSA_WARNING("Max pipelining size exceeded: size = ", m_requests.size(), ", max_size = ", max_size);
			DEBUG_THROW(Poseidon::Cbpp::Exception, Msg::ERR_MAX_PIPELINING_SIZE, Poseidon::sslit("Max pipelining size exceeded"));
		}
	}
	void push_send(Poseidon::StreamBuffer data){
		PROFILE_ME;

		DEBUG_THROW_ASSERT(!m_requests.empty());
		AUTO_REF(req, m_requests.back());

		req.send_queue.splice(data);

		const AUTO(max_size, get_config<std::size_t>("fetch_max_pending_buffer_size", 65536));
		if(req.send_queue.size() >= max_size){
			LOG_MEDUSA_WARNING("Max pending buffer size exceeded: size = ", req.send_queue.size(), ", max_size = ", max_size);
			DEBUG_THROW(Poseidon::Cbpp::Exception, Msg::ERR_MAX_PENDING_BUFFER_SIZE, Poseidon::sslit("Max pending buffer size exceeded"));
		}
	}

	void produce_some(boost::uint64_t size){
		PROFILE_ME;

		const AUTO(bytes_received, Poseidon::atomic_add(m_bytes_received, size, Poseidon::ATOMIC_RELAXED));
		const AUTO(bytes_acknowledged, Poseidon::atomic_load(m_bytes_acknowledged, Poseidon::ATOMIC_RELAXED));
		LOG_MEDUSA_DEBUG("> Produced: bytes_received = ", bytes_received, ", bytes_acknowledged = ", bytes_acknowledged);
		DEBUG_THROW_ASSERT(bytes_received >= bytes_acknowledged);
		if(bytes_received - bytes_acknowledged >= get_max_single_pipeline_size()){
			LOG_MEDUSA_DEBUG("Throttle the client!");
			if(!m_requests.empty()){
				const AUTO_REF(origin_client, m_requests.front().origin_client);
				if(origin_client){
					origin_client->set_throttled(true);
				}
			}
		}
	}
	void consume_some(boost::uint64_t size){
		PROFILE_ME;

		const AUTO(bytes_received, Poseidon::atomic_load(m_bytes_received, Poseidon::ATOMIC_RELAXED));
		const AUTO(bytes_acknowledged, Poseidon::atomic_add(m_bytes_acknowledged, size, Poseidon::ATOMIC_RELAXED));
		LOG_MEDUSA_DEBUG("> Consumed: bytes_received = ", bytes_received, ", bytes_acknowledged = ", bytes_acknowledged);
		DEBUG_THROW_ASSERT(bytes_received >= bytes_acknowledged);
		if(bytes_received - bytes_acknowledged < get_max_single_pipeline_size()){
			LOG_MEDUSA_DEBUG("Unthrottle the client!");
			if(!m_requests.empty()){
				const AUTO_REF(origin_client, m_requests.front().origin_client);
				if(origin_client){
					origin_client->set_throttled(false);
				}
			}
		}
	}

	boost::uint64_t get_last_activity_time() const {
		return m_last_activity_time;
	}
	void set_last_activity_time(boost::uint64_t last_activity_time){
		m_last_activity_time = last_activity_time;
	}
};

FetchSession::Channel::~Channel(){
	if(!m_requests.empty()){
		const AUTO_REF(origin_client, m_requests.front().origin_client);
		if(origin_client){
			origin_client->force_shutdown();
		}
	}
}

void FetchSession::OriginClient::on_receive(Poseidon::StreamBuffer data){
	const AUTO(channel, m_weak_channel.lock());
	if(!channel){
		force_shutdown();
		return;
	}
	channel->produce_some(data.size());

	const Poseidon::Mutex::UniqueLock lock(m_recv_queue_mutex);
	m_recv_queue.splice(data);
}

void FetchSession::timer_proc(const boost::weak_ptr<FetchSession> &weak) NOEXCEPT {
	PROFILE_ME;

	const AUTO(session, weak.lock());
	if(!session){
		return;
	}
	session->on_sync_timer();
}

FetchSession::FetchSession(Poseidon::UniqueFile socket, std::string password)
	: Poseidon::Cbpp::Session(STD_MOVE(socket))
	, m_password(STD_MOVE(password))
{
	LOG_MEDUSA_INFO("FetchSession constructor: remote = ", get_remote_info());
}
FetchSession::~FetchSession(){
	LOG_MEDUSA_INFO("FetchSession destructor: remote = ", get_remote_info());
}

void FetchSession::on_sync_data_message(boost::uint16_t message_id, Poseidon::StreamBuffer payload){
	PROFILE_ME;

	Poseidon::Uuid fetch_uuid;
	Poseidon::StreamBuffer plain;
	if(!decrypt(fetch_uuid, plain, STD_MOVE(payload), m_password)){
		LOG_MEDUSA_ERROR("Error decrypting data from fetch client: remote = ", get_remote_info());
		DEBUG_THROW(Poseidon::Cbpp::Exception, Poseidon::Cbpp::ST_END_OF_STREAM, Poseidon::sslit("Error decrypting data from fetch client"));
	}
	boost::shared_ptr<Channel> channel;
	try {
		LOG_MEDUSA_DEBUG("Fetch request: fetch_uuid = ", fetch_uuid, ", message_id = ", message_id);
		switch(message_id){
			{{
#define ON_MESSAGE(Msg_, req_)  \
			}}  \
			break;  \
		case Msg_::ID: {    \
			PROFILE_ME;	\
			Msg_ (req_)(plain); \
			{ //
//=============================================================================
	ON_MESSAGE(Msg::CS_FetchOpen, req){
		const AUTO(result, m_channels.emplace(fetch_uuid, boost::make_shared<Channel>()));
		if(!result.second){
			LOG_MEDUSA_WARNING("Fetch channel exists: fetch_uuid = ", fetch_uuid);
			break;
		}
		if(!m_timer){
			m_timer = Poseidon::TimerDaemon::register_timer(0, 100, boost::bind(&timer_proc, virtual_weak_from_this<FetchSession>()));
		}
		channel = result.first->second;
	}
	ON_MESSAGE(Msg::CS_FetchConnect, req){
		const AUTO(it, m_channels.find(fetch_uuid));
		if(it == m_channels.end()){
			LOG_MEDUSA_DEBUG("Fetch channel not found: fetch_uuid = ", fetch_uuid);
			break;
		}
		channel = it->second;
		channel->push_connect(STD_MOVE(req.host), req.port, req.use_ssl, req.flags);
	}
	ON_MESSAGE(Msg::CS_FetchSend, req){
		const AUTO(it, m_channels.find(fetch_uuid));
		if(it == m_channels.end()){
			LOG_MEDUSA_DEBUG("Fetch channel not found: fetch_uuid = ", fetch_uuid);
			break;
		}
		channel = it->second;
		Poseidon::Inflator inflator;
		inflator.put(req.send_queue.data(), req.send_queue.size());
		AUTO(data, inflator.finalize());
		const AUTO(size, data.size());
		channel->push_send(STD_MOVE(data));
		LOG_MEDUSA_DEBUG("Fetch sent: fetch_uuid = ", fetch_uuid, ", size = ", size);
	}
	ON_MESSAGE(Msg::CS_FetchAcknowledge, req){
		const AUTO(it, m_channels.find(fetch_uuid));
		if(it == m_channels.end()){
			LOG_MEDUSA_DEBUG("Fetch channel not found: fetch_uuid = ", fetch_uuid);
			break;
		}
		channel = it->second;
		channel->consume_some(req.size);
	}
	ON_MESSAGE(Msg::CS_FetchClose, req){
		const AUTO(it, m_channels.find(fetch_uuid));
		if(it == m_channels.end()){
			LOG_MEDUSA_DEBUG("Fetch channel not found: fetch_uuid = ", fetch_uuid);
			break;
		}
		// channel.reset();
	}
//=============================================================================
			}}
			break;
		default:
			LOG_MEDUSA_ERROR("Unknown fetch message from client: message_id = ", message_id, ", size = ", plain.size());
			break;
		}
	} catch(Poseidon::Cbpp::Exception &e){
		LOG_MEDUSA_WARNING("Poseidon::Cbpp::Exception thrown: status_code = ", e.get_status_code(), ", what = ", e.what());
		send(fetch_uuid, Msg::SC_FetchClosed(e.get_status_code(), 0, e.what()));
		channel.reset();
	} catch(std::exception &e){
		LOG_MEDUSA_WARNING("std::exception thrown: what = ", e.what());
		send(fetch_uuid, Msg::SC_FetchClosed(Msg::ST_INTERNAL_ERROR, 0, e.what()));
		channel.reset();
	}
	if(channel){
		const AUTO(now, Poseidon::get_fast_mono_clock());
		channel->set_last_activity_time(now);
	}
	if(!channel){
		LOG_MEDUSA_DEBUG("Reclaiming fetch request: fetch_uuid = ", fetch_uuid);
		m_channels.erase(fetch_uuid);
	}
}
void FetchSession::on_sync_timer(){
	PROFILE_ME;

	AUTO(channels, m_channels);
	for(AUTO(it, channels.begin()); it != channels.end(); ++it){
		const AUTO_REF(fetch_uuid, it->first);
		AUTO_REF(channel, it->second);
		try {
			channel->fetch_some(fetch_uuid, this);
		} catch(Poseidon::Cbpp::Exception &e){
			LOG_MEDUSA_DEBUG("Cbpp::Exception thrown: fetch_uuid = ", fetch_uuid, ", status_code = ", e.get_status_code(), ", what = ", e.what());
			send(fetch_uuid, Msg::SC_FetchClosed(e.get_status_code(), 0, e.what()));
			channel.reset();
		} catch(std::exception &e){
			LOG_MEDUSA_DEBUG("Cbpp::Exception thrown: fetch_uuid = ", fetch_uuid, ", what = ", e.what());
			send(fetch_uuid, Msg::SC_FetchClosed(Msg::ERR_CONNECTION_LOST, 0, e.what()));
			channel.reset();
		}
		if(channel){
			const AUTO(now, Poseidon::get_fast_mono_clock());
			const AUTO(expiry_timeout, get_config<boost::uint64_t>("fetch_channel_expiry_timeout", 300000));
			if(Poseidon::saturated_sub(now, channel->get_last_activity_time()) > expiry_timeout){
				LOG_MEDUSA_DEBUG("Reclaiming expired channel: fetch_uuid = ", fetch_uuid);
				channel.reset();
			}
		}
		if(!channel){
			m_channels.erase(fetch_uuid);
		}
	}
	if(m_channels.empty()){
		m_timer.reset();
	}
}
bool FetchSession::send(const Poseidon::Uuid &fetch_uuid, const Poseidon::Cbpp::MessageBase &msg){
	PROFILE_ME;

	Poseidon::StreamBuffer encrypted;
	encrypt(encrypted, fetch_uuid, Poseidon::StreamBuffer(msg), m_password);
	return Poseidon::Cbpp::Session::send(msg.get_id(), STD_MOVE(encrypted));
}

}
