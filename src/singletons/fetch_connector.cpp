#include "../precompiled.hpp"
#include "fetch_connector.hpp"
#include <poseidon/singletons/dns_daemon.hpp>
#include <poseidon/singletons/timer_daemon.hpp>
#include <poseidon/sock_addr.hpp>

namespace Medusa {

namespace {
	class RollingMap : NONCOPYABLE {
	private:
		std::vector<boost::weak_ptr<FetchClient> > m_pool;
		std::size_t m_next;

	public:
		RollingMap()
			: m_pool(std::max<std::size_t>(1, get_config<std::size_t>("fetch_client_count", 3))), m_next(0)
		{
			DEBUG_THROW_ASSERT(!m_pool.empty());
		}
		~RollingMap(){
			for(std::size_t i = 0; i < m_pool.size(); ++i){
				const AUTO(client, m_pool.at(i).lock());
				if(client){
					client->force_shutdown();
				}
			}
		}

	public:
		void check_all(const Poseidon::SockAddr &sock_addr, bool use_ssl, bool verify_peer, const std::string &password){
			PROFILE_ME;

			for(std::size_t i = 0; i < m_pool.size(); ++i){
				AUTO(client, m_pool.at(i).lock());
				if(!client){
					LOG_MEDUSA_DEBUG("Creating new fetch client: sock_addr = ", Poseidon::get_ip_port_from_sock_addr(sock_addr));
					client = boost::make_shared<FetchClient>(sock_addr, use_ssl, verify_peer, password);
					client->go_resident();
					client->send_control(Poseidon::Cbpp::ST_PING, VAL_INIT);
					m_pool.at(i) = client;
					break; // 一次只检查一个。
				}
			}
		}
		boost::shared_ptr<FetchClient> get_one(){
			PROFILE_ME;

			for(std::size_t i = 0; i < m_pool.size(); ++i){
				AUTO(client, m_pool.at(++m_next % m_pool.size()).lock());
				if(client){
					return STD_MOVE(client);
				}
			}
			return VAL_INIT;
		}
	};

	boost::weak_ptr<RollingMap> g_rolling_map;

	void check_timer_proc(){
		PROFILE_ME;

		const AUTO(rolling_map, g_rolling_map.lock());
		if(!rolling_map){
			return;
		}

		const AUTO(addr, get_config<std::string> ("fetch_client_addr",        "127.0.0.1"));
		const AUTO(port, get_config<unsigned>    ("fetch_client_port",        5326));
		const AUTO(ssl,  get_config<bool>        ("fetch_client_use_ssl",     false));
		const AUTO(verf, get_config<bool>        ("fetch_client_verify_peer", true));
		const AUTO(pass, get_config<std::string> ("fetch_client_password",    "password"));

		const AUTO(promised_sock_addr, Poseidon::DnsDaemon::enqueue_for_looking_up(addr, port));
		Poseidon::yield(promised_sock_addr);
		const AUTO_REF(sock_addr, promised_sock_addr->get());

		rolling_map->check_all(sock_addr, ssl, verf, pass);
	}

	MODULE_RAII(handles){
		const AUTO(rolling_map, boost::make_shared<RollingMap>());
		handles.push(rolling_map);
		g_rolling_map = rolling_map;

		const AUTO(reconnect_delay, get_config<boost::uint64_t>("fetch_client_reconnect_delay", 5000));
		const AUTO(check_timer, Poseidon::TimerDaemon::register_timer(0, reconnect_delay, boost::bind(&check_timer_proc)));
		handles.push(check_timer);
	}
}

boost::shared_ptr<FetchClient> FetchConnector::get_client(){
	PROFILE_ME;

	const AUTO(rolling_map, g_rolling_map.lock());
	if(!rolling_map){
		LOG_MEDUSA_WARNING("Fetch client rolling map is gone!");
		return VAL_INIT;
	}
	return rolling_map->get_one();
}

}
