#include "../precompiled.hpp"
#include "dns_daemon.hpp"
#include <poseidon/job_base.hpp>
#include <poseidon/ip_port.hpp>
#include <poseidon/mutex.hpp>
#include <poseidon/atomic.hpp>
#include <poseidon/thread.hpp>
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <string.h>

namespace Medusa {

namespace {
	class CallbackJob : public Poseidon::JobBase {
	private:
		const DnsDaemon::Callback m_callback;
		const std::string m_host;
		const unsigned m_port;
		const int m_gaiCode;
		const Poseidon::SockAddr m_addr;
		const int m_errCode;
		const std::string m_errMsg;

	public:
		CallbackJob(DnsDaemon::Callback callback, std::string host, unsigned port,
			int gaiCode, const Poseidon::SockAddr &addr, int errCode, std::string errMsg)
			: m_callback(STD_MOVE_IDN(callback)), m_host(STD_MOVE(host)), m_port(port)
			, m_gaiCode(gaiCode), m_addr(addr), m_errCode(errCode), m_errMsg(errMsg)
		{
		}

	public:
		boost::weak_ptr<const void> getCategory() const OVERRIDE {
			return VAL_INIT;
		}
		void perform() const OVERRIDE {
			PROFILE_ME;

			m_callback(m_host, m_port, m_gaiCode, m_addr, m_errCode, m_errMsg.c_str());
		}
	};

	class DnsQueue : NONCOPYABLE {
	private:
		struct Element {
			std::string host;
			unsigned port;
			DnsDaemon::Callback callback;
			bool isLowLevel;
			DnsDaemon::ExceptionCallback except;
		};

	private:
		Poseidon::Mutex m_mutex;
		std::deque<Element> m_queue;

		volatile bool m_running;
		Poseidon::Thread m_thread;

	public:
		DnsQueue()
			: m_running(true)
			, m_thread(boost::bind(&DnsQueue::threadProc, this), "   D")
		{
		}
		~DnsQueue(){
			Poseidon::atomicStore(m_running, false, Poseidon::ATOMIC_RELEASE);
			m_thread.join();
		}

	private:
		bool pumpOne(){
			PROFILE_ME;

			if(m_queue.empty()){
				return false;
			}

			AUTO(elem, STD_MOVE(m_queue.front()));
			m_queue.pop_front();

			try {
				try {
					Poseidon::SockAddr sockAddr;

					char temp[1024];
					std::sprintf(temp, "%u", elem.port);
					::addrinfo *res = NULLPTR;
					const int gaiCode = ::getaddrinfo(elem.host.c_str(), temp, NULLPTR, &res);
					const int errCode = errno;
					const char *errMsg;
					if(gaiCode == 0){
						try {
							sockAddr = Poseidon::SockAddr(res->ai_addr, res->ai_addrlen);
						} catch(...){
							::freeaddrinfo(res);
							throw;
						}
						::freeaddrinfo(res);
						errMsg = "";
					} else if(gaiCode != EAI_SYSTEM){
						errMsg = ::gai_strerror(gaiCode);
					} else {
						errMsg = ::strerror_r(errCode, temp, sizeof(temp));
					}
					LOG_MEDUSA_DEBUG("DNS lookup result: host:port = ", elem.host, ':', elem.port,
						", gaiCode = ", gaiCode, ", errCode = ", errCode, ", errMsg = ", errMsg);
					if(elem.isLowLevel){
						elem.callback(elem.host, elem.port, gaiCode, sockAddr, errCode, errMsg);
					} else {
						Poseidon::enqueueJob(boost::make_shared<CallbackJob>(STD_MOVE(elem.callback),
							STD_MOVE(elem.host), elem.port, gaiCode, sockAddr, errCode, std::string(errMsg)));
					}
				} catch(...){
					if(elem.except){
						elem.except();
					}
					throw;
				}
			} catch(std::exception &e){
				LOG_MEDUSA_ERROR("std::exception thrown in DNS loop: what = ", e.what());
			} catch(...){
				LOG_MEDUSA_ERROR("Unknown exception thrown in DNS loop");
			}

			return true;
		}

		void threadProc() NOEXCEPT {
			PROFILE_ME;
			LOG_MEDUSA_INFO("DNS daemon started");

			for(;;){
				while(pumpOne()){
					// noop
				}

				if(!atomicLoad(m_running, Poseidon::ATOMIC_ACQUIRE)){
					break;
				}

				::usleep(100000);
			}

			LOG_MEDUSA_INFO("DNS daemon stopped");
		}

	public:
		void push(std::string host, unsigned port, DnsDaemon::Callback callback,
			bool isLowLevel, DnsDaemon::ExceptionCallback except)
		{
			Element elem;
			elem.host = STD_MOVE(host);
			elem.port = port;
			elem.callback = STD_MOVE_IDN(callback);
			elem.isLowLevel = isLowLevel;
			elem.except = STD_MOVE_IDN(except);

			const Poseidon::Mutex::UniqueLock lock(m_mutex);
			m_queue.push_back(STD_MOVE(elem));
		}
	};

	boost::weak_ptr<DnsQueue> g_queue;

	MODULE_RAII_PRIORITY(handles, 9000){
		AUTO(queue, boost::make_shared<DnsQueue>());
		g_queue = queue;
		handles.push(STD_MOVE_IDN(queue));
	}
}

void DnsDaemon::asyncLookup(std::string host, unsigned port, Callback callback,
	bool isLowLevel, DnsDaemon::ExceptionCallback except)
{
	PROFILE_ME;

	const AUTO(queue, g_queue.lock());
	if(!queue){
		LOG_MEDUSA_ERROR("DNS queue has not been created");
		DEBUG_THROW(Exception, SSLIT("DNS queue has not been created"));
	}

	queue->push(STD_MOVE(host), port, STD_MOVE(callback), isLowLevel, STD_MOVE(except));
}

}
