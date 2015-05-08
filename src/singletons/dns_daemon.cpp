#include "../precompiled.hpp"
#include "dns_daemon.hpp"
#include <poseidon/raii.hpp>
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
	typedef DnsDaemon::SuccessCallback SuccessCallback;
	typedef DnsDaemon::FailureCallback FailureCallback;

	struct AddrInfoDeleter {
		CONSTEXPR ::addrinfo *operator()() const NOEXCEPT {
			return NULLPTR;
		}
		void operator()(::addrinfo *res) const NOEXCEPT {
			::freeaddrinfo(res);
		}
	};

	class DnsQueue : NONCOPYABLE {
	private:
		struct Element {
			Poseidon::IpPort ipPort;
			SuccessCallback success;
			FailureCallback failure;

			Element(Poseidon::IpPort ipPort_, SuccessCallback success_, FailureCallback failure_)
				: ipPort(STD_MOVE(ipPort_)), success(STD_MOVE_IDN(success_)), failure(STD_MOVE_IDN(failure_))
			{
			}
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

			try {
				const AUTO_REF(elem, m_queue.front());

				int gaiCode;
				int errCode;
				Poseidon::UniqueHandle<AddrInfoDeleter> addrInfo;
				{
					char port[32];
					std::sprintf(port, "%u", elem.ipPort.port);
					::addrinfo *res = NULLPTR;
					gaiCode = ::getaddrinfo(elem.ipPort.ip.get(), port, NULLPTR, &res);
					errCode = errno;
					addrInfo.reset(res);
					LOG_MEDUSA_DEBUG("DNS lookup result: ipPort = ", elem.ipPort, ", gaiCode = ", gaiCode, ", errCode = ", errCode);
				}
				if(gaiCode == 0){
					const Poseidon::SockAddr sockAddr(addrInfo.get()->ai_addr, addrInfo.get()->ai_addrlen);
					LOG_MEDUSA_DEBUG("DNS: ", elem.ipPort, ", is resolved as ", Poseidon::getIpPortFromSockAddr(sockAddr));
					elem.success(elem.ipPort, sockAddr);
				} else {
					char temp[1024];
					const char *errMsg;
					if(gaiCode == EAI_SYSTEM){
						errMsg = ::strerror_r(errCode, temp, sizeof(temp));
					} else {
						errMsg = ::gai_strerror(gaiCode);
					}
					elem.failure(elem.ipPort, gaiCode, errCode, errMsg);
				}
			} catch(std::exception &e){
				LOG_MEDUSA_ERROR("std::exception thrown in DNS loop: what = ", e.what());
			} catch(...){
				LOG_MEDUSA_ERROR("Unknown exception thrown in DNS loop");
			}
			m_queue.pop_front();

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
		void push(Poseidon::IpPort ipPort, SuccessCallback success, FailureCallback failure){
			const Poseidon::Mutex::UniqueLock lock(m_mutex);
			m_queue.push_back(Element(STD_MOVE(ipPort), STD_MOVE(success), STD_MOVE(failure)));
		}
	};

	boost::weak_ptr<DnsQueue> g_queue;

	MODULE_RAII_PRIORITY(handles, 9000){
		AUTO(queue, boost::make_shared<DnsQueue>());
		g_queue = queue;
		handles.push(STD_MOVE_IDN(queue));
	}
}

void DnsDaemon::asyncLookup(Poseidon::IpPort ipPort, SuccessCallback success, FailureCallback failure){
	PROFILE_ME;

	const AUTO(queue, g_queue.lock());
	if(!queue){
		LOG_MEDUSA_ERROR("DNS queue has not been created");
		DEBUG_THROW(Exception, SSLIT("DNS queue has not been created"));
	}

	queue->push(STD_MOVE(ipPort), STD_MOVE(success), STD_MOVE(failure));
}

}
