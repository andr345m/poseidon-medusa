#include "../precompiled.hpp"
#include "dns_daemon.hpp"
#include <poseidon/job_base.hpp>
#include <poseidon/ip_port.hpp>
#include <poseidon/atomic.hpp>
#include <poseidon/module_raii.hpp>
#include <netdb.h>
#include <unistd.h>

namespace Medusa {

namespace {
	class CallbackJob : public Poseidon::JobBase {
	private:
		const std::string m_host;
		const unsigned m_port;
		const DnsDaemon::Callback m_callback;
		const DnsDaemon::ExceptionCallback m_except;

		const int m_gaiCode;
		const Poseidon::SockAddr m_addr;
		const std::string m_errMsg;

	public:
		CallbackJob(std::string host, unsigned port, DnsDaemon::Callback callback, DnsDaemon::ExceptionCallback except,
			int gaiCode, const Poseidon::SockAddr &addr, std::string errMsg)
			: m_host(STD_MOVE(host)), m_port(port), m_callback(STD_MOVE_IDN(callback)), m_except(STD_MOVE_IDN(except))
			, m_gaiCode(gaiCode), m_addr(addr), m_errMsg(errMsg)
		{
		}

	public:
		boost::weak_ptr<const void> getCategory() const OVERRIDE {
			return VAL_INIT;
		}
		void perform() const OVERRIDE {
			PROFILE_ME;

			try {
				m_callback(m_host, m_port, m_gaiCode, m_addr, m_errMsg.c_str());
			} catch(std::exception &e){
				LOG_MEDUSA_ERROR("std::exception thrown: what = ", e.what());
				if(m_except){
					m_except();
				}
				throw;
			}
		}
	};

	volatile std::size_t g_pendingCallbackCount = 0;

	struct DnsCallbackParam {
		std::string host;
		unsigned port;
		DnsDaemon::Callback callback;
		DnsDaemon::ExceptionCallback except;
		bool isLowLevel;

		char portStr[16];
		::gaicb cb;
		::gaicb *req;

		DnsCallbackParam(std::string host_, unsigned port_,
			DnsDaemon::Callback callback_, DnsDaemon::ExceptionCallback except_, bool isLowLevel_)
			: host(STD_MOVE(host_)), port(port_)
			, callback(STD_MOVE_IDN(callback_)), except(STD_MOVE_IDN(except_)), isLowLevel(isLowLevel_)
		{
			std::sprintf(portStr, "%hu", port);
			cb.ar_name = host.c_str();
			cb.ar_service = portStr;
			cb.ar_request = NULLPTR;
			cb.ar_result = NULLPTR;
			req = &cb;
		}
		~DnsCallbackParam(){
			if(cb.ar_result){
				::freeaddrinfo(cb.ar_result);
			}
		}
	};

	void dnsCallback(::sigval sigvalParam) NOEXCEPT {
		PROFILE_ME;

		Poseidon::Logger::setThreadTag("   D");

		const boost::scoped_ptr<DnsCallbackParam> param(static_cast<DnsCallbackParam *>(sigvalParam.sival_ptr));

		try {
			const int gaiCode = ::gai_error(param->req);
			Poseidon::SockAddr sockAddr;
			const char *errMsg;
			if(gaiCode == 0){
				sockAddr = Poseidon::SockAddr(param->cb.ar_result->ai_addr, param->cb.ar_result->ai_addrlen);
				errMsg = "";
				LOG_MEDUSA_DEBUG("DNS lookup success: host:port = ", param->host, ':', param->port,
					", result = ", Poseidon::getIpPortFromSockAddr(sockAddr));
			} else {
				errMsg = ::gai_strerror(gaiCode);
				LOG_MEDUSA_DEBUG("DNS lookup failure: host:port = ", param->host, ':', param->port,
					", gaiCode = ", gaiCode, ", errMsg = ", errMsg);
			}

			if(param->isLowLevel){
				param->callback(param->host, param->port, gaiCode, sockAddr, errMsg);
			} else {
				Poseidon::enqueueJob(boost::make_shared<CallbackJob>(
					STD_MOVE(param->host), param->port, STD_MOVE(param->callback), param->except, gaiCode, sockAddr, errMsg));
			}
		} catch(std::exception &e){
			LOG_MEDUSA_ERROR("std::exception thrown in DNS loop: what = ", e.what());
			if(param->except){
				param->except();
			}
		}

		Poseidon::atomicSub(g_pendingCallbackCount, 1, Poseidon::ATOMIC_RELAXED);
	}

	struct CallbackCancellationGuard {
		~CallbackCancellationGuard(){
			for(;;){
				const AUTO(count, Poseidon::atomicLoad(g_pendingCallbackCount, Poseidon::ATOMIC_RELAXED));
				if(count == 0){
					break;
				}
				LOG_MEDUSA_INFO("Waiting for ", count, " pending DNS callbacks...");
				::gai_cancel(NULLPTR);
				::usleep(100000);
			}
		}
	};

	MODULE_RAII(handles){
		handles.push(boost::make_shared<CallbackCancellationGuard>());
	}
}

void DnsDaemon::asyncLookup(std::string host, unsigned port,
	DnsDaemon::Callback callback, DnsDaemon::ExceptionCallback except, bool isLowLevel)
{
	PROFILE_ME;

	const AUTO(param, new DnsCallbackParam(STD_MOVE(host), port, STD_MOVE(callback), STD_MOVE(except), isLowLevel));
	try {
		::sigevent sev;
		sev.sigev_notify = SIGEV_THREAD;
		sev.sigev_value.sival_ptr = param;
		sev.sigev_notify_function = &dnsCallback;
		sev.sigev_notify_attributes = NULLPTR;
		const int gaiCode = ::getaddrinfo_a(GAI_NOWAIT, &(param->req), 1, &sev); // noexcept
		if(gaiCode != 0){
			LOG_MEDUSA_ERROR("Could not initiate async DNS lookup: gaiCode = ", gaiCode, ", errMsg = ", ::gai_strerror(gaiCode));
			DEBUG_THROW(Exception, sslit("Could not initiate async DNS lookup"));
		}
	} catch(...){
		delete param;
		throw;
	}
	Poseidon::atomicAdd(g_pendingCallbackCount, 1, Poseidon::ATOMIC_RELAXED); // noexcept
}

}
