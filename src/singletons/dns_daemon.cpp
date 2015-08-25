#include "../precompiled.hpp"
#include "dns_daemon.hpp"
#include <poseidon/singletons/job_dispatcher.hpp>
#include <poseidon/job_promise.hpp>
#include <poseidon/ip_port.hpp>
#include <poseidon/sock_addr.hpp>
#include <poseidon/atomic.hpp>
#include <poseidon/module_raii.hpp>
#include <netdb.h>
#include <unistd.h>

namespace Medusa {

namespace {
	volatile std::size_t g_pendingCallbackCount = 0;

	struct DnsCallbackParam {
		Poseidon::SockAddr &sockAddr;

		std::string host;
		unsigned port;
		boost::shared_ptr<Poseidon::JobPromise> promise;

		std::string hostStr;
		char portStr[16];
		::gaicb cb;
		::gaicb *req;

		DnsCallbackParam(Poseidon::SockAddr &sockAddr_,
			std::string host_, unsigned port_, boost::shared_ptr<Poseidon::JobPromise> promise_)
			: sockAddr(sockAddr_)
			, host(STD_MOVE(host_)), port(port_), promise(STD_MOVE(promise_))
		{
			assert(!host.empty());

			if((host.begin()[0] == '[') && (host.end()[-1] == ']')){
				hostStr.assign(host.begin() + 1, host.end() - 1);
			} else {
				hostStr = host;
			}
			std::sprintf(portStr, "%u", port);

			cb.ar_name = hostStr.c_str();
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
			const char *errMsg = "";
			if(gaiCode != 0){
				errMsg = ::gai_strerror(gaiCode);
				LOG_MEDUSA_DEBUG("DNS lookup failure: host = ", param->host, ", gaiCode = ", gaiCode, ", errMsg = ", errMsg);
				DEBUG_THROW(Exception, SharedNts(errMsg));
			}
			param->sockAddr = Poseidon::SockAddr(param->cb.ar_result->ai_addr, param->cb.ar_result->ai_addrlen);
			LOG_MEDUSA_DEBUG("DNS lookup success: host = ", param->host,
				", result = ", Poseidon::getIpPortFromSockAddr(param->sockAddr).ip);

			param->promise->setSuccess();
		} catch(std::exception &e){
			LOG_MEDUSA_INFO("std::exception thrown in DNS loop: what = ", e.what());
			// param->promise->setException(boost::current_exception());
			param->promise->setException(boost::copy_exception(std::runtime_error(e.what())));
		} catch(...){
			LOG_MEDUSA_ERROR("Unknown exception thrown in DNS loop");
			param->promise->setException(boost::current_exception());
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

void DnsDaemon::syncLookUp(Poseidon::SockAddr &sockAddr, const std::string &host, unsigned port){
	PROFILE_ME;

	if(host.empty()){
		LOG_MEDUSA_ERROR("Empty host string?");
		DEBUG_THROW(Exception, sslit("Empty host string?"));
	}

	const AUTO(promise, boost::make_shared<Poseidon::JobPromise>());

	const AUTO(param, new DnsCallbackParam(sockAddr, host, port, promise));
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

	Poseidon::JobDispatcher::yield(promise);
	promise->checkAndRethrow();
}

}
