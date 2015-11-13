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
	volatile std::size_t g_pending_callback_count = 0;

	struct DnsCallbackParam {
		Poseidon::SockAddr &sock_addr;

		std::string host;
		unsigned port;
		boost::shared_ptr<Poseidon::JobPromise> promise;

		std::string host_str;
		char port_str[16];
		::gaicb cb;
		::gaicb *req;

		DnsCallbackParam(Poseidon::SockAddr &sock_addr_,
			std::string host_, unsigned port_, boost::shared_ptr<Poseidon::JobPromise> promise_)
			: sock_addr(sock_addr_)
			, host(STD_MOVE(host_)), port(port_), promise(STD_MOVE(promise_))
		{
			assert(!host.empty());

			if((host.begin()[0] == '[') && (host.end()[-1] == ']')){
				host_str.assign(host.begin() + 1, host.end() - 1);
			} else {
				host_str = host;
			}
			std::sprintf(port_str, "%u", port);

			cb.ar_name = host_str.c_str();
			cb.ar_service = port_str;
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

	void dns_callback(::sigval sigval_param) NOEXCEPT {
		PROFILE_ME;

		Poseidon::Logger::set_thread_tag("   D");

		const boost::scoped_ptr<DnsCallbackParam> param(static_cast<DnsCallbackParam *>(sigval_param.sival_ptr));

		try {
			const int gai_code = ::gai_error(param->req);
			const char *err_msg = "";
			if(gai_code != 0){
				err_msg = ::gai_strerror(gai_code);
				LOG_MEDUSA_DEBUG("DNS lookup failure: host = ", param->host, ", gai_code = ", gai_code, ", err_msg = ", err_msg);
				DEBUG_THROW(Exception, SharedNts(err_msg));
			}
			param->sock_addr = Poseidon::SockAddr(param->cb.ar_result->ai_addr, param->cb.ar_result->ai_addrlen);
			LOG_MEDUSA_DEBUG("DNS lookup success: host = ", param->host,
				", result = ", Poseidon::get_ip_port_from_sock_addr(param->sock_addr).ip);

			param->promise->set_success();
		} catch(std::exception &e){
			LOG_MEDUSA_INFO("std::exception thrown in DNS loop: what = ", e.what());
			// param->promise->set_exception(boost::current_exception());
			param->promise->set_exception(boost::copy_exception(std::runtime_error(e.what())));
		} catch(...){
			LOG_MEDUSA_ERROR("Unknown exception thrown in DNS loop");
			param->promise->set_exception(boost::current_exception());
		}

		Poseidon::atomic_sub(g_pending_callback_count, 1, Poseidon::ATOMIC_RELAXED);
	}

	struct CallbackCancellationGuard {
		~CallbackCancellationGuard(){
			for(;;){
				const AUTO(count, Poseidon::atomic_load(g_pending_callback_count, Poseidon::ATOMIC_RELAXED));
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

void DnsDaemon::sync_look_up(Poseidon::SockAddr &sock_addr, const std::string &host, unsigned port){
	PROFILE_ME;

	if(host.empty()){
		LOG_MEDUSA_ERROR("Empty host string?");
		DEBUG_THROW(Exception, sslit("Empty host string?"));
	}

	const AUTO(promise, boost::make_shared<Poseidon::JobPromise>());

	const AUTO(param, new DnsCallbackParam(sock_addr, host, port, promise));
	try {
		::sigevent sev;
		sev.sigev_notify = SIGEV_THREAD;
		sev.sigev_value.sival_ptr = param;
		sev.sigev_notify_function = &dns_callback;
		sev.sigev_notify_attributes = NULLPTR;
		const int gai_code = ::getaddrinfo_a(GAI_NOWAIT, &(param->req), 1, &sev); // noexcept
		if(gai_code != 0){
			LOG_MEDUSA_ERROR("Could not initiate async DNS lookup: gai_code = ", gai_code, ", err_msg = ", ::gai_strerror(gai_code));
			DEBUG_THROW(Exception, sslit("Could not initiate async DNS lookup"));
		}
	} catch(...){
		delete param;
		throw;
	}
	Poseidon::atomic_add(g_pending_callback_count, 1, Poseidon::ATOMIC_RELAXED); // noexcept

	Poseidon::JobDispatcher::yield(promise);
	promise->check_and_rethrow();
}

}
