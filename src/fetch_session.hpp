#ifndef MEDUSA_FETCH_SESSION_HPP_
#define MEDUSA_FETCH_SESSION_HPP_

#include <map>
#include <boost/cstdint.hpp>
#include <poseidon/stream_buffer.hpp>
#include <poseidon/cbpp/low_level_session.hpp>

namespace Medusa {

class FetchSession : public Poseidon::Cbpp::LowLevelSession {
private:
	class FetchClient;

public:
	struct ClientContext {
		std::string host;
		unsigned port;
		boost::uint64_t opaque;

		ClientContext()
			: host(), port(), opaque()
		{
		}
		ClientContext(std::string host_, unsigned port_, boost::uint64_t opaque_)
			: host(STD_MOVE(host_)), port(port_), opaque(opaque_)
		{
		}

		bool operator<(const ClientContext &rhs) const {
			const int cmp = host.compare(rhs.host);
			if(cmp != 0){
				return cmp < 0;
			}
			if(port != rhs.port){
				return port < rhs.port;
			}
			return opaque < rhs.opaque;
		}
	};

private:
	const std::string m_password;

	std::map<ClientContext, boost::weak_ptr<FetchClient> > m_clients;

public:
	FetchSession(Poseidon::UniqueFile socket, std::string password);
	~FetchSession();

private:
	void shutdownAllClients(bool force) NOEXCEPT;

protected:
	void onClose(int errCode) NOEXCEPT OVERRIDE;

	void onLowLevelRequest(boost::uint16_t messageId, Poseidon::StreamBuffer payload) OVERRIDE;
	void onLowLevelControl(Poseidon::Cbpp::ControlCode controlCode, Poseidon::Cbpp::StatusCode statusCode, std::string reason) OVERRIDE;

public:
	bool send(boost::uint16_t messageId, Poseidon::StreamBuffer payload);

	template<class MessageT>
	typename boost::enable_if<boost::is_base_of<Poseidon::Cbpp::MessageBase, MessageT>, bool>::type send(const MessageT &payload){
		return send(MessageT::ID, Poseidon::StreamBuffer(payload));
	}
};

}

#endif
