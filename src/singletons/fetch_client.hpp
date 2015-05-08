#ifndef MEDUSA_FETCH_CLIENT_HPP_
#define MEDUSA_FETCH_CLIENT_HPP_

#include <poseidon/cbpp/low_level_client.hpp>

namespace Medusa {

class FetchClient : public Poseidon::Cbpp::LowLevelClient {
public:
	static boost::shared_ptr<FetchClient> get();
	static boost::shared_ptr<FetchClient> require();

private:
	FetchClient(const Poseidon::IpPort &addr, boost::uint64_t keepAliveTimeout, bool useSsl);
	~FetchClient();

protected:
	void onLowLevelResponse(boost::uint16_t messageId, boost::uint64_t payloadLen) OVERRIDE;
	void onLowLevelPayload(boost::uint64_t payloadOffset, Poseidon::StreamBuffer payload) OVERRIDE;

	void onLowLevelError(boost::uint16_t messageId, Poseidon::Cbpp::StatusCode statusCode, std::string reason) OVERRIDE;

public:
	bool send(boost::uint16_t messageId, Poseidon::StreamBuffer plain);

	template<class MsgT>
	bool send(const MsgT &msg){
		return send(MsgT::ID, Poseidon::StreamBuffer(msg));
	}

	bool sendControl(Poseidon::Cbpp::ControlCode controlCode, boost::int64_t intParam, std::string strParam);
};

}

#endif
