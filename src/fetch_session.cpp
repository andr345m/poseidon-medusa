#include "precompiled.hpp"
#include "fetch_session.hpp"
#include "fetch_protocol.hpp"

namespace Medusa {

FetchSession::FetchSession(Poseidon::UniqueFile socket, std::string password)
	: Poseidon::Cbpp::Session(STD_MOVE(socket))
	, m_password(STD_MOVE(password))
{
}
FetchSession::~FetchSession(){
}

void FetchSession::onRequest(boost::uint16_t messageId, const Poseidon::StreamBuffer &payload){
}

}
