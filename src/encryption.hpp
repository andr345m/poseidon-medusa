#ifndef MEDUSA_ENCRYPTION_HPP_
#define MEDUSA_ENCRYPTION_HPP_

#include <string>
#include <boost/cstdint.hpp>
#include <poseidon/stream_buffer.hpp>

namespace Medusa {

extern Poseidon::StreamBuffer encryptBuffer(Poseidon::StreamBuffer data, const std::string &key, boost::uint64_t nonce);
extern Poseidon::StreamBuffer decryptBuffer(Poseidon::StreamBuffer data, const std::string &key, boost::uint64_t nonce);

}

#endif
