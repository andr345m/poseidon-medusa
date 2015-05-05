#ifndef MEDUSA_ENCRYPTION_HPP_
#define MEDUSA_ENCRYPTION_HPP_

#include <string>
#include <poseidon/stream_buffer.hpp>

namespace Medusa {

extern std::string generateNonce(unsigned lenMin = 16, unsigned lenDelta = 16);

extern std::string encrypt(std::string data, const std::string &key, const std::string &nonce);
extern std::string decrypt(std::string data, const std::string &key, const std::string &nonce);

extern Poseidon::StreamBuffer encrypt(Poseidon::StreamBuffer data, const std::string &key, const std::string &nonce);
extern Poseidon::StreamBuffer decrypt(Poseidon::StreamBuffer data, const std::string &key, const std::string &nonce);

}

#endif
