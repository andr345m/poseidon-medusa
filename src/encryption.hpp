#ifndef MEDUSA_ENCRYPTION_HPP_
#define MEDUSA_ENCRYPTION_HPP_

#include <poseidon/stream_buffer.hpp>
#include <poseidon/uuid.hpp>
#include <string>

namespace Medusa {

extern void encrypt(Poseidon::StreamBuffer &dst, const Poseidon::Uuid &uuid, Poseidon::StreamBuffer src, const std::string &key);
extern bool decrypt(Poseidon::Uuid &uuid, Poseidon::StreamBuffer &dst, Poseidon::StreamBuffer src, const std::string &key);

}

#endif
