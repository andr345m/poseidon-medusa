#ifndef MEDUSA_ENCRYPTION_HPP_
#define MEDUSA_ENCRYPTION_HPP_

#include <string>
#include <utility>
#include <cstddef>
#include <boost/shared_ptr.hpp>
#include <poseidon/uuid.hpp>
#include <poseidon/stream_buffer.hpp>

namespace Medusa {

// 用于保存加密器状态。
struct EncryptionContext;

extern std::size_t getEncryptedHeaderSize();

// 返回头部数据，其大小等于 getEncryptedHeaderSize() 的值。
// 同时生成一个新的可以用于后续加密数据的 EncryptionContext。
extern std::pair<boost::shared_ptr<EncryptionContext>, Poseidon::StreamBuffer> encryptHeader(const Poseidon::Uuid &uuid, const std::string &key);
extern Poseidon::StreamBuffer encryptPayload(const boost::shared_ptr<EncryptionContext> &context, Poseidon::StreamBuffer plain);

// 如果 data 的大小不够 getEncryptedHeaderSize() 会抛出异常，如果校验和不正确返回空指针。
// 同时生成一个新的可以用于后续解密数据的 EncryptionContext。
extern boost::shared_ptr<EncryptionContext> tryDecryptHeader(const Poseidon::StreamBuffer &encrypted, const std::string &key);
extern Poseidon::StreamBuffer decryptPayload(const boost::shared_ptr<EncryptionContext> &context, Poseidon::StreamBuffer encrypted);

}

#endif
