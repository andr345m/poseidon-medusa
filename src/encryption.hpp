#ifndef MEDUSA_ENCRYPTION_HPP_
#define MEDUSA_ENCRYPTION_HPP_

#include <cstddef>
#include <string>
#include <boost/scoped_ptr.hpp>
#include <poseidon/uuid.hpp>
#include <poseidon/stream_buffer.hpp>

namespace Medusa {

// 用于保存加密器状态。
struct EncryptionContext {
	Poseidon::Uuid uuid;
	unsigned i, j;
	unsigned char s[256];
};

typedef boost::scoped_ptr<EncryptionContext> EncryptionContextPtr;

extern std::size_t getEncryptedHeaderSize();

// 返回头部数据，其大小等于 getEncryptedHeaderSize() 的值。
// 同时生成一个新的可以用于后续加密数据的 EncryptionContext。
extern Poseidon::StreamBuffer encryptHeader(EncryptionContextPtr &context, const Poseidon::Uuid &uuid, const std::string &key);
extern Poseidon::StreamBuffer encryptPayload(const EncryptionContextPtr &context, Poseidon::StreamBuffer plain);

// 如果 data 的大小不够 getEncryptedHeaderSize() 会抛出异常，如果校验和不正确返回 false。
// 同时生成一个新的可以用于后续解密数据的 EncryptionContext。
extern bool tryDecryptHeader(EncryptionContextPtr &context, const std::string &key, const Poseidon::StreamBuffer &encrypted);
extern Poseidon::StreamBuffer decryptPayload(const EncryptionContextPtr &context, Poseidon::StreamBuffer encrypted);

}

#endif
