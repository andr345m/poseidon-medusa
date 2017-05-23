#include "precompiled.hpp"
#include "encryption.hpp"
#include <poseidon/sha256.hpp>
#include <poseidon/random.hpp>
#include <openssl/aes.h>

namespace Medusa {

void encrypt(Poseidon::StreamBuffer &dst, const Poseidon::Uuid &uuid, Poseidon::StreamBuffer src, const std::string &key){
	PROFILE_ME;

	dst.put(uuid.data(), 16); // 16 bytes: UUID
	boost::uint64_t nonce;
	nonce = Poseidon::random_uint64();
	dst.put(&nonce, 8); // 8 bytes: nonce
	Poseidon::Sha256_ostream sha256_os;
	sha256_os.write(reinterpret_cast<const char *>(uuid.data()), 16)
	         .write(reinterpret_cast<const char *>(&nonce), 8)
	         .write(reinterpret_cast<const char *>(key.data()), static_cast<std::streamsize>(key.size()));
	const AUTO(sha256, sha256_os.finalize());
	::AES_KEY aes_key[1];
	if(::AES_set_encrypt_key(sha256.data(), 128, aes_key) != 0){
		LOG_MEDUSA_FATAL("::AES_set_encrypt_key() failed!");
		std::abort();
	}
	unsigned char out[16], in[16], iv[16], ecount_buf[16];
	unsigned num;
	std::memset(iv, 42, 16);
	std::memset(ecount_buf, 0, 16);
	num = 0;
	::AES_ctr128_encrypt(sha256.data() + 16, out, 16, aes_key, iv, ecount_buf, &num);
	assert(num == 0);
	dst.put(out, 16); // 16 bytes: checksum
	for(;;){
		const unsigned n = src.get(in, 16);
		if(n == 0){
			break;
		}
		::AES_ctr128_encrypt(in, out, n, aes_key, iv, ecount_buf, &num);
		dst.put(out, n);
	}
}
bool decrypt(Poseidon::Uuid &uuid, Poseidon::StreamBuffer &dst, Poseidon::StreamBuffer src, const std::string &key){
	PROFILE_ME;

	if(src.get(uuid.data(), 16) < 16){ // 16 bytes: UUID
		LOG_MEDUSA_WARNING("Encrypted data is truncated, expecting UUID.");
		return false;
	}
	boost::uint64_t nonce;
	if(src.get(&nonce, 8) < 8){ // 8 bytes: nonce
		LOG_MEDUSA_WARNING("Encrypted data is truncated, expecting nonce.");
		return false;
	}
	Poseidon::Sha256_ostream sha256_os;
	sha256_os.write(reinterpret_cast<const char *>(uuid.data()), 16)
	         .write(reinterpret_cast<const char *>(&nonce), 8)
	         .write(reinterpret_cast<const char *>(key.data()), static_cast<std::streamsize>(key.size()));
	const AUTO(sha256, sha256_os.finalize());
	::AES_KEY aes_key[1];
	if(::AES_set_encrypt_key(sha256.data(), 128, aes_key) != 0){
		LOG_MEDUSA_FATAL("::AES_set_encrypt_key() failed!");
		std::abort();
	}
	unsigned char out[16], in[16], iv[16], ecount_buf[16];
	unsigned num;
	if(src.get(in, 16) < 16){ // 16 bytes: checksum
		LOG_MEDUSA_WARNING("Encrypted data is truncated, expecting checksum.");
		return false;
	}
	std::memset(iv, 42, 16);
	std::memset(ecount_buf, 0, 16);
	num = 0;
	::AES_ctr128_encrypt(in, out, 16, aes_key, iv, ecount_buf, &num);
	assert(num == 0);
	if(std::memcmp(out, sha256.data() + 16, 16) != 0){
		LOG_MEDUSA_WARNING("Encrypted data is invalid, erroneous checksum.");
		return false;
	}
	for(;;){
		const unsigned n = src.get(in, 16);
		if(n == 0){
			break;
		}
		::AES_ctr128_encrypt(in, out, n, aes_key, iv, ecount_buf, &num);
		dst.put(out, n);
	}
	return true;
}

}
