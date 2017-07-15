#include "precompiled.hpp"
#include "encryption.hpp"
#include <poseidon/sha256.hpp>
#include <poseidon/random.hpp>
#include <openssl/aes.h>

namespace Medusa {

namespace {
	void aes_ctr_gen(boost::uint8_t *mask, const boost::uint8_t *nonce, boost::uint64_t *cnt, const ::AES_KEY *key){
		boost::uint8_t temp[16];
		boost::uint64_t word = ++*cnt;
		for(unsigned i = 0; i < 16; ++i){
			temp[i] = nonce[i] ^ (boost::uint8_t)word;
			word = (word << 56) | (word >> 8);
		}
		::AES_encrypt(temp, mask, key);
	}
	void aes_ctr_xor(boost::uint8_t *out, const boost::uint8_t *mask, const boost::uint8_t *in){
		for(unsigned i = 0; i < 16; ++i){
			out[i] = mask[i] ^ in[i];
		}
	}
}

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
	::AES_KEY aes_key;
	if(::AES_set_encrypt_key(sha256.data(), 128, &aes_key) != 0){
		LOG_MEDUSA_FATAL("::AES_set_encrypt_key() failed!");
		std::abort();
	}
	boost::uint8_t out[16], in[16], mask[16];
	boost::uint64_t cnt = 0;
	aes_ctr_gen(mask, sha256.data(), &cnt, &aes_key);
	aes_ctr_xor(out, mask, sha256.data() + 16);
	dst.put(out, 16); // 16 bytes: checksum
	for(;;){
		const unsigned n = src.get(in, 16);
		if(n == 0){
			break;
		}
		aes_ctr_gen(mask, sha256.data(), &cnt, &aes_key);
		aes_ctr_xor(out, mask, in);
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
	::AES_KEY aes_key;
	if(::AES_set_encrypt_key(sha256.data(), 128, &aes_key) != 0){
		LOG_MEDUSA_FATAL("::AES_set_encrypt_key() failed!");
		std::abort();
	}
	boost::uint8_t out[16], in[16], mask[16];
	if(src.get(in, 16) < 16){ // 16 bytes: checksum
		LOG_MEDUSA_WARNING("Encrypted data is truncated, expecting checksum.");
		return false;
	}
	boost::uint64_t cnt = 0;
	aes_ctr_gen(mask, sha256.data(), &cnt, &aes_key);
	aes_ctr_xor(out, mask, in);
	if(std::memcmp(out, sha256.data() + 16, 16) != 0){
		LOG_MEDUSA_WARNING("Encrypted data is invalid, erroneous checksum.");
		return false;
	}
	for(;;){
		const unsigned n = src.get(in, 16);
		if(n == 0){
			break;
		}
		aes_ctr_gen(mask, sha256.data(), &cnt, &aes_key);
		aes_ctr_xor(out, mask, in);
		dst.put(out, n);
	}
	return true;
}

}
