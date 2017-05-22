#include "precompiled.hpp"
#include "encryption.hpp"
#include <poseidon/sha256.hpp>
#include <poseidon/random.hpp>
#include <openssl/aes.h>

namespace Medusa {

typedef boost::array<unsigned char, 16> AesBlock;

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
	AesBlock iv, in, out;
	int num = 0;
	std::fill(iv.begin(), iv.end(), 42);
	std::copy(sha256.begin() + 16, sha256.end(), in.begin());
	::AES_cfb128_encrypt(in.data(), out.data(), 16, aes_key, iv.data(), &num, AES_ENCRYPT);
	dst.put(out.data(), 16); // 16 bytes: checksum
	for(;;){
		const AUTO(bytes_read, src.get(in.data(), 16));
		if(bytes_read == 0){
			break;
		}
		::AES_cfb128_encrypt(in.data(), out.data(), bytes_read, aes_key, iv.data(), &num, AES_ENCRYPT);
		dst.put(out.data(), bytes_read);
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
	if(::AES_set_encrypt_key(sha256.data(), 128, aes_key) != 0){ // CFB 仅使用加密密钥。
		LOG_MEDUSA_FATAL("::AES_set_encrypt_key() failed!");
		std::abort();
	}
	AesBlock iv, in, out;
	int num = 0;
	std::fill(iv.begin(), iv.end(), 42);
	if(src.get(in.data(), 16) < 16){ // 16 bytes: checksum
		LOG_MEDUSA_WARNING("Encrypted data is truncated, expecting checksum.");
		return false;
	}
	::AES_cfb128_encrypt(in.data(), out.data(), 16, aes_key, iv.data(), &num, AES_DECRYPT);
	if(!std::equal(out.begin(), out.end(), sha256.begin() + 16)){
		LOG_MEDUSA_WARNING("Encrypted data is invalid, erroneous checksum.");
		return false;
	}
	for(;;){
		const AUTO(bytes_read, src.get(in.data(), 16));
		if(bytes_read == 0){
			break;
		}
		::AES_cfb128_encrypt(in.data(), out.data(), bytes_read, aes_key, iv.data(), &num, AES_DECRYPT);
		dst.put(out.data(), bytes_read);
	}
	return true;
}

}
