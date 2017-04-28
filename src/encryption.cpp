#include "precompiled.hpp"
#include "encryption.hpp"
#include <poseidon/sha256.hpp>
#include <poseidon/endian.hpp>
#include <poseidon/random.hpp>
#include <openssl/aes.h>

namespace Medusa {

void encrypt(Poseidon::StreamBuffer &dst, const Poseidon::Uuid &uuid, Poseidon::StreamBuffer src, const std::string &key){
	PROFILE_ME;

	dst.put(uuid.data(), uuid.size()); // 16 bytes: UUID
	boost::uint64_t nonce_remainder_be;
	Poseidon::store_be(nonce_remainder_be, (Poseidon::random_uint64() << 4) | (src.size() & 0x0F));
	dst.put(&nonce_remainder_be, sizeof(nonce_remainder_be)); // 8 bytes: nonce and number of bytes in the last block
	Poseidon::Sha256_ostream sha256_os;
	sha256_os.write(reinterpret_cast<const char *>(uuid.data()), static_cast<std::streamsize>(uuid.size()))
	         .write(reinterpret_cast<const char *>(&nonce_remainder_be), static_cast<std::streamsize>(sizeof(nonce_remainder_be)))
	         .write(reinterpret_cast<const char *>(key.data()), static_cast<std::streamsize>(key.size()));
	const AUTO(sha256, sha256_os.finalize());
	::AES_KEY aes_key[1];
	if(::AES_set_encrypt_key(sha256.data() + 16, 128, aes_key) != 0){
		LOG_MEDUSA_FATAL("::AES_set_encrypt_key() failed!");
		std::abort();
	}
	boost::array<unsigned char, 16> iv, block_dst, block_src;
	std::memset(iv.data(), 0xCC, iv.size());
	std::memcpy(block_src.data(), uuid.data(), block_src.size());
	::AES_cbc_encrypt(block_src.data(), block_dst.data(), block_src.size(), aes_key, iv.data(), AES_ENCRYPT);
	dst.put(block_dst.data(), 16); // 16 bytes: checksum
	for(;;){
		const AUTO(block_plain_len, src.get(block_src.data(), 16));
		if(block_plain_len == 0){
			break;
		}
		::AES_cbc_encrypt(block_src.data(), block_dst.data(), block_plain_len, aes_key, iv.data(), AES_ENCRYPT);
		dst.put(block_dst.data(), block_dst.size()); // *: encrypted data
	}
}
bool decrypt(Poseidon::Uuid &uuid, Poseidon::StreamBuffer &dst, Poseidon::StreamBuffer src, const std::string &key){
	PROFILE_ME;

	if(src.get(uuid.data(), uuid.size()) < 16){ // 16 bytes: UUID
		LOG_MEDUSA_WARNING("Encrypted data is truncated, expecting UUID.");
		return false;
	}
	boost::uint64_t nonce_remainder_be;
	if(src.get(&nonce_remainder_be, sizeof(nonce_remainder_be)) < 8){ // 8 bytes: nonce and number of bytes in the last block
		LOG_MEDUSA_WARNING("Encrypted data is truncated, expecting nonce and number of bytes in the last block.");
		return false;
	}
	Poseidon::Sha256_ostream sha256_os;
	sha256_os.write(reinterpret_cast<const char *>(uuid.data()), static_cast<std::streamsize>(uuid.size()))
	         .write(reinterpret_cast<const char *>(&nonce_remainder_be), static_cast<std::streamsize>(sizeof(nonce_remainder_be)))
	         .write(reinterpret_cast<const char *>(key.data()), static_cast<std::streamsize>(key.size()));
	const AUTO(sha256, sha256_os.finalize());
	boost::array<unsigned char, 16> checksum;
	if(src.get(checksum.data(), checksum.size()) < 16){ // 16 bytes: first half of checksum
		LOG_MEDUSA_WARNING("Encrypted data is truncated, expecting first half of checksum.");
		return false;
	}
	::AES_KEY aes_key[1];
	if(::AES_set_decrypt_key(sha256.data() + 16, 128, aes_key) != 0){
		LOG_MEDUSA_FATAL("::AES_set_decrypt_key() failed!");
		std::abort();
	}
	boost::array<unsigned char, 16> iv, block_dst, block_src;
	std::memset(iv.data(), 0xCC, iv.size());
	std::memcpy(block_src.data(), checksum.data(), block_src.size());
	::AES_cbc_encrypt(block_src.data(), block_dst.data(), block_src.size(), aes_key, iv.data(), AES_DECRYPT);
	if(std::memcmp(block_dst.data(), uuid.data(), 16) != 0){
		LOG_MEDUSA_WARNING("Encrypted data is invalid, checksum failure.");
		return false;
	}
	for(;;){
		const AUTO(block_encrypted_len, src.get(block_src.data(), 16));
		if(block_encrypted_len == 0){
			break;
		}
		::AES_cbc_encrypt(block_src.data(), block_dst.data(), block_encrypted_len, aes_key, iv.data(), AES_DECRYPT);
		dst.put(block_dst.data(), block_dst.size()); // *: encrypted data
	}
	for(unsigned remainder = -Poseidon::load_be(nonce_remainder_be) & 0x0F; remainder != 0; --remainder){
		dst.unput();
	}
	return true;
}

}
