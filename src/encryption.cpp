#include "precompiled.hpp"
#include "encryption.hpp"
#include <poseidon/sha256.hpp>
#include <poseidon/random.hpp>
#include <openssl/aes.h>

namespace Medusa {

void encrypt(Poseidon::StreamBuffer &dst, const Poseidon::Uuid &uuid, Poseidon::StreamBuffer src, const std::string &key){
	PROFILE_ME;

	dst.put(uuid.data(), uuid.size()); // 16 bytes: UUID
	boost::uint64_t nonce;
	nonce = Poseidon::random_uint64();
	dst.put(&nonce, sizeof(nonce)); // 8 bytes: nonce
	Poseidon::Sha256_ostream sha256_os;
	sha256_os.write(reinterpret_cast<const char *>(uuid.data()), static_cast<std::streamsize>(uuid.size()))
	         .write(reinterpret_cast<const char *>(&nonce), static_cast<std::streamsize>(sizeof(nonce)))
	         .write(reinterpret_cast<const char *>(key.data()), static_cast<std::streamsize>(key.size()));
	const AUTO(sha256, sha256_os.finalize());
	::AES_KEY aes_key[1];
	if(::AES_set_encrypt_key(sha256.data(), 128, aes_key) != 0){
		LOG_MEDUSA_FATAL("::AES_set_encrypt_key() failed!");
		std::abort();
	}
	boost::array<unsigned char, 16> iv, block_dst, block_src;
	std::memset(iv.data(), 0xCC, 16);
	std::memcpy(block_src.data(), sha256.data() + 16, 16);
	::AES_cbc_encrypt(block_src.data(), block_dst.data(), 16, aes_key, iv.data(), AES_ENCRYPT);
	dst.put(block_dst.data(), 16); // 16 bytes: checksum
	for(;;){
		const AUTO(block_plain_len, src.get(block_src.data(), 16));
		if(block_plain_len < 16){
			// Append PKCS#7 padding.
			const unsigned bytes_padded = 16 - block_plain_len;
			for(unsigned i = 0; i < bytes_padded; ++i){
				block_src[block_plain_len + i] = bytes_padded;
			}
			::AES_cbc_encrypt(block_src.data(), block_dst.data(), block_plain_len, aes_key, iv.data(), AES_ENCRYPT);
			dst.put(block_dst.data(), 16); // *: final block encrypted
			break;
		}
		::AES_cbc_encrypt(block_src.data(), block_dst.data(), 16, aes_key, iv.data(), AES_ENCRYPT);
		dst.put(block_dst.data(), 16); // *: block encrypted
	}
}
bool decrypt(Poseidon::Uuid &uuid, Poseidon::StreamBuffer &dst, Poseidon::StreamBuffer src, const std::string &key){
	PROFILE_ME;

	if(src.get(uuid.data(), uuid.size()) < 16){ // 16 bytes: UUID
		LOG_MEDUSA_WARNING("Encrypted data is truncated, expecting UUID.");
		return false;
	}
	boost::uint64_t nonce;
	if(src.get(&nonce, sizeof(nonce)) < 8){ // 8 bytes: nonce and number of bytes in the last block
		LOG_MEDUSA_WARNING("Encrypted data is truncated, expecting nonce and number of bytes in the last block.");
		return false;
	}
	Poseidon::Sha256_ostream sha256_os;
	sha256_os.write(reinterpret_cast<const char *>(uuid.data()), static_cast<std::streamsize>(uuid.size()))
	         .write(reinterpret_cast<const char *>(&nonce), static_cast<std::streamsize>(sizeof(nonce)))
	         .write(reinterpret_cast<const char *>(key.data()), static_cast<std::streamsize>(key.size()));
	const AUTO(sha256, sha256_os.finalize());
	boost::array<unsigned char, 16> checksum;
	if(src.get(checksum.data(), checksum.size()) < 16){ // 16 bytes: checksum
		LOG_MEDUSA_WARNING("Encrypted data is truncated, expecting checksum.");
		return false;
	}
	::AES_KEY aes_key[1];
	if(::AES_set_decrypt_key(sha256.data(), 128, aes_key) != 0){
		LOG_MEDUSA_FATAL("::AES_set_decrypt_key() failed!");
		std::abort();
	}
	boost::array<unsigned char, 16> iv, block_dst, block_src;
	std::memset(iv.data(), 0xCC, 16);
	std::memcpy(block_src.data(), checksum.data(), 16);
	::AES_cbc_encrypt(block_src.data(), block_dst.data(), 16, aes_key, iv.data(), AES_DECRYPT);
	if(std::memcmp(block_dst.data(), sha256.data() + 16, 16) != 0){
		LOG_MEDUSA_WARNING("Encrypted data is invalid, erroneous checksum.");
		return false;
	}
	if((src.size() - 1) / 16 != src.size() / 16 - 1){ // (size % 16 != 0) || (size == 0)
		LOG_MEDUSA_WARNING("Encrypted data is invalid, invalid size.");
		return false;
	}
	for(;;){
		const AUTO(block_encrypted_len, src.get(block_src.data(), 16));
		if(block_encrypted_len < 16){
			// Remove PKCS#7 padding.
			DEBUG_THROW_ASSERT(block_encrypted_len == 0);
			DEBUG_THROW_ASSERT(!dst.empty());
			const unsigned bytes_padded = static_cast<unsigned>(dst.back());
			DEBUG_THROW_ASSERT((1 <= bytes_padded) && (bytes_padded <= 16));
			for(unsigned i = 0; i < bytes_padded; ++i){
				dst.unput();
			}
			break;
		}
		::AES_cbc_encrypt(block_src.data(), block_dst.data(), 16, aes_key, iv.data(), AES_DECRYPT);
		dst.put(block_dst.data(), 16); // *: block encrypted
	}
	return true;
}

}
