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
	// Encrypt payload.
	const std::size_t n_blocks_m1 = (src.size() + 1) / 16;
	for(std::size_t i = 0; i < n_blocks_m1; ++i){
		DEBUG_THROW_ASSERT(src.get(block_src.data(), 16) == 16);
		::AES_cbc_encrypt(block_src.data(), block_dst.data(), 16, aes_key, iv.data(), AES_ENCRYPT);
		dst.put(block_dst.data(), 16);
	}
	// Append PKCS#7 padding.
	const unsigned bytes_padded = 16 - src.get(block_src.data(), 16);
	LOG_MEDUSA_DEBUG("Appending ", bytes_padded, " padding byte(s).");
	std::memset(block_src.data() + bytes_padded, static_cast<int>(bytes_padded), bytes_padded);
	::AES_cbc_encrypt(block_src.data(), block_dst.data(), 16, aes_key, iv.data(), AES_ENCRYPT);
	dst.put(block_dst.data(), 16);
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
	// Decrypt payload.
	if(src.size() % 16 != 0){
		LOG_MEDUSA_WARNING("Encrypted data is invalid, invalid size.");
		return false;
	}
	const std::size_t n_blocks_m1 = src.size() / 16 - 1;
	if(n_blocks_m1 == (std::size_t)-1){
		LOG_MEDUSA_WARNING("Encrypted data is invalid, final block not found.");
		return false;
	}
	for(std::size_t i = 0; i < n_blocks_m1; ++i){
		DEBUG_THROW_ASSERT(src.get(block_src.data(), 16) == 16);
		::AES_cbc_encrypt(block_src.data(), block_dst.data(), 16, aes_key, iv.data(), AES_DECRYPT);
		dst.put(block_dst.data(), 16);
	}
	// Remove PKCS#7 padding.
	DEBUG_THROW_ASSERT(src.get(block_src.data(), 16) == 16);
	::AES_cbc_encrypt(block_src.data(), block_dst.data(), 16, aes_key, iv.data(), AES_DECRYPT);
	const unsigned bytes_padded = block_dst.back();
	LOG_MEDUSA_DEBUG("Removing ", bytes_padded, " padding byte(s).");
	DEBUG_THROW_ASSERT((1 <= bytes_padded) && (bytes_padded <= 16));
	dst.put(block_dst.data(), 16 - bytes_padded);
	return true;
}

}
