#include "precompiled.hpp"
#include "encryption.hpp"
#include <poseidon/sha256.hpp>
#include <poseidon/endian.hpp>
#include <openssl/aes.h>

namespace Medusa {

void encrypt(Poseidon::StreamBuffer &dst, const Poseidon::Uuid &uuid, Poseidon::StreamBuffer src, const std::string &key){
	PROFILE_ME;

	dst.put(uuid.data(), uuid.size()); // 16 bytes: UUID
	boost::uint64_t length_be;
	const std::size_t plain_size = src.size();
	Poseidon::store_be(length_be, plain_size);
	dst.put(&length_be, sizeof(length_be)); // 8 bytes: length of plaintext
	Poseidon::Sha256_ostream sha256_os;
	sha256_os.write(reinterpret_cast<const char *>(uuid.data()), static_cast<std::streamsize>(uuid.size()))
	         .write(reinterpret_cast<const char *>(&length_be), static_cast<std::streamsize>(sizeof(length_be)))
	         .write(reinterpret_cast<const char *>(key.data()), static_cast<std::streamsize>(key.size()));
	const AUTO(sha256, sha256_os.finalize());
	dst.put(sha256.data(), 16); // 16 bytes: first half of checksum
	::AES_KEY aes_key[1];
	if(::AES_set_encrypt_key(sha256.data() + 16, 128, aes_key) != 0){
		LOG_MEDUSA_FATAL("::AES_set_encrypt_key() failed!");
		std::abort();
	}
	boost::array<unsigned char, 16> iv, block_dst, block_src;
	std::memcpy(iv.data(), uuid.data(), 16);
	std::memset(block_src.data(), 0, block_src.size());
	for(;;){
		const AUTO(block_plain_len, src.get(block_src.data(), 16));
		if(block_plain_len == 0){
			break;
		}
		::AES_cbc_encrypt(block_src.data(), block_dst.data(), block_plain_len, aes_key, iv.data(), AES_ENCRYPT);
		const AUTO(block_encrypted_len, block_dst.size());
		dst.put(block_dst.data(), block_encrypted_len); // *: encrypted data
	}
}
bool decrypt(Poseidon::Uuid &uuid, Poseidon::StreamBuffer &dst, Poseidon::StreamBuffer src, const std::string &key){
	PROFILE_ME;

	if(src.get(uuid.data(), uuid.size()) < 16){ // 16 bytes: UUID
		LOG_MEDUSA_WARNING("Encrypted data is truncated, expecting UUID.");
		return false;
	}
	boost::uint64_t length_be;
	if(src.get(&length_be, sizeof(length_be)) < 8){ // 8 bytes: length of plaintext
		LOG_MEDUSA_WARNING("Encrypted data is truncated, expecting length of plaintext.");
		return false;
	}
	const std::size_t plain_size = Poseidon::load_be(length_be);
	std::size_t plain_size_remaining = plain_size;
	Poseidon::Sha256_ostream sha256_os;
	sha256_os.write(reinterpret_cast<const char *>(uuid.data()), static_cast<std::streamsize>(uuid.size()))
	         .write(reinterpret_cast<const char *>(&length_be), static_cast<std::streamsize>(sizeof(length_be)))
	         .write(reinterpret_cast<const char *>(key.data()), static_cast<std::streamsize>(key.size()));
	const AUTO(sha256, sha256_os.finalize());
	boost::array<unsigned char, 16> checksum;
	if(src.get(checksum.data(), checksum.size()) < 16){ // 16 bytes: first half of checksum
		LOG_MEDUSA_WARNING("Encrypted data is truncated, expecting first half of checksum.");
		return false;
	}
	if(std::memcmp(sha256.data(), checksum.data(), 16) != 0){
		LOG_MEDUSA_WARNING("Encrypted data is invalid, checksum failure.");
		return false;
	}
	::AES_KEY aes_key[1];
	if(::AES_set_decrypt_key(sha256.data() + 16, 128, aes_key) != 0){
		LOG_MEDUSA_FATAL("::AES_set_decrypt_key() failed!");
		std::abort();
	}
	boost::array<unsigned char, 16> iv, block_dst, block_src;
	std::memcpy(iv.data(), uuid.data(), 16);
	std::memset(block_src.data(), 0, block_src.size());
	while(plain_size_remaining != 0){
		const AUTO(block_encrypted_len, src.get(block_src.data(), 16));
		if(block_encrypted_len == 0){
			LOG_MEDUSA_WARNING("Encrypted data is truncated, leaving out ", plain_size_remaining, " byte(s) of plaintext.");
			return false;
		}
		::AES_cbc_encrypt(block_src.data(), block_dst.data(), block_encrypted_len, aes_key, iv.data(), AES_DECRYPT);
		const AUTO(block_plain_len, std::min(plain_size_remaining, block_dst.size()));
		plain_size_remaining -= block_plain_len;
		dst.put(block_dst.data(), block_plain_len); // *: encrypted data
	}
	return true;
}

}
