#include "precompiled.hpp"
#include "encryption.hpp"
#include <poseidon/random.hpp>
#include <poseidon/hash.hpp>

namespace Medusa {

namespace {
	class TinyEncryptorBase {
	protected:
		unsigned char m_box[32];
		unsigned m_idx;

	protected:
		TinyEncryptorBase(const std::string &key, const std::string &nonce){
			unsigned char keyHash[32], nonceHash[32];
			Poseidon::sha256Sum(keyHash, key.data(), key.size());
			Poseidon::sha256Sum(nonceHash, nonce.data(), nonce.size());

			for(unsigned i = 0; i < 32; ++i){
				m_box[i] = keyHash[i] ^ nonceHash[i];
			}
			m_idx = 0;
		}
	};

	class TinyEncryptor : private TinyEncryptorBase {
	public:
		TinyEncryptor(const std::string &key, const std::string &nonce)
			: TinyEncryptorBase(key, nonce)
		{
		}

	public:
		unsigned encryptByte(unsigned char byte){
			AUTO_REF(mask, m_box[m_idx++ & 0x1F]);
			byte ^= mask;
			AUTO_REF(xchg, m_box[byte >> 3]);
			std::swap(mask, xchg);
			return byte;
		}
	};
	class TinyDecryptor : private TinyEncryptorBase {
	public:
		TinyDecryptor(const std::string &key, const std::string &nonce)
			: TinyEncryptorBase(key, nonce)
		{
		}

	public:
		unsigned decryptByte(unsigned char byte){
			AUTO_REF(mask, m_box[m_idx++ & 0x1F]);
			AUTO_REF(xchg, m_box[byte >> 3]);
			byte ^= mask;
			std::swap(mask, xchg);
			return byte;
		}
	};
}

std::string generateRandomBytes(unsigned lenMin, unsigned lenDelta){
	PROFILE_ME;

	std::string ret;
	ret.resize(lenMin + Poseidon::rand32() % lenDelta);
	for(AUTO(it, ret.begin()); it != ret.end(); ++it){
		*it = static_cast<char>(Poseidon::rand32());
	}
	return ret;
}

std::string encrypt(std::string data, const std::string &key, const std::string &nonce){
	PROFILE_ME;

	TinyEncryptor enc(key, nonce);
	for(std::size_t i = 0; i < data.size(); ++i){
		AUTO_REF(byte, reinterpret_cast<unsigned char &>(data[i]));
		byte = enc.encryptByte(byte);
	}
	return STD_MOVE(data);
}
std::string decrypt(std::string data, const std::string &key, const std::string &nonce){
	PROFILE_ME;

	TinyDecryptor dec(key, nonce);
	for(std::size_t i = 0; i < data.size(); ++i){
		AUTO_REF(byte, reinterpret_cast<unsigned char &>(data[i]));
		byte = dec.decryptByte(byte);
	}
	return STD_MOVE(data);
}

Poseidon::StreamBuffer encrypt(Poseidon::StreamBuffer data, const std::string &key, const std::string &nonce){
	PROFILE_ME;

	TinyEncryptor enc(key, nonce);
	Poseidon::StreamBuffer ret;
	int c;
	while((c = data.get()) >= 0){
		const AUTO(byte, static_cast<unsigned char>(c));
		ret.put(enc.encryptByte(byte));
	}
	return ret;
}
Poseidon::StreamBuffer decrypt(Poseidon::StreamBuffer data, const std::string &key, const std::string &nonce){
	PROFILE_ME;

	TinyDecryptor dec(key, nonce);
	Poseidon::StreamBuffer ret;
	int c;
	while((c = data.get()) >= 0){
		const AUTO(byte, static_cast<unsigned char>(c));
		ret.put(dec.decryptByte(byte));
	}
	return ret;
}

}
