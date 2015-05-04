#include "precompiled.hpp"
#include "encryption.hpp"
#include <poseidon/random.hpp>
#include <poseidon/hash.hpp>

namespace Medusa {

std::string generateNonce(){
	std::string ret;
	ret.resize(Poseidon::rand32(16, 32));
	for(AUTO(it, ret.begin()); it != ret.end(); ++it){
		*it = static_cast<char>(Poseidon::rand32());
	}
	return ret;
}

std::string encrypt(std::string data, const std::string &key, const std::string &nonce){
	unsigned char box[32];
	const std::string noncedKey(key + nonce);
	Poseidon::sha256Sum(box, noncedKey.data(), noncedKey.size());

	for(std::size_t i = 0; i < data.size(); ++i){
		AUTO_REF(byte, reinterpret_cast<unsigned char &>(data[i]));
		AUTO_REF(mask, box[i & 0x1F]);
		byte ^= mask;
		AUTO_REF(xchg, box[byte >> 3]);
		std::swap(mask, xchg);
	}
	return STD_MOVE(data);
}
std::string decrypt(std::string data, const std::string &key, const std::string &nonce){
	unsigned char box[32];
	const std::string noncedKey(key + nonce);
	Poseidon::sha256Sum(box, noncedKey.data(), noncedKey.size());

	for(std::size_t i = 0; i < data.size(); ++i){
		AUTO_REF(byte, reinterpret_cast<unsigned char &>(data[i]));
		AUTO_REF(mask, box[i & 0x1F]);
		AUTO_REF(xchg, box[byte >> 3]);
		byte ^= mask;
		std::swap(mask, xchg);
	}
	return STD_MOVE(data);
}

}
