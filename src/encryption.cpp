#include "precompiled.hpp"
#include "encryption.hpp"
#include <poseidon/hash.hpp>
#include <poseidon/endian.hpp>

namespace Medusa {

namespace {
	void makeBox(unsigned char (&box)[32], std::string key, boost::uint64_t nonce){
		boost::uint64_t nonceBe;
		Poseidon::storeBe(nonceBe, nonce & ((boost::uint64_t)-1) >> 16);
		key.append((const char *)&nonceBe, sizeof(nonceBe));
		Poseidon::sha256Sum(box, key.data(), key.size());
	}
}

Poseidon::StreamBuffer encryptBuffer(Poseidon::StreamBuffer data, const std::string &key, boost::uint64_t nonce){
	unsigned char box[32];
	makeBox(box, key, nonce);

	Poseidon::StreamBuffer ret;
	unsigned i = 0;
	for(;;){
		const int c = data.get();
		if(c < 0){
			break;
		}

		unsigned byte = static_cast<boost::uint8_t>(c);
		AUTO_REF(mask, box[i & 0x1F]);
		byte ^= mask;
		AUTO_REF(xchg, box[byte >> 3]);

		std::swap(mask, xchg);
		++i;
		ret.put(byte);
	}
	return ret;
}
Poseidon::StreamBuffer decryptBuffer(Poseidon::StreamBuffer data, const std::string &key, boost::uint64_t nonce){
	unsigned char box[32];
	makeBox(box, key, nonce);

	Poseidon::StreamBuffer ret;
	unsigned i = 0;
	for(;;){
		const int c = data.get();
		if(c < 0){
			break;
		}

		unsigned byte = static_cast<boost::uint8_t>(c);
		AUTO_REF(mask, box[i & 0x1F]);
		AUTO_REF(xchg, box[byte >> 3]);
		byte ^= mask;

		std::swap(mask, xchg);
		++i;
		ret.put(byte);
	}
	return ret;
}

}
