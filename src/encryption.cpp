#include "precompiled.hpp"
#include "encryption.hpp"
#include <poseidon/hash.hpp>
#include <poseidon/random.hpp>
#include <poseidon/string.hpp>

namespace Medusa {

namespace {
	struct EncryptedHeader {
		unsigned char uuid[16];
		unsigned char nonce[16];
		unsigned char md5[16];
	};

	void makeNoncedKey(unsigned char (&ret)[32], const unsigned char (&nonce)[16], const std::string &key){
		PROFILE_ME;

		AUTO(noncedKey, reinterpret_cast<unsigned char (&)[2][16]>(ret));
		std::memcpy(noncedKey[0], nonce, 16);
		Poseidon::md5Sum(noncedKey[1], key.data(), key.size());
	}

	// http://en.wikipedia.org/wiki/RC4 有改动。

	void createContext(boost::scoped_ptr<EncryptionContext> &ret, const Poseidon::Uuid &uuid, const unsigned char (&noncedKey)[32]){
		PROFILE_ME;

		boost::scoped_ptr<EncryptionContext> ctx(new EncryptionContext);

		ctx->uuid = uuid;
		ctx->i = 0;
		ctx->j = 0;

		for(unsigned i = 0; i < 256; ++i){
			ctx->s[i] = i;
		}
		unsigned i = 0, j = 0;
		while(i < 256){
			unsigned tmp;

#define GEN_S(k_)	\
			tmp = ctx->s[i];	\
			j = (j + tmp + (k_)) & 0xFF;	\
			ctx->s[i] = ctx->s[j];	\
			ctx->s[j] = tmp;	\
			++i;

			for(unsigned r = 0; r < 16; ++r){
				GEN_S(uuid[r]);
			}
			for(unsigned r = 0; r < 32; ++r){
				GEN_S(noncedKey[r]);
			}
			for(unsigned r = 0; r < 16; ++r){
				GEN_S(uuid[r]);
			}
		}

		ret.swap(ctx);
	}
	void encryptBytes(EncryptionContext *ctx, unsigned char *data, std::size_t size){
		PROFILE_ME;

		for(std::size_t i = 0; i < size; ++i){
			unsigned byte = data[i];

			// ctx->i = (ctx->i + 1) & 0xFF;
			const unsigned k1 = ctx->s[ctx->i];
			ctx->j = (ctx->j + k1) & 0xFF;
			const unsigned k2 = ctx->s[ctx->j];
			ctx->s[ctx->i] = k2;
			ctx->s[ctx->j] = k1;
			ctx->i = (ctx->i + (byte | 0x0F)) & 0xFF; // RC4 改。
			byte ^= k1 + k2;
			data[i] = byte;
		}
	}
	void decryptBytes(EncryptionContext *ctx, unsigned char *data, std::size_t size){
		PROFILE_ME;

		for(std::size_t i = 0; i < size; ++i){
			unsigned byte = data[i];
			// ctx->i = (ctx->i + 1) & 0xFF;
			const unsigned k1 = ctx->s[ctx->i];
			ctx->j = (ctx->j + k1) & 0xFF;
			const unsigned k2 = ctx->s[ctx->j];
			ctx->s[ctx->i] = k2;
			ctx->s[ctx->j] = k1;
			byte ^= k1 + k2;
			ctx->i = (ctx->i + (byte | 0x0F)) & 0xFF; // RC4 改。
			data[i] = byte;
		}
	}
}

std::size_t getEncryptedHeaderSize(){
	return sizeof(EncryptedHeader);
}

Poseidon::StreamBuffer encryptHeader(EncryptionContextPtr &context, const Poseidon::Uuid &uuid, const std::string &key){
	PROFILE_ME;

	EncryptedHeader header;
	std::memcpy(header.uuid, uuid.data(), uuid.size());
	for(unsigned i = 0; i < 16; ++i){
		header.nonce[i] = Poseidon::rand32();
	}
	unsigned char noncedKey[32];
	makeNoncedKey(noncedKey, header.nonce, key);
	Poseidon::md5Sum(header.md5, noncedKey, sizeof(noncedKey));

	Poseidon::StreamBuffer ret(&header, sizeof(header));
	createContext(context, uuid, noncedKey);
	return ret;
}
Poseidon::StreamBuffer encryptPayload(const EncryptionContextPtr &context, Poseidon::StreamBuffer plain){
	PROFILE_ME;

	struct Helper {
		static bool callback(void *context, void *data, std::size_t size){
			encryptBytes(static_cast<EncryptionContext *>(context), static_cast<unsigned char *>(data), size);
			return true;
		}
	};

	Poseidon::StreamBuffer ret(STD_MOVE(plain));
	ret.traverse(&Helper::callback, context.get());
	return ret;
}

bool tryDecryptHeader(EncryptionContextPtr &context, const std::string &key, const Poseidon::StreamBuffer &encrypted){
	PROFILE_ME;

	const AUTO(headerSize, getEncryptedHeaderSize());
	if(encrypted.size() < headerSize){
		LOG_MEDUSA_ERROR("No enough data provided, expecting at least ", headerSize, " bytes.");
		DEBUG_THROW(Exception, SSLIT("No enough data provided"));
	}

	EncryptedHeader header;
	encrypted.peek(&header, sizeof(header));
	unsigned char noncedKey[32];
	makeNoncedKey(noncedKey, header.nonce, key);
	unsigned char md5[16];
	Poseidon::md5Sum(md5, noncedKey, sizeof(noncedKey));
	if(std::memcmp(md5, header.md5, 16) != 0){
		using Poseidon::HexDumper;
		LOG_MEDUSA_DEBUG("Unexpected MD5: expecting ", HexDumper(md5, 16), ", got ", HexDumper(header.md5, 16));
		return false;
	}
	createContext(context, Poseidon::Uuid(header.uuid), noncedKey);
	return true;
}
Poseidon::StreamBuffer decryptPayload(const EncryptionContextPtr &context, Poseidon::StreamBuffer encrypted){
	PROFILE_ME;

	struct Helper {
		static bool callback(void *context, void *data, std::size_t size){
			decryptBytes(static_cast<EncryptionContext *>(context), static_cast<unsigned char *>(data), size);
			return true;
		}
	};

	Poseidon::StreamBuffer ret(STD_MOVE(encrypted));
	ret.traverse(&Helper::callback, context.get());
	return ret;
}

}
