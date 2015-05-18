#include "precompiled.hpp"
#include "encryption.hpp"
#include <poseidon/hash.hpp>
#include <poseidon/random.hpp>
#include <poseidon/string.hpp>

namespace Medusa {

namespace {
	typedef boost::array<unsigned char, 16> Nonce;

	struct EncryptedHeader {
		Nonce nonce;
		Poseidon::Uuid uuid;
		Poseidon::Md5 authMd5;
	};

#ifdef POSEIDON_CXX11
	static_assert(std::is_standard_layout<EncryptedHeader>::value, "EncryptedHeader is not a standard-layout structe?");
	static_assert(sizeof(EncryptedHeader) == 48, "Incompatible layout detected");
#endif

	struct NoncedKey {
		Nonce nonce;
		Poseidon::Md5 keyMd5;

		explicit NoncedKey(const Nonce &nonce_, const std::string &key_)
			: nonce(nonce_), keyMd5(Poseidon::md5Hash(key_))
		{
		}
	};

#ifdef POSEIDON_CXX11
	static_assert(sizeof(NoncedKey) == 32, "Incompatible layout detected");
#endif

	// http://en.wikipedia.org/wiki/RC4 有改动。

	boost::shared_ptr<EncryptionContext> createContext(const Poseidon::Uuid &uuid, const NoncedKey &noncedKey){
		PROFILE_ME;

		AUTO(ret, boost::make_shared<EncryptionContext>());

		ret->uuid = uuid;
		ret->i = 0;
		ret->j = 0;

		for(unsigned i = 0; i < 256; ++i){
			ret->s[i] = i;
		}
		unsigned i = 0, j = 0;
		while(i < 256){
			unsigned tmp;

#define GEN_S(k_)	\
			tmp = ret->s[i];	\
			j = (j + tmp + (k_)) & 0xFF;	\
			ret->s[i] = ret->s[j];	\
			ret->s[j] = tmp;	\
			++i;

			for(unsigned r = 0; r < 16; ++r){
				GEN_S(noncedKey.nonce[r]);
			}
			for(unsigned r = 0; r < 16; ++r){
				GEN_S(uuid[r]);
			}
			for(unsigned r = 0; r < 16; ++r){
				GEN_S(noncedKey.keyMd5[r]);
			}
			for(unsigned r = 0; r < 16; ++r){
				GEN_S(uuid[r]);
			}
		}

		return ret;
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

std::pair<boost::shared_ptr<EncryptionContext>, Poseidon::StreamBuffer> encryptHeader(const Poseidon::Uuid &uuid, const std::string &key){
	PROFILE_ME;

	Nonce nonce;
	for(AUTO(it, nonce.begin()); it != nonce.end(); ++it){
		*it = Poseidon::rand32();
	}
	const NoncedKey noncedKey(nonce, key);
	AUTO(context, createContext(uuid, noncedKey));

	EncryptedHeader header;
	header.nonce = nonce;
	header.uuid = uuid;
	header.authMd5 = Poseidon::md5Hash(&noncedKey, sizeof(noncedKey));
	AUTO(encrypted, Poseidon::StreamBuffer(&header, sizeof(header)));

	return std::make_pair(STD_MOVE(context), STD_MOVE(encrypted));
}
Poseidon::StreamBuffer encryptPayload(const boost::shared_ptr<EncryptionContext> &context, Poseidon::StreamBuffer plain){
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

boost::shared_ptr<EncryptionContext> tryDecryptHeader(const Poseidon::StreamBuffer &encrypted, const std::string &key){
	PROFILE_ME;

	const AUTO(headerSize, getEncryptedHeaderSize());
	if(encrypted.size() < headerSize){
		LOG_MEDUSA_ERROR("No enough data provided, expecting at least ", headerSize, " bytes.");
		DEBUG_THROW(Exception, sslit("No enough data provided"));
	}

	EncryptedHeader header;
	encrypted.peek(&header, sizeof(header));
	const NoncedKey noncedKey(header.nonce, key);
	const AUTO(expectedMd5, Poseidon::md5Hash(&noncedKey, sizeof(noncedKey)));
	if(expectedMd5 != header.authMd5){
		LOG_MEDUSA_DEBUG("Unexpected MD5: expecting ", Poseidon::HexDumper(expectedMd5.data(), expectedMd5.size()),
			", got ", Poseidon::HexDumper(header.authMd5.data(), header.authMd5.size()));
		return VAL_INIT;
	}
	return createContext(header.uuid, noncedKey);
}
Poseidon::StreamBuffer decryptPayload(const boost::shared_ptr<EncryptionContext> &context, Poseidon::StreamBuffer encrypted){
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
