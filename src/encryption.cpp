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
		Poseidon::Md5 auth_md5;
	};

#ifdef POSEIDON_CXX11
	static_assert(std::is_standard_layout<EncryptedHeader>::value, "EncryptedHeader is not a standard-layout struct?");
#endif
	BOOST_STATIC_ASSERT_MSG(sizeof(EncryptedHeader) == 48, "Incompatible layout detected");

	struct NoncedKey {
		Nonce nonce;
		Poseidon::Md5 key_md5;

		explicit NoncedKey(const Nonce &nonce_, const std::string &key_)
			: nonce(nonce_), key_md5(Poseidon::md5_hash(key_))
		{
		}
	};

	BOOST_STATIC_ASSERT_MSG(sizeof(NoncedKey) == 32, "Incompatible layout detected");

	// http://en.wikipedia.org/wiki/RC4 有改动。

	boost::shared_ptr<EncryptionContext> create_context(const Poseidon::Uuid &uuid, const NoncedKey &nonced_key){
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

#define GEN_S(k_)   \
			tmp = ret->s[i];    \
			j = (j + tmp + (k_)) & 0xFF;    \
			ret->s[i] = ret->s[j];  \
			ret->s[j] = tmp;    \
			++i;

			for(unsigned r = 0; r < 16; ++r){
				GEN_S(nonced_key.nonce[r]);
			}
			for(unsigned r = 0; r < 16; ++r){
				GEN_S(uuid[r]);
			}
			for(unsigned r = 0; r < 16; ++r){
				GEN_S(nonced_key.key_md5[r]);
			}
			for(unsigned r = 0; r < 16; ++r){
				GEN_S(uuid[r]);
			}
		}

		return ret;
	}
	void encrypt_bytes(EncryptionContext *ctx, unsigned char *data, std::size_t size){
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
	void decrypt_bytes(EncryptionContext *ctx, unsigned char *data, std::size_t size){
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

std::size_t get_encrypted_header_size(){
	return sizeof(EncryptedHeader);
}

std::pair<boost::shared_ptr<EncryptionContext>, Poseidon::StreamBuffer> encrypt_header(const Poseidon::Uuid &uuid, const std::string &key){
	PROFILE_ME;

	Nonce nonce;
	for(AUTO(it, nonce.begin()); it != nonce.end(); ++it){
		*it = Poseidon::rand32();
	}
	const NoncedKey nonced_key(nonce, key);
	AUTO(context, create_context(uuid, nonced_key));

	EncryptedHeader header;
	header.nonce = nonce;
	header.uuid = uuid;
	header.auth_md5 = Poseidon::md5_hash(&nonced_key, sizeof(nonced_key));
	AUTO(encrypted, Poseidon::StreamBuffer(&header, sizeof(header)));

	return std::make_pair(STD_MOVE(context), STD_MOVE(encrypted));
}
Poseidon::StreamBuffer encrypt_payload(const boost::shared_ptr<EncryptionContext> &context, Poseidon::StreamBuffer plain){
	PROFILE_ME;

	AUTO(ce, plain.get_chunk_enumerator());
	while(ce){
		encrypt_bytes(context.get(), ce.data(), ce.size());
		++ce;
	}
	return STD_MOVE(plain);
}

boost::shared_ptr<EncryptionContext> try_decrypt_header(const Poseidon::StreamBuffer &encrypted, const std::string &key){
	PROFILE_ME;

	const AUTO(header_size, get_encrypted_header_size());
	if(encrypted.size() < header_size){
		LOG_MEDUSA_ERROR("No enough data provided, expecting at least ", header_size, " bytes.");
		DEBUG_THROW(Exception, sslit("No enough data provided"));
	}

	EncryptedHeader header;
	encrypted.peek(&header, sizeof(header));
	const NoncedKey nonced_key(header.nonce, key);
	const AUTO(expected_md5, Poseidon::md5_hash(&nonced_key, sizeof(nonced_key)));
	if(expected_md5 != header.auth_md5){
		LOG_MEDUSA_DEBUG("Unexpected MD5: expecting ", Poseidon::HexDumper(expected_md5.data(), expected_md5.size()),
			", got ", Poseidon::HexDumper(header.auth_md5.data(), header.auth_md5.size()));
		return VAL_INIT;
	}
	return create_context(header.uuid, nonced_key);
}
Poseidon::StreamBuffer decrypt_payload(const boost::shared_ptr<EncryptionContext> &context, Poseidon::StreamBuffer encrypted){
	PROFILE_ME;

	AUTO(ce, encrypted.get_chunk_enumerator());
	while(ce){
		decrypt_bytes(context.get(), ce.data(), ce.size());
		++ce;
	}
	return STD_MOVE(encrypted);
}

}
