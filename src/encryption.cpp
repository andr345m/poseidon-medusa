#include "precompiled.hpp"
#include "encryption.hpp"
#include <poseidon/md5.hpp>
#include <poseidon/random.hpp>
#include <poseidon/hex.hpp>

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

	inline Poseidon::Md5 md5_string(const std::string &s){
		Poseidon::Md5_ostream md5_os;
		md5_os <<s;
		return md5_os.finalize();
	}

	struct NoncedKey {
		Nonce nonce;
		Poseidon::Md5 key_md5;

		explicit NoncedKey(const Nonce &nonce_, const std::string &key_)
			: nonce(nonce_), key_md5(md5_string(key_))
		{
		}
	};

	BOOST_STATIC_ASSERT_MSG(sizeof(NoncedKey) == 32, "Incompatible layout detected.");

	// http://en.wikipedia.org/wiki/RC4 有改动。

	boost::shared_ptr<EncryptionContext> create_context(const Poseidon::Uuid &uuid, const NoncedKey &nonced_key){
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
	unsigned char encrypt_byte(EncryptionContext *ctx, unsigned char c){
		unsigned byte = c;
		// ctx->i = (ctx->i + 1) & 0xFF;
		const unsigned k1 = ctx->s[ctx->i];
		ctx->j = (ctx->j + k1) & 0xFF;
		const unsigned k2 = ctx->s[ctx->j];
		ctx->s[ctx->i] = k2;
		ctx->s[ctx->j] = k1;
		ctx->i = (ctx->i + (byte | 0x0F)) & 0xFF; // RC4 改。
		byte ^= k1 + k2;
		return byte;
	}
	unsigned char decrypt_byte(EncryptionContext *ctx, unsigned char c){
		unsigned byte = c;
		// ctx->i = (ctx->i + 1) & 0xFF;
		const unsigned k1 = ctx->s[ctx->i];
		ctx->j = (ctx->j + k1) & 0xFF;
		const unsigned k2 = ctx->s[ctx->j];
		ctx->s[ctx->i] = k2;
		ctx->s[ctx->j] = k1;
		byte ^= k1 + k2;
		ctx->i = (ctx->i + (byte | 0x0F)) & 0xFF; // RC4 改。
		return byte;
	}
}

std::size_t get_encrypted_header_size(){
	return sizeof(EncryptedHeader);
}

std::pair<boost::shared_ptr<EncryptionContext>, Poseidon::StreamBuffer> encrypt_header(const Poseidon::Uuid &uuid, const std::string &key){
	PROFILE_ME;

	Nonce nonce;
	for(AUTO(it, nonce.begin()); it != nonce.end(); ++it){
		*it = Poseidon::random_uint32();
	}
	const NoncedKey nonced_key(nonce, key);
	AUTO(context, create_context(uuid, nonced_key));

	EncryptedHeader header;
	header.nonce = nonce;
	header.uuid = uuid;
	Poseidon::Md5_ostream md5_os;
	md5_os.write(reinterpret_cast<const char *>(&nonced_key), static_cast<std::streamsize>(sizeof(nonced_key)));
	header.auth_md5 = md5_os.finalize();
	AUTO(encrypted, Poseidon::StreamBuffer(&header, sizeof(header)));

	return std::make_pair(STD_MOVE(context), STD_MOVE(encrypted));
}
Poseidon::StreamBuffer encrypt_payload(const boost::shared_ptr<EncryptionContext> &context, Poseidon::StreamBuffer plain){
	PROFILE_ME;

	Poseidon::StreamBuffer encrypted;
	int c;
	while((c = plain.get()) >= 0){
		encrypted.put(encrypt_byte(context.get(), static_cast<unsigned char>(c)));
	}
	return encrypted;
}

boost::shared_ptr<EncryptionContext> try_decrypt_header(const Poseidon::StreamBuffer &encrypted, const std::string &key){
	PROFILE_ME;

	const AUTO(header_size, get_encrypted_header_size());
	if(encrypted.size() < header_size){
		LOG_MEDUSA_ERROR("Data truncated, expecting at least ", header_size, " bytes.");
		DEBUG_THROW(Poseidon::Exception, Poseidon::sslit("Data truncated"));
	}

	EncryptedHeader header;
	encrypted.peek(&header, sizeof(header));
	const NoncedKey nonced_key(header.nonce, key);
	Poseidon::Md5_ostream md5_os;
	md5_os.write(reinterpret_cast<const char *>(&nonced_key), static_cast<std::streamsize>(sizeof(nonced_key)));
	const AUTO(auth_md5_expected, md5_os.finalize());
	if(header.auth_md5 != auth_md5_expected){
		LOG_MEDUSA_DEBUG("MD5 check failure.");
		return VAL_INIT;
	}
	return create_context(header.uuid, nonced_key);
}
Poseidon::StreamBuffer decrypt_payload(const boost::shared_ptr<EncryptionContext> &context, Poseidon::StreamBuffer encrypted){
	PROFILE_ME;

	Poseidon::StreamBuffer plain;
	int c;
	while((c = encrypted.get()) >= 0){
		plain.put(decrypt_byte(context.get(), static_cast<unsigned char>(c)));
	}
	return plain;
}

}
