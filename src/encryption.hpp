#ifndef MEDUSA_ENCRYPTION_HPP_
#define MEDUSA_ENCRYPTION_HPP_

#include <string>

namespace Medusa {

extern std::string generateNonce();

extern std::string encrypt(std::string data, const std::string &key, const std::string &nonce);
extern std::string decrypt(std::string data, const std::string &key, const std::string &nonce);

}

#endif
