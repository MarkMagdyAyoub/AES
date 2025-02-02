#ifndef AES_ALGORITHM_H
#define AES_ALGORITHM_H
#include "../aes128_helper/aes128_helper.h"
#include "steps.h"
#include "keyGen.h"
using namespace AES128;
class Algorithm {
public:
    static std::string encrypt(const std::string& plaintext, const std::string& key);
};
#endif
