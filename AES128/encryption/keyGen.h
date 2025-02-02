#ifndef AES_KEYGEN_H
#define AES_KEYGEN_H
#include "../aes128_helper/aes128_helper.h"
using namespace AES128;
class KeyGen {
public:
    static matrix gen_key(const matrix& keyMat, const int round);
};
#endif
