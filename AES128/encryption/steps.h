#ifndef AES_STEPS_H
#define AES_STEPS_H
#include "../aes128_helper/aes128_helper.h"
using namespace AES128;

class Steps {
public:
    static matrix add_round_key(const matrix& plaintext, const matrix& key);

    static void sub_bytes(matrix& _mat);

    static void shift_rows(matrix& _mat);

    static matrix mix_columns(const matrix& stateArray);
};


#endif
