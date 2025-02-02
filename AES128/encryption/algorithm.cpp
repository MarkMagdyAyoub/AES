#include "algorithm.h"

std::string Algorithm::encrypt(const std::string& plaintext, const std::string& key) {
    std::string plaintextCpy = plaintext;
    AES128Helper::add_padding(plaintextCpy);

    std::string ciphertext;

    for (size_t i = 0; i < plaintextCpy.length(); i += STANDARD_BLOCK_SIZE_IN_HEX) {
        std::string block = plaintextCpy.substr(i, STANDARD_BLOCK_SIZE_IN_HEX);

        matrix plainTextMat = AES128Helper::to_matrix(block);
        matrix keyMat = AES128Helper::to_matrix(key);

        matrix addRoundKey = Steps::add_round_key(plainTextMat, keyMat);

        for (int round = 1; round <= 9; round++) {
            Steps::sub_bytes(addRoundKey);
            Steps::shift_rows(addRoundKey);
            addRoundKey = Steps::mix_columns(addRoundKey);
            keyMat = KeyGen::gen_key(keyMat, round - 1);
            addRoundKey = Steps::add_round_key(addRoundKey, keyMat);
        }

        Steps::sub_bytes(addRoundKey);
        Steps::shift_rows(addRoundKey);
        keyMat = KeyGen::gen_key(keyMat, 9);
        addRoundKey = Steps::add_round_key(addRoundKey, keyMat);

        ciphertext += AES128Helper::to_string(addRoundKey);
    }
    return ciphertext;
}
