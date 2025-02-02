#include "keyGen.h"
matrix KeyGen::gen_key(const matrix& keyMat, const int round) {
    matrix result(keyMat.begin(), keyMat.end());

    rotate(result.begin(), result.begin() + 1, result.end());

    for (int row = 0; row < STANDARD_ROW_SIZE; row++) {
        int rowIndex = charToHexMapper.at(result[row][3][0]);
        int colIndex = charToHexMapper.at(result[row][3][1]);
        result[row][3] = sBox[rowIndex][colIndex];
    }

    for (int row = 0; row < STANDARD_ROW_SIZE; row++) {
        result[row][0] = AES128Helper::_xor(
                AES128Helper::_xor(result[row][3], keyMat[row][0]),
                recon_constants[round][row]
        );
    }

    for (int col = 1; col < STANDARD_COLUMN_SIZE; col++) {
        for (int row = 0; row < STANDARD_ROW_SIZE; row++) {
            result[row][col] = AES128Helper::_xor(
                    result[row][col - 1],
                    keyMat[row][col]
            );
        }
    }
    return result;
}
