#include "steps.h"

matrix Steps::add_round_key(const matrix& plaintext, const matrix& key) {
    matrix result(STANDARD_ROW_SIZE, std::vector<std::string>(STANDARD_COLUMN_SIZE));
    for (int row = 0; row < STANDARD_ROW_SIZE; row++) {
        for (int col = 0; col < STANDARD_COLUMN_SIZE; col++) {
            std::string plaintextCell = plaintext[row][col];
            std::string keyCell = key[row][col];
            result[row][col] = AES128::AES128Helper::_xor(plaintextCell, keyCell);
        }
    }
    return result;
}

void Steps::sub_bytes(matrix& _mat) {
    for (int row = 0; row < STANDARD_ROW_SIZE; row++) {
        for (int col = 0; col < STANDARD_COLUMN_SIZE; col++) {
            int rowIndex = charToHexMapper.at(_mat[row][col][0]);
            int colIndex = charToHexMapper.at(_mat[row][col][1]);
            _mat[row][col] = sBox[rowIndex][colIndex];
        }
    }
}

void Steps::shift_rows(matrix& _mat) {
    int shift = 0;
    for (auto& row : _mat) {
        rotate(row.begin() , row.begin()+shift++ , row.end());
    }
}

matrix Steps::mix_columns(const matrix& stateArray) {
    matrix result(STANDARD_ROW_SIZE , std::vector<std::string>(STANDARD_COLUMN_SIZE));
    for (int row = 0; row < STANDARD_ROW_SIZE; row++) {
        for (int col = 0; col < STANDARD_COLUMN_SIZE ; col++) {
            std::string resultCell = "00";
            for (int k = 0; k < STANDARD_COLUMN_SIZE; k++) {
                std::string hex1 = stateArray[k][col];
                std::string hex2 = preDefinedMatrix[row][k];
                resultCell = AES128Helper::_xor(resultCell, AES128Helper::multiply(hex1, hex2));
            }
            result[row][col] = resultCell;
        }
    }
    return result;
}

