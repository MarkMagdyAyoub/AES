#include "aes128_helper.h"
using namespace AES128;


bool AES128Helper::is_hex_digit(int digit) {
    return
            (_0 <= digit && digit <= _9) ||
            (_a <= digit && digit <= _f) ||
            (_A <= digit && digit <= _F);
}

bool AES128Helper::is_hex_decimal_number(const std::string& text) {
    for (const char& _char : text) {
        if (!is_hex_digit(static_cast<int>(_char)))
            return false;
    }
    return true;
}

std::string AES128Helper::hex_mapper(const std::string& text) {
    std::stringstream hexStream;
    for (const char& _char : text) {
        if (_char != ' ')
            hexStream << std::hex << static_cast<int>(_char);
    }
    return hexStream.str();
}

matrix AES128Helper::to_matrix(const std::string& hexNumber) {
    std::string processedHex = hexNumber;
    if (!is_hex_decimal_number(processedHex)) {
        processedHex = hex_mapper(processedHex);
    }
    if (processedHex.size() < 32) {
        throw std::invalid_argument("Invalid Argument: Hexadecimal string must be at least 32 characters long.");
    }
    std::vector<std::vector<std::string>> matrix(STANDARD_ROW_SIZE, std::vector<std::string>(STANDARD_COLUMN_SIZE));
    int curIndex = 0;
    for (int col = 0; col < 4; col++) {
        for (int row = 0; row < 4; row++) {
            matrix[row][col] = processedHex.substr(curIndex, 2);
            curIndex += 2;
        }
    }
    return matrix;
}

std::string AES128Helper::_xor(const std::string& hexNumber1 , const std::string& hexNumber2) {
    if (hexNumber1.size() != 2 || hexNumber2.size() != 2)
        throw std::invalid_argument("hexNumber1 and hexNumber2 must each be 2 characters long.");

    int hex1 = charToHexMapper.at(hexNumber1[0]) << 4 | charToHexMapper.at(hexNumber1[1]);
    int hex2 = charToHexMapper.at(hexNumber2[0]) << 4 | charToHexMapper.at(hexNumber2[1]);
    int result = hex1 ^ hex2;

    std::stringstream stream;
    stream << std::hex << std::setw(2) << std::setfill('0') << result;
    return stream.str();
}

void AES128Helper::display_matrix(matrix& matrix) {
    for (int row = 0; row < STANDARD_ROW_SIZE; row++) {
        for (int col = 0; col < STANDARD_COLUMN_SIZE; col++) {
            std::cout << matrix[row][col][0] << matrix[row][col][1] << " ";
        }
        std::cout << "\n";
    }
}

std::string AES128Helper::multiplyByTwo(const std::string& hexString) {
    int hexValue = std::stoi(hexString, nullptr, 16);
    int num = hexValue;
    int leftBinDigit = (hexValue >> 7) & 1;
    hexValue <<= 1;
    if (leftBinDigit) {
        hexValue ^= 0x1B;
    }
    hexValue &= 0xFF;

    std::stringstream ss;
    ss << std::setw(2) << std::setfill('0') << std::hex << hexValue;
    return ss.str();
}

std::string AES128Helper::multiply(const std::string& hex, const std::string& predefHex) {
    if (predefHex == "01") return hex;
    if (predefHex == "02") return AES128Helper::multiplyByTwo(hex);
    if (predefHex == "03") return AES128Helper::_xor(multiplyByTwo(hex), hex);
    throw std::invalid_argument("Invalid predefined hex value for multiplication.");
}

std::string AES128Helper::to_string(const matrix& mat) {
    std::string result;
    for (int col = 0; col < STANDARD_COLUMN_SIZE; col++)
        for (int row = 0; row < STANDARD_ROW_SIZE; row++)
            result += mat[row][col];
    return result;
}

int AES128Helper::calculate_padding(const std::string &text) {
    int remainder = (int)text.length() % STANDARD_BLOCK_SIZE_IN_BYTES;
    if (remainder == 0)
        return 0;
    return STANDARD_BLOCK_SIZE_IN_BYTES - remainder;
}

void AES128Helper::add_padding(std::string &text) {
    int paddingNeeded = calculate_padding(text);
    if(paddingNeeded == 0) return;
    char paddingChar = hexToCharMapper.at(paddingNeeded);
    int iterations = STANDARD_BLOCK_SIZE_IN_HEX-((int)text.size() % STANDARD_BLOCK_SIZE_IN_HEX);
    for(int i = 0 ; i < iterations ; i++){
        text.push_back(paddingChar);
    }
}