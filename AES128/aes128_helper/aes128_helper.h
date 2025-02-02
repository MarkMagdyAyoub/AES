#ifndef AES_AES128_HELPER_H
#define AES_AES128_HELPER_H
#include <iostream>
#include <sstream>
#include <vector>
#include <iomanip>
#include <unordered_map>
#include <algorithm>
#include <cstdint>
namespace AES128{
    using matrix = std::vector<std::vector<std::string>>;
    constexpr int _a = 97;
    constexpr int _f = 102;
    constexpr int _A = 65;
    constexpr int _F = 70;
    constexpr int _0 = 48;
    constexpr int _9 = 57;
    constexpr int STANDARD_ROW_SIZE = 4;
    constexpr int STANDARD_COLUMN_SIZE = 4;
    constexpr int STANDARD_BLOCK_SIZE_IN_BYTES = 16;
    constexpr int STANDARD_BLOCK_SIZE_IN_HEX = 32;

    const std::unordered_map<int, int> hexToBinaryMapper{
            {0, 0b0000}, {1, 0b0001}, {2, 0b0010}, {3, 0b0011},
            {4, 0b0100}, {5, 0b0101}, {6, 0b0110}, {7, 0b0111},
            {8, 0b1000}, {9, 0b1001}, {10, 0b1010}, {11, 0b1011},
            {12, 0b1100}, {13, 0b1101}, {14, 0b1110}, {15, 0b1111}
    };

    const std::unordered_map<char, int> charToHexMapper{
            {'0', 0}, {'1', 1}, {'2', 2}, {'3', 3},
            {'4', 4}, {'5', 5}, {'6', 6}, {'7', 7},
            {'8', 8}, {'9', 9}, {'a', 10}, {'b', 11},
            {'c', 12}, {'d', 13}, {'e', 14}, {'f', 15},
            {'A', 10}, {'B', 11}, {'C', 12}, {'D', 13},
            {'E', 14}, {'F', 15}
    };

    const std::unordered_map<int, char> hexToCharMapper{
            {0, '0'}, {1, '1'}, {2, '2'}, {3,'3'},
            {4, '4'}, {5, '5'}, {6, '6'}, {7, '7'},
            {8, '8'}, {9, '9'},
            {10, 'a'}, {11, 'b'}, {12, 'c'}, {13, 'd'}, {14, 'e'}, {15, 'f'}
    };

    const matrix sBox{
            {"63", "7c", "77", "7b", "f2", "6b", "6f", "c5", "30", "01", "67", "2b", "fe", "d7", "ab", "76"},
            {"ca", "82", "c9", "7d", "fa", "59", "47", "f0", "ad", "d4", "a2", "af", "9c", "a4", "72", "c0"},
            {"b7", "fd", "93", "26", "36", "3f", "f7", "cc", "34", "a5", "e5", "f1", "71", "d8", "31", "15"},
            {"04", "c7", "23", "c3", "18", "96", "05", "9a", "07", "12", "80", "e2", "eb", "27", "b2", "75"},
            {"09", "83", "2c", "1a", "1b", "6e", "5a", "a0", "52", "3b", "d6", "b3", "29", "e3", "2f", "84"},
            {"53", "d1", "00", "ed", "20", "fc", "b1", "5b", "6a", "cb", "be", "39", "4a", "4c", "58", "cf"},
            {"d0", "ef", "aa", "fb", "43", "4d", "33", "85", "45", "f9", "02", "7f", "50", "3c", "9f", "a8"},
            {"51", "a3", "40", "8f", "92", "9d", "38", "f5", "bc", "b6", "da", "21", "10", "ff", "f3", "d2"},
            {"cd", "0c", "13", "ec", "5f", "97", "44", "17", "c4", "a7", "7e", "3d", "64", "5d", "19", "73"},
            {"60", "81", "4f", "dc", "22", "2a", "90", "88", "46", "ee", "b8", "14", "de", "5e", "0b", "db"},
            {"e0", "32", "3a", "0a", "49", "06", "24", "5c", "c2", "d3", "ac", "62", "91", "95", "e4", "79"},
            {"e7", "c8", "37", "6d", "8d", "d5", "4e", "a9", "6c", "56", "f4", "ea", "65", "7a", "ae", "08"},
            {"ba", "78", "25", "2e", "1c", "a6", "b4", "c6", "e8", "dd", "74", "1f", "4b", "bd", "8b", "8a"},
            {"70", "3e", "b5", "66", "48", "03", "f6", "0e", "61", "35", "57", "b9", "86", "c1", "1d", "9e"},
            {"e1", "f8", "98", "11", "69", "d9", "8e", "94", "9b", "1e", "87", "e9", "ce", "55", "28", "df"},
            {"8c", "a1", "89", "0d", "bf", "e6", "42", "68", "41", "99", "2d", "0f", "b0", "54", "bb", "16"}
    };

    const std::vector<std::vector<std::string>> preDefinedMatrix{
            {"02" , "03" , "01" , "01"},
            {"01" , "02" , "03" , "01"},
            {"01" , "01" , "02" , "03"},
            {"03" , "01" , "01" , "02"}
    };

    const matrix recon_constants{
            {"01" , "00" , "00" , "00"}, // rountd 1
            {"02" , "00" , "00" , "00"}, // rountd 2
            {"04" , "00" , "00" , "00"}, // rountd 3
            {"08" , "00" , "00" , "00"}, // rountd 4
            {"10" , "00" , "00" , "00"}, // rountd 5
            {"20" , "00" , "00" , "00"}, // rountd 6
            {"40" , "00" , "00" , "00"}, // rountd 7
            {"80" , "00" , "00" , "00"}, // rountd 8
            {"1B" , "00" , "00" , "00"}, // rountd 9
            {"36" , "00" , "00" , "00"}  // rountd 10
    };

    class AES128Helper {
    public:
        static bool is_hex_digit(int digit);

        static bool is_hex_decimal_number(const std::string& text);

        static std::string hex_mapper(const std::string& text);

        static matrix to_matrix(const std::string& hexNumber);

        static std::string _xor(const std::string& hexNumber1 , const std::string& hexNumber2);

        static void display_matrix(matrix& matrix);

        static std::string multiplyByTwo(const std::string& hexString);

        static std::string multiply(const std::string& hex, const std::string& predefHex);

        static std::string to_string(const matrix& mat);

        static int calculate_padding(const std::string& text);

        static void add_padding(std::string& text);
    };
};
#endif
