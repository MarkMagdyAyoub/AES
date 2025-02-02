#include <iostream>
#include "./fileManager/File.h"
#include "./encryption/algorithm.h"
using namespace std;
using namespace AES128;
std::string truncate(const std::string& path , const char _char) {
    std::string truncatedPath = path;
    truncatedPath.erase(std::remove(truncatedPath.begin(), truncatedPath.end(), _char), truncatedPath.end());
    return truncatedPath;
}
int main(int argc , char* argv[]) {
    if (argc != 3) {
        cerr << "Usage: " << argv[0] << " <input_file> <encryption_key>" << endl;
        return 1;
    }
    try {
        File myFile(truncate(argv[1] , '?'));
        std::string plainText = myFile.read();
        std::string key = argv[2];
        std::string cipherText = Algorithm::encrypt(plainText , key);
        myFile.write(Algorithm::encrypt(plainText , key));
    } catch (const std::exception& e) {
        std::cerr << "Error: " << e.what() << std::endl;
    }
    return 0;
}
