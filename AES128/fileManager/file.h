#ifndef AES_FILE_H
#define AES_FILE_H

#include <filesystem>
#include <string>
#include <fstream>
#include <stdexcept>

class File {
private:
    std::string filePath;
    std::string encryptedFilePath;
    std::ofstream outFile;
    std::ifstream inFile;

public:
    explicit File(const std::string& fileName);
    ~File();

    void write(const std::string& data);
    std::string read();
    bool exists() const;
};
#endif