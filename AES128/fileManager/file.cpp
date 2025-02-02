#include "file.h"
#include <stdexcept>
#include <filesystem>

#define EXTENSION ".myEnc"
namespace fs = std::filesystem;

File::File(const std::string& filePath) : filePath(filePath) {
    if (filePath.empty()) {
        throw std::invalid_argument("File name cannot be empty.");
    }
    this->encryptedFilePath = filePath + EXTENSION;
}

File::~File() {
    if (outFile.is_open()) {
        outFile.close();
    }
    if (inFile.is_open()) {
        inFile.close();
    }
}

bool File::exists() const {
    return fs::exists(filePath);
}

void File::write(const std::string& ciphertext) {
    std::filesystem::path encryptedFileDir = std::filesystem::path(encryptedFilePath).parent_path();
    if (!encryptedFileDir.empty() && !std::filesystem::exists(encryptedFileDir)) {
        std::filesystem::create_directories(encryptedFileDir);
    }

    std::ofstream tempFile(encryptedFilePath, std::ios::app);
    if (!tempFile) {
        throw std::runtime_error("Failed to create encrypted file: " + encryptedFilePath);
    }
    tempFile.close();

    outFile.open(encryptedFilePath, std::ios::out | std::ios::trunc);
    if (!outFile) {
        throw std::runtime_error("Failed to open encrypted file for writing: " + encryptedFilePath);
    }

    size_t length = ciphertext.length();
    for (size_t i = 0; i < length; i += 64) {
        outFile << ciphertext.substr(i, 64) << '\n';
    }

    outFile.close();
}

std::string File::read() {
    if (!exists()) {
        throw std::runtime_error("File not found: " + filePath);
    }

    inFile.open(filePath);
    if (!inFile) {
        throw std::runtime_error("Failed to open file for reading: " + filePath);
    }

    std::string content((std::istreambuf_iterator<char>(inFile)), std::istreambuf_iterator<char>());
    inFile.close();
    return content;
}