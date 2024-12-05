#include <iostream>
#include <fstream>
#include <iomanip>
#include <sstream>
#include <openssl/evp.h>

// Функция для вычисления SHA-256 хэша с использованием EVP
std::string computeHash(const std::string &filePath) {
    std::ifstream file(filePath, std::ios::binary);
    if (!file.is_open()) {
        throw std::runtime_error("Не удалось открыть файл.");
    }

    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    const EVP_MD *md = EVP_sha256();
    EVP_DigestInit_ex(ctx, md, nullptr);

    char buffer[4096];
    while (file.read(buffer, sizeof(buffer))) {
        EVP_DigestUpdate(ctx, buffer, file.gcount());
    }
    EVP_DigestUpdate(ctx, buffer, file.gcount());

    unsigned char hash[EVP_MAX_MD_SIZE];
    unsigned int length;
    EVP_DigestFinal_ex(ctx, hash, &length);
    EVP_MD_CTX_free(ctx);

    std::ostringstream hexHash;
    for (unsigned int i = 0; i < length; ++i) {
        hexHash << std::hex << std::setw(2) << std::setfill('0') << (int)hash[i];
    }

    return hexHash.str();
}

int main() {
    try {
        std::string filePath;
        std::cout << "Введите путь к файлу: ";
        std::cin >> filePath;

        std::string hash = computeHash(filePath);
        std::cout << "Хэш SHA-256: " << hash << std::endl;
    } catch (const std::exception &e) {
        std::cerr << "Ошибка: " << e.what() << std::endl;
    }

    return 0;
}
