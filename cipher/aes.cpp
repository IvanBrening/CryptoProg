#include <cryptopp/aes.h>
#include <cryptopp/modes.h>  // Для работы с режимами шифрования
#include <cryptopp/hkdf.h>   // Для HKDF
#include <cryptopp/sha.h>    // Для SHA256
#include <cryptopp/hex.h>    // Для вывода в hex
#include <cryptopp/files.h>  // Для работы с файлами
#include <iostream>
#include <string>
#include <vector>

// Функция для шифрования
void encrypt(const std::string& inputFile, const std::string& outputFile, const std::string& password) {
    // Генерация ключа из пароля с использованием HKDF
    CryptoPP::SecByteBlock key(CryptoPP::AES::DEFAULT_KEYLENGTH);
    CryptoPP::SecByteBlock iv(CryptoPP::AES::BLOCKSIZE);

    // Используем HKDF для вывода ключа из пароля
    CryptoPP::HKDF<CryptoPP::SHA256> hkdf;
    hkdf.DeriveKey(key, key.size(), 
                   reinterpret_cast<const CryptoPP::byte*>(password.data()), password.size(),
                   reinterpret_cast<const CryptoPP::byte*>("salt"), 4,
                   nullptr, 0); // Параметры info не используются

    // Создаем шифратор в режиме CBC
    CryptoPP::CBC_Mode<CryptoPP::AES>::Encryption encryption(key, key.size(), iv);

    // Открытие входного и выходного файлов
    CryptoPP::FileSource fs(inputFile.c_str(), true, new CryptoPP::StreamTransformationFilter(
        encryption,
        new CryptoPP::FileSink(outputFile.c_str())
    ));
}

// Функция для расшифровки
void decrypt(const std::string& inputFile, const std::string& outputFile, const std::string& password) {
    // Генерация ключа из пароля с использованием HKDF
    CryptoPP::SecByteBlock key(CryptoPP::AES::DEFAULT_KEYLENGTH);
    CryptoPP::SecByteBlock iv(CryptoPP::AES::BLOCKSIZE);

    // Используем HKDF для вывода ключа из пароля
    CryptoPP::HKDF<CryptoPP::SHA256> hkdf;
    hkdf.DeriveKey(key, key.size(), 
                   reinterpret_cast<const CryptoPP::byte*>(password.data()), password.size(),
                   reinterpret_cast<const CryptoPP::byte*>("salt"), 4,
                   nullptr, 0); // Параметры info не используются

    // Создаем дешифратор в режиме CBC
    CryptoPP::CBC_Mode<CryptoPP::AES>::Decryption decryption(key, key.size(), iv);

    // Открытие входного и выходного файлов
    CryptoPP::FileSource fs(inputFile.c_str(), true, new CryptoPP::StreamTransformationFilter(
        decryption,
        new CryptoPP::FileSink(outputFile.c_str())
    ));
}

int main(int argc, char* argv[]) {
    if (argc != 5) {
        std::cerr << "Usage: " << argv[0] << " <encrypt/decrypt> <inputfile> <outputfile> <password>" << std::endl;
        return 1;
    }

    std::string mode = argv[1];
    std::string inputFile = argv[2];
    std::string outputFile = argv[3];
    std::string password = argv[4];

    try {
        if (mode == "encrypt") {
            encrypt(inputFile, outputFile, password);
            std::cout << "Encryption completed!" << std::endl;
        } else if (mode == "decrypt") {
            decrypt(inputFile, outputFile, password);
            std::cout << "Decryption completed!" << std::endl;
        } else {
            std::cerr << "Invalid mode. Use 'encrypt' or 'decrypt'." << std::endl;
            return 1;
        }
    } catch (const CryptoPP::Exception& e) {
        std::cerr << e.what() << std::endl;
        return 1;
    }

    return 0;
}



