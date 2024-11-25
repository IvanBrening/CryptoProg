#include <cryptopp/sha.h>
#include <cryptopp/hex.h>
#include <cryptopp/files.h>
#include <iostream>
#include <fstream>
#include <string>
#include <sstream>

int main(int argc, char* argv[]) {
    if (argc != 2) {
        std::cerr << "Usage: " << argv[0] << " <filename>" << std::endl;
        return 1;
    }

    std::string filename = argv[1];
    std::string file_content;
    std::string hash;

    // Считываем содержимое файла
    std::ifstream file(filename, std::ios::binary);
    if (file) {
        std::ostringstream ss;
        ss << file.rdbuf();  // Считываем весь файл в строковый поток
        file_content = ss.str();
        file.close();
    } else {
        std::cerr << "Error reading file: " << filename << std::endl;
        return 1;
    }

    try {
        // Используем SHA-256 для хэширования
        CryptoPP::SHA256 sha;
        CryptoPP::StringSource(file_content, true,
            new CryptoPP::HashFilter(sha,
                new CryptoPP::HexEncoder(
                    new CryptoPP::StringSink(hash), false // false — без пробела между байтами
                )
            )
        );

        std::cout << "SHA-256 Hash: " << hash << std::endl;
    } catch (const CryptoPP::Exception& e) {
        std::cerr << e.what() << std::endl;
        return 1;
    }

    return 0;
}
