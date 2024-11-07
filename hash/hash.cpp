#include <cryptopp/sha.h>
#include <cryptopp/hex.h>
#include <cryptopp/files.h>
#include <iostream>
#include <fstream>
#include <string>

int main(int argc, char* argv[]) {
    if (argc != 2) {
        std::cerr << "Usage: " << argv[0] << " <filename>" << std::endl;
        return 1;
    }

    std::string filename = argv[1];
    std::string file_content;
    std::string hash;

    // Считываем содержимое файла
    std::ifstream file(filename);
    if (file) {
        std::getline(file, file_content);
        file.close();
    } else {
        std::cerr << "Error reading file: " << filename << std::endl;
        return 1;
    }

    try {
        CryptoPP::SHA256 sha;
        CryptoPP::StringSource(file_content, true,
            new CryptoPP::HashFilter(sha,
                new CryptoPP::HexEncoder(
                    new CryptoPP::StringSink(hash), false
                )
            )
        );

        std::cout << "Hash: " << hash << std::endl;
    } catch (const CryptoPP::Exception& e) {
        std::cerr << e.what() << std::endl;
        return 1;
    }

    return 0;
}


