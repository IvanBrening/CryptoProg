#include <iostream>
#include <fstream>
#include <vector>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/err.h>

void handleErrors() {
    ERR_print_errors_fp(stderr);
    abort();
}

// Функция для генерации ключа из пароля
std::vector<unsigned char> deriveKey(const std::string &password, const unsigned char *salt) {
    const int keyLen = 32;
    const int iterations = 10000;
    std::vector<unsigned char> key(keyLen);

    if (!PKCS5_PBKDF2_HMAC(password.c_str(), password.size(), salt, 16, iterations, EVP_sha256(), keyLen, key.data())) {
        handleErrors();
    }
    return key;
}

// Функция шифрования или расшифрования
void encryptDecryptFile(bool encrypt, const std::string &inputFile, const std::string &outputFile, const std::string &password) {
    // Проверка наличия пароля
    if (password.empty()) {
        std::cerr << "Ошибка: Пароль не может быть пустым!" << std::endl;
        exit(1);
    }

    unsigned char iv[16];
    unsigned char salt[16];
    if (encrypt) {
        RAND_bytes(salt, sizeof(salt));
        RAND_bytes(iv, sizeof(iv));
    }

    std::ifstream in(inputFile, std::ios::binary);
    std::ofstream out(outputFile, std::ios::binary);
    if (!in || !out) {
        std::cerr << "Ошибка: Не удалось открыть файлы. Проверьте пути." << std::endl;
        exit(1);
    }

    if (encrypt) {
        out.write(reinterpret_cast<const char *>(salt), sizeof(salt));
        out.write(reinterpret_cast<const char *>(iv), sizeof(iv));
    } else {
        in.read(reinterpret_cast<char *>(salt), sizeof(salt));
        in.read(reinterpret_cast<char *>(iv), sizeof(iv));
    }

    std::vector<unsigned char> key = deriveKey(password, salt);

    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx) handleErrors();

    const EVP_CIPHER *cipher = EVP_aes_256_cbc();
    if (!EVP_CipherInit_ex(ctx, cipher, nullptr, key.data(), iv, encrypt)) {
        handleErrors();
    }

    char inBuffer[4096];
    unsigned char outBuffer[4096 + EVP_CIPHER_block_size(cipher)];
    int bytesRead, outLen;

    while ((bytesRead = in.readsome(inBuffer, sizeof(inBuffer))) > 0) {
        if (!EVP_CipherUpdate(ctx, outBuffer, &outLen, reinterpret_cast<unsigned char *>(inBuffer), bytesRead)) {
            handleErrors();
        }
        out.write(reinterpret_cast<const char *>(outBuffer), outLen);
    }

    if (!EVP_CipherFinal_ex(ctx, outBuffer, &outLen)) {
        handleErrors();
    }
    out.write(reinterpret_cast<const char *>(outBuffer), outLen);

    EVP_CIPHER_CTX_free(ctx);
}

int main() {
    try {
        std::string mode, inputFile, outputFile, password;
        std::cout << "Режим работы (encrypt/decrypt): ";
        std::cin >> mode;

        // Проверка корректности введённого режима
        if (mode != "encrypt" && mode != "decrypt") {
            std::cerr << "Ошибка: Неверный режим работы. Должно быть 'encrypt' или 'decrypt'." << std::endl;
            return 1;
        }

        std::cout << "Введите путь к входному файлу: ";
        std::cin >> inputFile;

        // Проверка существования входного файла
        std::ifstream in(inputFile, std::ios::binary);
        if (!in) {
            std::cerr << "Ошибка: Не удалось открыть файл: " << inputFile << std::endl;
            return 1;
        }
        in.close(); // Закрываем файл после проверки

        std::cout << "Введите путь к выходному файлу: ";
        std::cin >> outputFile;

        std::cout << "Введите пароль: ";
        std::cin >> password;

        // Проверка пароля на пустоту
        if (password.empty()) {
            std::cerr << "Ошибка: Пароль не может быть пустым!" << std::endl;
            return 1;
        }

        if (mode == "encrypt") {
            encryptDecryptFile(true, inputFile, outputFile, password);
            std::cout << "Файл успешно зашифрован.\n";
        } else if (mode == "decrypt") {
            encryptDecryptFile(false, inputFile, outputFile, password);
            std::cout << "Файл успешно расшифрован.\n";
        }

    } catch (const std::exception &e) {
        std::cerr << "Ошибка: " << e.what() << std::endl;
        return 1;
    }

    return 0;
}
