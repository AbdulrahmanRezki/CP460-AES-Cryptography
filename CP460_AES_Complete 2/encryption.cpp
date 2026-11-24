#include "encryption.h"
#include <openssl/evp.h>
#include <stdexcept>

std::vector<unsigned char> encryptAES(const std::string& message,
                                      const std::vector<unsigned char>& key,
                                      const std::vector<unsigned char>& iv) {
    if (key.size() != 16 || iv.size() != 16) {
        throw std::runtime_error("Key and IV must be 16 bytes");
    }

    EVP_CIPHER_CTX* context = EVP_CIPHER_CTX_new();
    if (context == nullptr) {
        throw std::runtime_error("Could not start encryption");
    }

    std::vector<unsigned char> encrypted_message(message.size() + 16);
    int length = 0;
    int total_length = 0;

    int result = EVP_EncryptInit_ex(context, EVP_aes_128_cbc(), nullptr,
                                    key.data(), iv.data());

    if (result == 1) {
        result = EVP_EncryptUpdate(context, encrypted_message.data(), &length,
                                   (const unsigned char*)message.data(),
                                   (int)message.size());
        total_length = length;
    }

    if (result == 1) {
        result = EVP_EncryptFinal_ex(context,
                                     encrypted_message.data() + total_length,
                                     &length);
        total_length += length;
    }

    EVP_CIPHER_CTX_free(context);

    if (result != 1) {
        throw std::runtime_error("Encryption failed");
    }

    encrypted_message.resize(total_length);
    return encrypted_message;
}

std::string toHex(const std::vector<unsigned char>& data) {
    const char digits[] = "0123456789abcdef";
    std::string hex_text;

    for (unsigned char byte : data) {
        hex_text += digits[byte / 16];
        hex_text += digits[byte % 16];
    }

    return hex_text;
}
