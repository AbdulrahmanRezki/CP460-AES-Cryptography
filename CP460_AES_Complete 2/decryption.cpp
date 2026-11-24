#include "decryption.h"
#include <openssl/evp.h>
#include <cctype>
#include <stdexcept>

std::string decryptAES(const std::vector<unsigned char>& ciphertext,
                       const std::vector<unsigned char>& key,
                       const std::vector<unsigned char>& iv) {
    if (key.size() != 16 || iv.size() != 16) {
        throw std::runtime_error("Key and IV must be 16 bytes");
    }
    if (ciphertext.empty()) {
        throw std::runtime_error("Ciphertext is empty");
    }
    if (ciphertext.size() % 16 != 0) {
        throw std::runtime_error("Ciphertext length must be a multiple of 16 bytes");
    }

    EVP_CIPHER_CTX* context = EVP_CIPHER_CTX_new();
    if (context == nullptr) {
        throw std::runtime_error("Could not start decryption");
    }

    std::vector<unsigned char> decrypted_message(ciphertext.size());
    int length = 0;
    int total_length = 0;

    int result = EVP_DecryptInit_ex(context, EVP_aes_128_cbc(), nullptr,
                                    key.data(), iv.data());

    if (result == 1) {
        result = EVP_DecryptUpdate(context, decrypted_message.data(), &length,
                                   ciphertext.data(), (int)ciphertext.size());
        total_length = length;
    }

    if (result == 1) {
        // Final step checks padding; some incorrect inputs can still have valid padding.
        result = EVP_DecryptFinal_ex(context,
                                     decrypted_message.data() + total_length,
                                     &length);
        total_length += length;
    }

    EVP_CIPHER_CTX_free(context);

    if (result != 1) {
        throw std::runtime_error("Decryption failed (wrong key/IV or corrupted ciphertext)");
    }

    return std::string(decrypted_message.begin(),
                       decrypted_message.begin() + total_length);
}

static int hexValue(char c) {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

std::vector<unsigned char> fromHex(const std::string& hex_text) {
    std::string clean;
    for (char c : hex_text) {
        if (!std::isspace((unsigned char)c)) clean += c;
    }

    if (clean.empty()) {
        throw std::runtime_error("Hex input is empty");
    }
    if (clean.size() % 2 != 0) {
        throw std::runtime_error("Hex input must have an even number of characters");
    }

    std::vector<unsigned char> bytes;
    for (size_t i = 0; i < clean.size(); i += 2) {
        int high = hexValue(clean[i]);
        int low = hexValue(clean[i + 1]);
        if (high < 0 || low < 0) {
            throw std::runtime_error("Hex input contains a non-hex character");
        }
        bytes.push_back((unsigned char)(high * 16 + low));
    }
    return bytes;
}
