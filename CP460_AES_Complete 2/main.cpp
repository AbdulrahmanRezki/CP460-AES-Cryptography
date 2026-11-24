#include "encryption.h"
#include "decryption.h"
#include <iostream>
#include <exception>

int main() {
    // Fixed key and IV for classroom demonstration only.
    std::vector<unsigned char> key = {
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
        0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f
    };
    std::vector<unsigned char> iv = {
        0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
        0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f
    };

    std::string choice;
    while (true) {
        std::cout << "\nAES-128-CBC Demonstration\n"
                  << "1. Encrypt and decrypt a message\n"
                  << "2. Decrypt hexadecimal ciphertext\n"
                  << "3. Exit\nChoose an option: ";
        if (!std::getline(std::cin, choice) || choice == "3") break;

        try {
            if (choice == "1") {
                std::string message;
                std::cout << "Enter a message: ";
                if (!std::getline(std::cin, message)) break;
                std::vector<unsigned char> encrypted_message = encryptAES(message, key, iv);
                std::string hex_text = toHex(encrypted_message);
                std::cout << "Original message: " << message << '\n';
                std::cout << "Encrypted message (hex): " << hex_text << '\n';
                std::string decrypted_message = decryptAES(fromHex(hex_text), key, iv);
                std::cout << "Decrypted message: " << decrypted_message << '\n';
                if (message == decrypted_message) {
                    std::cout << "Verification: PASS - messages match\n";
                } else {
                    std::cout << "Verification: FAIL - messages differ\n";
                }
            } else if (choice == "2") {
                std::string hex_text;
                std::cout << "Enter ciphertext (hex): ";
                if (!std::getline(std::cin, hex_text)) break;
                std::cout << "Decrypted message: " << decryptAES(fromHex(hex_text), key, iv) << '\n';
            } else {
                std::cout << "Invalid option\n";
            }
        } catch (const std::exception& error) {
            std::cerr << "Error: " << error.what() << '\n';
        }
    }
    return 0;
}
