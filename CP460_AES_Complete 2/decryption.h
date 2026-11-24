#ifndef DECRYPTION_H
#define DECRYPTION_H

#include <string>
#include <vector>

// Decrypts AES-128-CBC (PKCS#7 padding) ciphertext produced by encryptAES().
// Throws std::runtime_error on invalid input or failed decryption.
std::string decryptAES(const std::vector<unsigned char>& ciphertext,
                       const std::vector<unsigned char>& key,
                       const std::vector<unsigned char>& iv);

// Converts a hex string (as printed by toHex()) back into bytes.
// Whitespace is ignored. Throws std::runtime_error if the text is not valid hex.
std::vector<unsigned char> fromHex(const std::string& hex_text);

#endif
