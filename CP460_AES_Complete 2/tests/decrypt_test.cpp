// Round-trip tests: Person 1's encryptAES() -> Person 2's decryptAES().
#include "encryption.h"
#include "decryption.h"
#include <iostream>
#include <string>
#include <vector>

static int passed = 0, failed = 0;

static void check(const std::string& name, bool ok) {
    std::cout << (ok ? "[PASS] " : "[FAIL] ") << name << '\n';
    ok ? ++passed : ++failed;
}

// Returns true if decryptAES throws (used for invalid-input tests).
static bool throws(const std::vector<unsigned char>& ct,
                   const std::vector<unsigned char>& key,
                   const std::vector<unsigned char>& iv) {
    try { decryptAES(ct, key, iv); } catch (const std::exception&) { return true; }
    return false;
}

int main() {
    std::vector<unsigned char> key = {0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07,
                                      0x08,0x09,0x0a,0x0b,0x0c,0x0d,0x0e,0x0f};
    std::vector<unsigned char> iv  = {0x10,0x11,0x12,0x13,0x14,0x15,0x16,0x17,
                                      0x18,0x19,0x1a,0x1b,0x1c,0x1d,0x1e,0x1f};

    // 1. Normal round trip
    std::string msg = "Hello CP460A! This is a secret message.";
    std::vector<unsigned char> ct = encryptAES(msg, key, iv);
    std::cout << "Ciphertext: " << toHex(ct) << '\n';
    check("Round trip returns original message", decryptAES(ct, key, iv) == msg);

    // 2. Hex path (what a user pastes from Person 1's program)
    check("Hex string -> bytes -> plaintext", decryptAES(fromHex(toHex(ct)), key, iv) == msg);

    // 3. Exactly one block (padding adds a full extra block)
    std::string block = "0123456789ABCDEF";
    check("16-byte message", decryptAES(encryptAES(block, key, iv), key, iv) == block);

    // 4. Empty message
    check("Empty message", decryptAES(encryptAES("", key, iv), key, iv) == "");

    // 5. Longer message
    std::string longer(1000, 'x');
    check("1000-byte message", decryptAES(encryptAES(longer, key, iv), key, iv) == longer);

    // 6. Wrong key
    std::vector<unsigned char> bad_key = key; bad_key[0] ^= 0xFF;
    bool wrong_key_ok = true;
    try { wrong_key_ok = (decryptAES(ct, bad_key, iv) != msg); } catch (const std::exception&) {}
    check("Wrong key does not recover message", wrong_key_ok);

    // 7. Wrong IV (only garbles first block in CBC, so check it differs)
    std::vector<unsigned char> bad_iv = iv; bad_iv[0] ^= 0x01;
    bool wrong_iv_ok = true;
    try { wrong_iv_ok = (decryptAES(ct, key, bad_iv) != msg); } catch (const std::exception&) {}
    check("Wrong IV does not recover message", wrong_iv_ok);

    // 8. Corrupted ciphertext
    std::vector<unsigned char> damaged = ct; damaged.back() ^= 0x01;
    check("Corrupted ciphertext throws", throws(damaged, key, iv));

    // 9. Invalid inputs
    check("Empty ciphertext throws", throws({}, key, iv));
    check("Bad ciphertext length throws",
          throws(std::vector<unsigned char>(ct.begin(), ct.end() - 1), key, iv));
    check("Short key throws", throws(ct, std::vector<unsigned char>(8, 0), iv));
    check("Short IV throws", throws(ct, key, std::vector<unsigned char>(8, 0)));

    // 10. Bad hex
    bool bad_hex = true;
    try { fromHex("zz11"); bad_hex = false; } catch (const std::exception&) {}
    try { fromHex("abc");  bad_hex = false; } catch (const std::exception&) {}
    try { fromHex("");     bad_hex = false; } catch (const std::exception&) {}
    check("Invalid hex rejected", bad_hex);

    std::cout << "\nResults: " << passed << " passed, " << failed << " failed\n";
    return failed == 0 ? 0 : 1;
}
