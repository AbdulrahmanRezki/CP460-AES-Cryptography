# CP460A Applied Cryptography — AES encryption and decryption

One C++ application combining both students' OpenSSL implementations.
AES-128-CBC, 16-byte key and IV, default PKCS#7-compatible padding.

## Files
- encryption.cpp / encryption.h: encryption and hex encoding (Person 1).
- decryption.cpp / decryption.h: decryption and hex decoding (Person 2).
- main.cpp: shared menu and round-trip verification.
- tests/decrypt_test.cpp: original teammate's integration tests.
- tests/results.txt and tests/demo_output.txt: recorded Linux test output.

## Build and run (Linux)
Install a C++ compiler and OpenSSL development package (libssl-dev on Ubuntu).

```sh
g++ -std=c++11 main.cpp encryption.cpp decryption.cpp -lcrypto -o aes_demo
./aes_demo
```

## macOS (Homebrew)
```sh
brew install openssl@3
g++ -std=c++11 main.cpp encryption.cpp decryption.cpp -I"$(brew --prefix openssl@3)/include" -L"$(brew --prefix openssl@3)/lib" -lcrypto -o aes_demo
./aes_demo
```

## Tests (Linux)
```sh
g++ -std=c++11 -I. tests/decrypt_test.cpp encryption.cpp decryption.cpp -lcrypto -o aes_test
./aes_test
```
On macOS add the same OpenSSL include and library flags shown above.

## Demonstration
Choose option 1, enter a message, show the hexadecimal ciphertext and recovered plaintext, and point out the verification result. Option 2 accepts previously generated hexadecimal ciphertext. Explain the key, IV, CBC mode, padding and EVP functions.

Fixed key and IV are for classroom functionality only. CBC is not authenticated; valid padding does not prove integrity or correct key/IV. Do not use this demo for real secrets.

The course requires a seven-minute presentation (four minutes theory, three minutes demonstration), with slides and recording submitted to MyLearningSpace. The separate syllabus rubric should also be checked.
